import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verifyReceipt, agentIdOf } from '@ageprotocol/receipts';
import { createIdentity, publicJwkOf, readIdentity } from '../src/identity.ts';
import { buildCore, commitFacts, parseEmitArgs, parseNumstat, runEmit, timestampOf, type EmitIo } from '../src/emit.ts';

const COMMIT = '8fa72c1e5b9d4a3f2e1c0b9a8d7f6e5c4b3a2918';
const PARENT = '1111111111111111111111111111111111111111';
const OBJECT = `tree aaaa\nparent ${PARENT}\nauthor A <a@example.com> 1757000000 +0000\n\nFix the auth bug\n`;

function home() {
  const dir = mkdtempSync(join(tmpdir(), 'agectl-emit-'));
  createIdentity(dir);
  return dir;
}

// git is stubbed rather than run, so the tests are deterministic and describe
// exactly which commands emission is allowed to depend on.
function harness(overrides: Record<string, string | Error> = {}) {
  const calls: string[][] = [];
  const responses: Record<string, string | Error> = {
    'rev-parse': `${COMMIT}\n`,
    'show -s': '2026-09-09T10:11:12+02:00\nFix the auth bug\n',
    'cat-file': OBJECT,
    'rev-list': `${COMMIT} ${PARENT}\n`,
    'show --numstat': '3\t1\tsrc/auth.ts\n10\t0\tsrc/session.ts\n-\t-\tlogo.png\n',
    'remote': 'https://github.com/ageprotocol/demo.git\n',
    ...overrides,
  };
  const out: string[] = [];
  const err: string[] = [];
  const files: Record<string, string> = {};
  const io: EmitIo = {
    git: async (args) => {
      calls.push(args);
      const key = Object.keys(responses).find((k) => args.join(' ').includes(k));
      const value = key === undefined ? undefined : responses[key];
      if (value === undefined) throw new Error(`unstubbed git: ${args.join(' ')}`);
      if (value instanceof Error) throw value;
      return value;
    },
    stdout: (line) => out.push(line),
    stderr: (line) => err.push(line),
    writeFile: async (path, text) => { files[path] = text; },
    now: () => new Date('2026-09-09T12:00:00.500Z'),
  };
  return { io, out, err, files, calls };
}

test('a timestamp carries no fractional seconds', () => {
  assert.equal(timestampOf(new Date('2026-09-09T12:00:00.500Z')), '2026-09-09T12:00:00Z');
  assert.equal(timestampOf(new Date('2026-01-02T03:04:05Z')), '2026-01-02T03:04:05Z');
});

test('numstat counts files, and a binary file has no lines to count', () => {
  assert.deepEqual(parseNumstat('3\t1\ta.ts\n10\t0\tb.ts\n'), { files_changed: 2, insertions: 13, deletions: 1 });
  // A binary file reports "-" for both. It changed, so it counts as a file,
  // and its lines are not invented.
  assert.deepEqual(parseNumstat('-\t-\tlogo.png\n'), { files_changed: 1, insertions: 0, deletions: 0 });
  assert.deepEqual(parseNumstat(''), { files_changed: 0, insertions: 0, deletions: 0 });
  assert.deepEqual(parseNumstat('not a numstat line\n'), { files_changed: 0, insertions: 0, deletions: 0 });
});

test('every fact in a receipt comes from git, and nothing is estimated', async () => {
  const { io } = harness();
  const facts = await commitFacts(io, '.', 'HEAD');
  assert.equal(facts.commit, COMMIT);
  assert.equal(facts.parent, PARENT);
  assert.equal(facts.subject, 'Fix the auth bug');
  assert.equal(facts.files_changed, 3);
  assert.equal(facts.insertions, 13);
  assert.equal(facts.deletions, 1);
  assert.match(facts.object_digest, /^sha256:[0-9a-f]{64}$/);
  // The authored time is the commit's, converted to UTC, not the clock's.
  assert.equal(facts.authored_at, '2026-09-09T08:11:12Z');
});

test('an emitted receipt verifies, and its commit binding holds', async () => {
  const dir = home();
  try {
    const { io, files } = harness();
    const code = await runEmit(['--task', 'Fix the auth bug', '--out', 'r.json'], dir, io);
    assert.equal(code, 0);
    const receipt = JSON.parse(files['r.json'] as string);

    const result = verifyReceipt(receipt);
    assert.equal(result.ok, true, JSON.stringify(result.checks));
    assert.equal(result.checks.find((c) => c.name === 'registry_signature')?.status, 'skip',
      'an emitted receipt is unregistered, which is valid');

    // The commit binding rule: the action's commit must be listed in outputs.
    const action = receipt.action as { commit: string; files_changed: number };
    assert.equal(action.commit, COMMIT);
    assert.equal(action.files_changed, 3);
    assert.ok(receipt.outputs.some((o: { kind: string; ref: string }) => o.kind === 'commit' && o.ref === COMMIT));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the receipt is signed by the identity on this machine', async () => {
  const dir = home();
  try {
    const { io, files } = harness();
    await runEmit(['--task', 'Fix the auth bug', '--out', 'r.json'], dir, io);
    const receipt = JSON.parse(files['r.json'] as string);
    const entry = receipt.signatures[0] as { signer: string; key: Record<string, string> };
    assert.equal(receipt.agent, entry.signer);
    assert.equal(entry.signer, agentIdOf(entry.key as never));
    // The identity stored on this machine, not a fresh key. If emission
    // generated its own, the receipt would verify and mean nothing.
    const stored = readIdentity(dir);
    assert.equal(receipt.agent, stored.id);
    assert.equal(receipt.agent, agentIdOf(publicJwkOf(stored)));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a prompt is recorded as a digest, never as text', async () => {
  const dir = home();
  try {
    const { io, files } = harness();
    await runEmit(['--task', 'Fix it', '--prompt', 'the secret internal prompt', '--out', 'r.json'], dir, io);
    const text = files['r.json'] as string;
    assert.doesNotMatch(text, /secret internal prompt/, 'prompt text must never reach the receipt');
    const receipt = JSON.parse(text);
    assert.equal(receipt.inputs.length, 1);
    assert.equal(receipt.inputs[0].kind, 'prompt');
    assert.match(receipt.inputs[0].digest, /^sha256:[0-9a-f]{64}$/);
    assert.equal(verifyReceipt(receipt).ok, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a repository with no origin still emits, saying less rather than something untrue', async () => {
  const dir = home();
  try {
    const { io, files } = harness({ remote: new Error('fatal: No such remote') });
    const code = await runEmit(['--task', 'Local only', '--out', 'r.json'], dir, io);
    assert.equal(code, 0);
    const receipt = JSON.parse(files['r.json'] as string);
    assert.equal((receipt.action as Record<string, unknown>).repository, undefined);
    assert.equal((receipt.environment as Record<string, unknown>).workspace, undefined);
    assert.equal(verifyReceipt(receipt).ok, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('emission refuses rather than guessing when git cannot answer', async () => {
  const dir = home();
  try {
    const { io, err } = harness({ 'rev-parse': 'not-a-commit\n' });
    assert.equal(await runEmit(['--task', 'x', '--out', 'r.json'], dir, io), 2);
    assert.match(err.join('\n'), /did not resolve/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('emission without an identity says how to make one', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'agectl-empty-'));
  try {
    const { io, err } = harness();
    assert.equal(await runEmit(['--task', 'x'], dir, io), 2);
    assert.match(err.join('\n'), /identity init/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('argument errors are reported, and --task is required', () => {
  assert.match(parseEmitArgs([]).error ?? '', /--task is required/);
  assert.match(parseEmitArgs(['--task']).error ?? '', /needs a value/);
  assert.match(parseEmitArgs(['--task', '--repo']).error ?? '', /needs a value/);
  assert.match(parseEmitArgs(['--nonsense', 'x']).error ?? '', /unknown argument/);
  const { options, error } = parseEmitArgs(['--task', 'a', '--repo', '/w', '--commit', 'HEAD~1', '--json']);
  assert.equal(error, undefined);
  assert.deepEqual(options, { task: 'a', repo: '/w', commit: 'HEAD~1', json: true });
});

test('two emissions of the same commit differ only where they should', async () => {
  const dir = home();
  try {
    const first = harness();
    await runEmit(['--task', 'Same task', '--out', 'a.json'], dir, first.io);
    const second = harness();
    await runEmit(['--task', 'Same task', '--out', 'b.json'], dir, second.io);
    const a = JSON.parse(first.files['a.json'] as string);
    const b = JSON.parse(second.files['b.json'] as string);
    // Ed25519 is deterministic and the clock is stubbed, so the same facts
    // give the same receipt. Anything that varied would be a fact the
    // receipt invented.
    assert.equal(a.id, b.id);
    assert.deepEqual(a, b);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('without --out the receipt goes to stdout as JSON and nothing else does', async () => {
  const dir = home();
  try {
    const { io, out } = harness();
    assert.equal(await runEmit(['--task', 'Fix it'], dir, io), 0);
    const receipt = JSON.parse(out.join('\n'));
    assert.equal(verifyReceipt(receipt).ok, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('buildCore never invents a value it was not given', () => {
  const identity = { identity_version: '0.1' as const, id: 'age:agent:x', created_at: 'now', private_jwk: {} as never };
  const facts = {
    commit: COMMIT, authored_at: '2026-09-09T08:11:12Z', subject: 's',
    files_changed: 0, insertions: 0, deletions: 0, object_digest: 'sha256:00',
  };
  const core = buildCore(identity, facts, { task: 't', repo: '.', commit: 'HEAD' }, undefined, new Date('2026-09-09T12:00:00Z'));
  assert.equal(core.inputs.length, 0, 'no prompt given, so no input is recorded');
  assert.equal((core.action as Record<string, unknown>).parent, undefined, 'a root commit has no parent');
  assert.equal((core.action as Record<string, unknown>).repository, undefined);
  assert.equal(core.policy, null);
  assert.equal(core.environment.runtime, 'agectl/0.1.1');
});
