import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verifyReceipt, agentIdOf } from '@ageprotocol/receipts';
import { createIdentity, publicJwkOf, readIdentity } from '../src/identity.ts';
import { buildCore, commitFacts, parseEmitArgs, parseNumstat, runEmit, timestampOf, withoutCredentials, type EmitIo } from '../src/emit.ts';

const COMMIT = '8fa72c1e5b9d4a3f2e1c0b9a8d7f6e5c4b3a2918';
const PARENT = '1111111111111111111111111111111111111111';
const OTHER = '2222222222222222222222222222222222222222';
const BAD_DATE_COMMIT = '3333333333333333333333333333333333333333';
const OBJECT = `tree aaaa\nparent ${PARENT}\nauthor A <a@example.com> 1757000000 +0000\n\nFix the auth bug\n`;

function home() {
  const dir = mkdtempSync(join(tmpdir(), 'agectl-emit-'));
  createIdentity(dir);
  return dir;
}

// A fake git rather than a stub. The difference matters: the old version
// matched a substring of the joined arguments and returned a fixed answer, so
// no test could see which commit or which format git was asked for. A review
// reintroduced ten defects and this suite caught four. Among the six it
// missed was reading the committer date under the author's name, which is the
// bug that shipped. This fake expands the format string it is given and
// resolves the ref it is given, so asking the wrong question gets the wrong
// answer and a test notices.
const COMMITS: Record<string, Record<string, string>> = {
  [COMMIT]: {
    '%aI': '2020-03-01T09:00:00+05:30',
    '%cI': '2026-09-09T10:11:12+02:00',
    '%s': 'Fix the auth bug',
    '%H': COMMIT,
  },
  [OTHER]: {
    '%aI': '2019-01-01T00:00:00Z',
    '%cI': '2019-01-02T00:00:00Z',
    '%s': 'A different commit entirely',
    '%H': OTHER,
  },
};

const NUMSTAT: Record<string, string> = {
  [COMMIT]: '3\t1\tsrc/auth.ts\n10\t0\tsrc/session.ts\n-\t-\tlogo.png\n',
  [OTHER]: '1\t1\tother.ts\n',
};

const PARENTS: Record<string, string[]> = { [COMMIT]: [PARENT], [OTHER]: [], [BAD_DATE_COMMIT]: [] };

// A commit object can carry a date git cannot parse back. Signing it as an
// invalid date would state something that is not a time.
COMMITS[BAD_DATE_COMMIT] = { '%aI': 'not-a-date', '%cI': '2026-09-09T10:11:12+02:00', '%s': 'bad date', '%H': BAD_DATE_COMMIT };
NUMSTAT[BAD_DATE_COMMIT] = '1\t0\tf.txt\n';

function harness(overrides: { remote?: string | Error; resolve?: Record<string, string> } = {}) {
  const calls: string[][] = [];
  const resolve: Record<string, string> = { HEAD: COMMIT, 'HEAD~1': OTHER, ...overrides.resolve };
  const out: string[] = [];
  const err: string[] = [];
  const files: Record<string, string> = {};

  const io: EmitIo = {
    git: async (args) => {
      calls.push(args);
      const rest = args.slice(2); // past -C <repo>
      const [command] = rest;

      if (command === 'rev-parse') {
        const ref = (rest[1] ?? '').replace(/\^\{commit\}$/, '');
        const hash = resolve[ref];
        if (hash === undefined) throw new Error(`fatal: bad revision '${ref}'`);
        return `${hash}\n`;
      }
      if (command === 'show' && rest.includes('-s')) {
        const format = (rest.find((a) => a.startsWith('--format=')) ?? '').slice('--format='.length);
        const commit = rest[rest.length - 1] as string;
        const fields = COMMITS[commit];
        if (!fields) throw new Error(`fatal: unknown commit ${commit}`);
        // Expand exactly what was asked for. Asking for %cI gets the
        // committer date, which is the point.
        // %n is a separator, expanded before the field tokens so the field
        // pattern cannot swallow it.
        const expanded = format.replace(/%n/g, '\u0000')
          .replace(/%[a-zA-Z]+/g, (token) => fields[token] ?? `<unsupported ${token}>`)
          .split('\u0000').join('\n');
        return `${expanded}\n`;
      }
      if (command === 'cat-file') return OBJECT;
      if (command === 'rev-list') {
        const commit = rest[rest.length - 1] as string;
        return `${[commit, ...(PARENTS[commit] ?? [])].join(' ')}\n`;
      }
      if (command === 'show') {
        const commit = rest[rest.length - 1] as string;
        const stat = NUMSTAT[commit];
        if (stat === undefined) throw new Error(`fatal: unknown commit ${commit}`);
        return stat;
      }
      if (command === 'remote') {
        const remote = overrides.remote ?? 'https://github.com/ageprotocol/demo.git\n';
        if (remote instanceof Error) throw remote;
        return remote;
      }
      throw new Error(`unstubbed git: ${args.join(' ')}`);
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
  assert.deepEqual(facts.parents, [PARENT]);
  assert.equal(facts.subject, 'Fix the auth bug');
  assert.equal(facts.files_changed, 3);
  assert.equal(facts.insertions, 13);
  assert.equal(facts.deletions, 1);
  assert.match(facts.object_digest, /^sha256:[0-9a-f]{64}$/);
  // The author date is when the work was written; the committer date is when
  // it landed. A rebase keeps the first and rewrites the second, so recording
  // one under the other's name misstates the date on most branches.
  assert.equal(facts.authored_at, '2020-03-01T03:30:00Z');
  assert.equal(facts.committed_at, '2026-09-09T08:11:12Z');
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
    assert.equal(verifyReceipt(receipt).ok, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('emission refuses rather than guessing when git cannot answer', async () => {
  const dir = home();
  try {
    const { io, err } = harness({ resolve: { HEAD: 'not-a-commit' } });
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
    committed_at: '2026-09-09T08:11:12Z',
    parents: [], files_changed: 0, insertions: 0, deletions: 0, object_digest: 'sha256:00',
  };
  const core = buildCore(identity, facts, { task: 't', repo: '.', commit: 'HEAD' }, undefined, new Date('2026-09-09T12:00:00Z'));
  assert.equal(core.inputs.length, 0, 'no prompt given, so no input is recorded');
  assert.equal((core.action as Record<string, unknown>).parents, undefined, 'a root commit has no parents');
  assert.equal((core.action as Record<string, unknown>).repository, undefined);
  assert.equal(core.policy, null);
  assert.match(String(core.environment.runtime), /^agectl/);
});

test('a credential in the origin remote never reaches the signed receipt', () => {
  // git clone https://user:token@host/repo writes the credential into origin
  // verbatim, and CI systems do the same. A receipt is signed and its id
  // covers those bytes, so a leak here cannot be redacted afterwards without
  // destroying the signature and any Merkle leaf built over it.
  const cases: [string, string][] = [
    ['https://ghp_EXAMPLETOKEN0123456789abcdef@github.com/org/repo.git', 'https://github.com/org/repo.git'],
    ['https://user:password@gitlab.com/org/repo.git', 'https://gitlab.com/org/repo.git'],
    ['https://gitlab-ci-token:glcbt-XYZ@gitlab.com/o/r.git', 'https://gitlab.com/o/r.git'],
    ['ssh://git@github.com/org/repo.git', 'ssh://github.com/org/repo.git'],
    ['https://github.com/org/repo.git', 'https://github.com/org/repo.git'],
    // scp-style carries a username, not a secret, and is conventional.
    ['git@github.com:org/repo.git', 'git@github.com:org/repo.git'],
    ['/srv/git/repo.git', '/srv/git/repo.git'],
  ];
  for (const [url, expected] of cases) {
    assert.equal(withoutCredentials(url), expected, url);
  }
});

test('a token in origin does not appear anywhere in the emitted receipt', async () => {
  const dir = home();
  try {
    const { io, files } = harness({ remote: 'https://ghp_SECRETTOKEN0123456789abcdef@github.com/org/repo.git\n' });
    await runEmit(['--task', 'Fix it', '--out', 'r.json'], dir, io);
    const text = files['r.json'] as string;
    assert.doesNotMatch(text, /ghp_SECRETTOKEN/, 'the credential must not be in the signed bytes');
    const receipt = JSON.parse(text);
    assert.equal((receipt.action as Record<string, unknown>).repository, 'https://github.com/org/repo.git');
    assert.equal(verifyReceipt(receipt).ok, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('an unwritable output path is an exit code, not a stack trace', async () => {
  const dir = home();
  try {
    const { io, err } = harness();
    io.writeFile = async () => { throw new Error('EACCES: permission denied'); };
    const code = await runEmit(['--task', 'Fix it', '--out', '/nope/r.json'], dir, io);
    assert.equal(code, 2);
    assert.match(err.join('\n'), /cannot write \/nope\/r\.json/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a date git cannot express is refused rather than signed as Invalid Date', async () => {
  const dir = home();
  try {
    const { io, err } = harness({ resolve: { HEAD: BAD_DATE_COMMIT } });
    assert.equal(await runEmit(['--task', 'x', '--out', 'r.json'], dir, io), 2);
    assert.match(err.join('\n'), /unreadable author date/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// A review reintroduced ten defects into emit and this suite caught four.
// These cover the six it missed. Each names a way the receipt could describe
// the wrong thing while every value in it still looks plausible.
test('the facts describe the commit that was asked for, and nothing else', async () => {
  const dir = home();
  try {
    // HEAD and HEAD~1 are different commits with different everything. A
    // gather that used a hardcoded ref, or read metadata from the raw ref
    // rather than the resolved hash, would mix them.
    const { io, files, calls } = harness();
    await runEmit(['--task', 't', '--commit', 'HEAD~1', '--out', 'r.json'], dir, io);
    const receipt = JSON.parse(files['r.json'] as string);
    const action = receipt.action as Record<string, unknown>;
    assert.equal(action.commit, OTHER);
    assert.equal(action.subject, 'A different commit entirely');
    assert.equal(action.files_changed, 1, 'the numstat is HEAD~1 own, not HEAD s');
    assert.equal(action.insertions, 1);
    assert.equal(action.authored_at, '2019-01-01T00:00:00Z');

    // Every git call after the first resolves against the full hash, never
    // the ref, so nothing can shift between calls.
    const afterResolve = calls.filter((c) => !c.includes('rev-parse') && !c.includes('remote'));
    assert.ok(afterResolve.length >= 3, 'metadata, object and numstat are all gathered');
    for (const call of afterResolve) {
      assert.ok(call.includes(OTHER), `every gather names the resolved hash: ${call.join(' ')}`);
      assert.ok(!call.includes('HEAD~1'), `no gather uses the raw ref: ${call.join(' ')}`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the dates come from the fields they are named after', async () => {
  const dir = home();
  try {
    const { io, files, calls } = harness();
    await runEmit(['--task', 't', '--out', 'r.json'], dir, io);
    const action = (JSON.parse(files['r.json'] as string) as { action: Record<string, unknown> }).action;
    // The fake expands whatever format it is given, so swapping %aI for %cI
    // in the source changes these values and this test fails.
    assert.equal(action.authored_at, '2020-03-01T03:30:00Z');
    assert.equal(action.committed_at, '2026-09-09T08:11:12Z');
    const format = calls.flat().find((a) => a.startsWith('--format='));
    assert.ok(format?.includes('%aI'), 'the author date is actually requested');
    assert.ok(format?.includes('%cI'), 'the committer date is actually requested');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the line counts in the receipt are the counts git reported, unrounded', async () => {
  const dir = home();
  try {
    const { io, files } = harness();
    await runEmit(['--task', 't', '--out', 'r.json'], dir, io);
    const action = (JSON.parse(files['r.json'] as string) as { action: Record<string, unknown> }).action;
    // Asserted on the receipt, not on commitFacts. The earlier test checked
    // the gather and would not have noticed a value rounded on its way in.
    assert.equal(action.files_changed, 3);
    assert.equal(action.insertions, 13);
    assert.equal(action.deletions, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the parent is the commit parent, not the commit itself', async () => {
  const dir = home();
  try {
    const { io, files } = harness();
    await runEmit(['--task', 't', '--out', 'r.json'], dir, io);
    const action = (JSON.parse(files['r.json'] as string) as { action: Record<string, unknown> }).action;
    // rev-list --parents prints the commit first and its parents after, so
    // an off-by-one here records the commit as its own parent.
    assert.deepEqual(action.parents, [PARENT]);
    assert.ok(!(action.parents as string[]).includes(COMMIT));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the remote is recorded when there is one', async () => {
  const dir = home();
  try {
    const { io, files } = harness();
    await runEmit(['--task', 't', '--out', 'r.json'], dir, io);
    const receipt = JSON.parse(files['r.json'] as string) as Record<string, Record<string, unknown>>;
    assert.equal(receipt.action?.repository, 'https://github.com/ageprotocol/demo.git');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
