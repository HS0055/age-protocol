import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  agentSign, registrySign, buildRoot, proofFor, generateKeyPair, agentIdOf, registryIdOf, bareJwk,
  RECEIPT_VERSION, type Receipt, type ReceiptCore,
  toPublicJwk, signBytes, registrySigningInput,
} from '@ageprotocol/receipts';
import { runVerify } from '../src/verify.ts';

const agent = generateKeyPair();
const registry = generateKeyPair();
const forger = generateKeyPair();
const COMMIT = '8fa72c1e5b9d4a3f2e1c0b9a8d7f6e5c4b3a2918';
const JWKS_URL = 'https://registry.test/.well-known/age-jwks.json';

function core(overrides: Partial<ReceiptCore> = {}): ReceiptCore {
  return {
    receipt_version: RECEIPT_VERSION, agent: agentIdOf(agent.publicJwk), timestamp: '2026-09-05T03:20:00Z',
    task: { id: 'tsk_91', description: 'Fix authentication bug' },
    action: { type: 'git.commit', commit: COMMIT, files_changed: 3, tests: 'passed' },
    inputs: [], outputs: [{ kind: 'commit', digest: `sha256:${'bb'.repeat(32)}`, ref: COMMIT }],
    environment: { runtime: 'claude-code/2.1.0' }, policy: null, ...overrides,
  };
}

const unregistered = agentSign(core(), agent.privateJwk);
const receipt = registrySign(unregistered, { sequence: 184, registered_at: '2026-09-05T03:20:04Z', jwks: JWKS_URL }, registry.privateJwk);
const root = buildRoot([receipt], '2026-09-05', registry.privateJwk);
const proof = proofFor([receipt], receipt, root.registry);
const jwks = { keys: [bareJwk(registry.publicJwk)] };

function harness(extraFiles: Record<string, unknown> = {}, options: { commitExists?: boolean; urls?: Record<string, unknown> } = {}) {
  const files: Record<string, string> = {
    'receipt.json': JSON.stringify(receipt),
    'unregistered.json': JSON.stringify(unregistered),
    'jwks.json': JSON.stringify(jwks),
    'root.json': JSON.stringify(root),
    'proof.json': JSON.stringify(proof),
    ...Object.fromEntries(Object.entries(extraFiles).map(([k, v]) => [k, JSON.stringify(v)])),
  };
  const urls: Record<string, string> = Object.fromEntries(
    Object.entries({ [JWKS_URL]: jwks, ...(options.urls ?? {}) }).map(([k, v]) => [k, JSON.stringify(v)]),
  );
  const out: string[] = [];
  const err: string[] = [];
  const fetched: string[] = [];
  const io = {
    readFile: async (path: string) => {
      const text = files[path];
      if (text === undefined) throw new Error(`ENOENT: ${path}`);
      return text;
    },
    fetchText: async (url: string) => {
      fetched.push(url);
      const text = urls[url];
      if (text === undefined) throw new Error(`HTTP 404 fetching ${url}`);
      return text;
    },
    gitCommitExists: async () => options.commitExists ?? true,
    stdout: (line: string) => out.push(line),
    stderr: (line: string) => err.push(line),
  };
  return { io, out, err, fetched };
}

const REGISTRY_SIGNER = receipt.signatures[1]?.signer;

const VERIFIED_LINES = [
  `✓ Receipt integrity      ${receipt.id}`,
  `✓ Agent signature        ${receipt.agent}`,
  '✓ Agent identity         key thumbprint matches id',
  `✓ Registry signature     ${REGISTRY_SIGNER}  sequence #184`,
  '✓ Commit binding         8fa72c1 (3 files)',
  'VERIFIED',
];

test('a registered receipt with a jwks file prints five checks and VERIFIED', async () => {
  const { io, out } = harness();
  assert.equal(await runVerify(['receipt.json', '--jwks', 'jwks.json'], io), 0);
  assert.deepEqual(out, VERIFIED_LINES);
});

test('one changed byte fails integrity and the agent signature with exit 1', async () => {
  const tampered = { ...receipt, task: { ...receipt.task, description: 'Fix authentication bug!' } };
  const { io, out } = harness({ 'tampered.json': tampered });
  assert.equal(await runVerify(['tampered.json', '--jwks', 'jwks.json'], io), 1);
  assert.equal(out[0], '✗ Receipt integrity      mismatch');
  assert.match(out[1] ?? '', /^✗ Agent signature/);
  assert.equal(out.at(-1), 'FAILED');
});

test('the registry key is fetched from a jwks URL, or from the hint in the receipt', async () => {
  const viaFlag = harness();
  assert.equal(await runVerify(['receipt.json', '--jwks', JWKS_URL], viaFlag.io), 0);
  assert.deepEqual(viaFlag.fetched, [JWKS_URL]);
  const viaHint = harness();
  assert.equal(await runVerify(['receipt.json'], viaHint.io), 0);
  assert.deepEqual(viaHint.fetched, [JWKS_URL]);
  assert.deepEqual(viaHint.out, VERIFIED_LINES);
});

test('--offline without --jwks cannot check the registry signature and fails', async () => {
  const { io, out, fetched } = harness();
  assert.equal(await runVerify(['receipt.json', '--offline'], io), 1);
  assert.deepEqual(fetched, []);
  assert.match(out[3] ?? '', /^✗ Registry signature     registry key .* not available/);
  assert.equal(out.at(-1), 'FAILED');
});

test('an unregistered receipt skips the registry check and is still VERIFIED', async () => {
  const { io, out } = harness();
  assert.equal(await runVerify(['unregistered.json', '--offline'], io), 0);
  assert.equal(out[3], '- Registry signature     absent, unregistered receipt');
  assert.equal(out.at(-1), 'VERIFIED');
});

test('--repo checks that the commit exists', async () => {
  const present = harness({}, { commitExists: true });
  assert.equal(await runVerify(['receipt.json', '--jwks', 'jwks.json', '--repo', '/tmp/demo'], present.io), 0);
  assert.equal(present.out[4], '✓ Commit binding         8fa72c1 exists in /tmp/demo (3 files)');
  const missing = harness({}, { commitExists: false });
  assert.equal(await runVerify(['receipt.json', '--jwks', 'jwks.json', '--repo', '/tmp/demo'], missing.io), 1);
  assert.match(missing.out[4] ?? '', /^✗ Commit binding         commit .* not found in \/tmp\/demo/);
});

test('commit binding is skipped for a non-commit action and fails for a malformed or unlisted commit', async () => {
  const research = registrySign(agentSign(core({ action: { type: 'research.report' }, outputs: [] }), agent.privateJwk), { sequence: 1, registered_at: '2026-09-05T00:00:00Z' }, registry.privateJwk);
  const bad = registrySign(agentSign(core({ action: { type: 'git.commit', commit: 'nope' } }), agent.privateJwk), { sequence: 2, registered_at: '2026-09-05T00:00:00Z' }, registry.privateJwk);
  const unlisted = registrySign(agentSign(core({ outputs: [] }), agent.privateJwk), { sequence: 3, registered_at: '2026-09-05T00:00:00Z' }, registry.privateJwk);
  const a = harness({ 'r.json': research });
  assert.equal(await runVerify(['r.json', '--jwks', 'jwks.json'], a.io), 0);
  assert.equal(a.out[4], '- Commit binding         action research.report is not a commit');
  const b = harness({ 'b.json': bad });
  assert.equal(await runVerify(['b.json', '--jwks', 'jwks.json'], b.io), 1);
  assert.equal(b.out[4], '✗ Commit binding         commit hash missing or malformed');
  const c = harness({ 'u.json': unlisted });
  assert.equal(await runVerify(['u.json', '--jwks', 'jwks.json'], c.io), 1);
  assert.equal(c.out[4], '✗ Commit binding         commit is not among the outputs');
});

test('--root and --proof add a root inclusion check', async () => {
  const good = harness();
  assert.equal(await runVerify(['receipt.json', '--jwks', 'jwks.json', '--root', 'root.json', '--proof', 'proof.json'], good.io), 0);
  assert.equal(good.out[5], '✓ Root inclusion         2026-09-05 sequence 184 to 184');
  assert.equal(good.out[6], 'VERIFIED');
  const forged = harness({ 'root.json': { ...root, date: '2026-09-06' } });
  assert.equal(await runVerify(['receipt.json', '--jwks', 'jwks.json', '--root', 'root.json', '--proof', 'proof.json'], forged.io), 1);
  assert.equal(forged.out[5], '✗ Root inclusion         root signature does not verify');
});

test('--json prints the checks as data', async () => {
  const { io, out } = harness();
  assert.equal(await runVerify(['receipt.json', '--jwks', 'jwks.json', '--json'], io), 0);
  const parsed = JSON.parse(out.join('\n')) as { ok: boolean; receipt: string; agent: string; checks: Array<{ name: string; status: string }> };
  assert.equal(parsed.ok, true);
  assert.equal(parsed.receipt, receipt.id);
  assert.equal(parsed.agent, receipt.agent);
  assert.deepEqual(parsed.checks.map((c) => c.name), ['integrity', 'agent_signature', 'agent_identity', 'registry_signature', 'commit_binding']);
});

test('usage and input errors exit 2', async () => {
  const { io, err } = harness({ 'array.json': [], 'badjwks.json': { keys: 'nope' } });
  assert.equal(await runVerify([], io), 2);
  assert.equal(await runVerify(['receipt.json', '--jwks'], io), 2);
  assert.equal(await runVerify(['receipt.json', '--chian', 'x.json'], io), 2);
  assert.equal(await runVerify(['receipt.json', '--root', 'root.json'], io), 2);
  assert.equal(await runVerify(['missing.json', '--offline'], io), 2);
  assert.equal(await runVerify(['array.json', '--offline'], io), 2);
  assert.equal(await runVerify(['receipt.json', '--jwks', 'badjwks.json'], io), 2);
  assert.ok(err.some((line) => line.startsWith('unknown flag: --chian')));
  assert.ok(err.some((line) => line.startsWith('cannot read input:')));
});

test('control characters from the input never reach the terminal', async () => {
  const noisy = { ...unregistered, id: `${unregistered.id}\u001b[2K` };
  const { io, out } = harness({ 'noisy.json': noisy });
  await runVerify(['noisy.json', '--offline'], io);
  assert.equal(out.some((line) => line.includes('\u001b')), false);
});

test('a forged second registry entry is labelled by position and fails with exit 1', async () => {
  const forged = {
    ...receipt,
    signatures: [...receipt.signatures, {
      role: 'registry', signer: registryIdOf(forger.publicJwk), alg: 'Ed25519', sequence: 9999,
      registered_at: '2026-09-05T03:20:04Z', signature: 'A'.repeat(86),
    }],
  };
  const { io, out } = harness({ 'forged.json': forged });
  assert.equal(await runVerify(['forged.json', '--jwks', 'jwks.json'], io), 1);
  assert.equal(out[3], `\u2713 Registry signature 1   ${REGISTRY_SIGNER}  sequence #184`);
  assert.match(out[4] ?? '', /^\u2717 Registry signature 2   registry key age:registry:/);
  assert.equal(out.at(-1), 'FAILED');
});

test('a receipt countersigned by two registries loads both keys and passes both checks', async () => {
  // Every registry entry is now checked and an unobtainable key is a
  // failure, so loading only the first entry's hint made a two-registry
  // receipt fail no matter what the caller did short of hand-building a
  // combined jwks file.
  const second = generateKeyPair();
  const SECOND_URL = 'https://second.test/.well-known/age-jwks.json';
  const signer = registryIdOf(bareJwk(toPublicJwk(second.privateJwk)));
  const fields = { sequence: 7, registered_at: '2026-09-05T05:00:00Z', signer };
  const both: Receipt = {
    ...receipt,
    signatures: [...receipt.signatures, {
      role: 'registry', signer, alg: 'Ed25519', sequence: fields.sequence,
      registered_at: fields.registered_at, jwks: SECOND_URL,
      signature: signBytes(registrySigningInput(receipt, fields), second.privateJwk),
    }],
  };

  const { io, out, fetched } = harness({ 'both.json': both }, {
    urls: { [SECOND_URL]: { keys: [bareJwk(second.publicJwk)] } },
  });
  const code = await runVerify(['both.json'], io);
  assert.equal(code, 0, out.join('\n'));
  assert.deepEqual(fetched.sort(), [JWKS_URL, SECOND_URL].sort());
  assert.match(out.join('\n'), /✓ Registry signature 1/);
  assert.match(out.join('\n'), /✓ Registry signature 2/);
});

test('an unknown signature role does not make the CLI reject the file', async () => {
  // The extensibility promise: a runtime or hardware entry shaped differently
  // is reported, not treated as a malformed receipt.
  const withRuntime: Receipt = {
    ...receipt,
    signatures: [...receipt.signatures, { role: 'runtime', attestation: { tee: 'sev-snp' } } as never],
  };
  const { io, out } = harness({ 'future.json': withRuntime });
  const code = await runVerify(['future.json', '--jwks', 'jwks.json'], io);
  assert.equal(code, 0, out.join('\n'));
  assert.match(out.join('\n'), /- Runtime signature\s+unknown role, not checked/);
});

test('a malformed receipt reaches the commit check without raising', async () => {
  // commit_binding runs alongside verifyReceipt rather than after it, so it
  // sees receipts whose shape has already failed. A null inside outputs used
  // to throw here, and the CLI printed "internal error" instead of a verdict.
  // The specification requires an answer for any input.
  const shapes: [string, (r: Record<string, unknown>) => void][] = [
    ['outputs holds null', (r) => { r.outputs = [null]; }],
    ['outputs holds a number', (r) => { r.outputs = [42]; }],
    ['outputs is an object', (r) => { r.outputs = { kind: 'commit' }; }],
    ['outputs is absent', (r) => { delete r.outputs; }],
    ['action is null', (r) => { r.action = null; }],
    ['action is a number', (r) => { r.action = 42; }],
    ['action is absent', (r) => { delete r.action; }],
    ['action.type is not a string', (r) => { (r.action as Record<string, unknown>).type = 7; }],
    ['commit is null', (r) => { (r.action as Record<string, unknown>).commit = null; }],
  ];

  for (const [label, mutate] of shapes) {
    const broken = JSON.parse(JSON.stringify(receipt)) as Record<string, unknown>;
    mutate(broken);
    const { io, out, err } = harness({ 'broken.json': broken });
    const code = await runVerify(['broken.json', '--jwks', 'jwks.json'], io);
    const printed = [...out, ...err].join('\n');
    assert.doesNotMatch(printed, /internal error/, `${label} produced an internal error`);
    assert.notEqual(code, 0, `${label} must not verify`);
  }
});
