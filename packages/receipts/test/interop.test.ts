import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  verifyReceipt, canonicalBytes, sha256Digest, signBytes, bareJwk, agentIdOf,
  verifyRoot, verifyRootInclusion, keyMapFromJwks,
  type PrivateJwk, type PublicJwk, type Receipt, type ReceiptCore,
} from '../src/index.ts';

interface GoldenVector {
  keys: { agent_private: PrivateJwk; agent_public: PublicJwk; registry_public: PublicJwk };
  receipts: { core: ReceiptCore; receipt: Receipt; proof: Record<string, unknown> }[];
  root: { document: Record<string, unknown> };
}

// docs/protocol/verify.py is a second implementation of verification: another
// language, another crypto library, its own canonicalizer, written from the
// specification rather than from this code. A format is interoperable when a
// stranger's implementation agrees, not when its author says so, and these
// tests are where that claim is actually checked.

const ROOT = join(import.meta.dirname, '..', '..', '..');
const VERIFIER = join(ROOT, 'docs', 'protocol', 'verify.py');
const VECTOR = join(ROOT, 'docs', 'protocol', 'golden-v0.1.json');

function python(): string | undefined {
  for (const candidate of ['python3', 'python']) {
    const probe = spawnSync(candidate, ['-c', 'import cryptography'], { encoding: 'utf8' });
    if (probe.status === 0) return candidate;
  }
  return undefined;
}

const PYTHON = python();
const missing = { skip: 'python3 with the cryptography package is not available' };
const when = PYTHON === undefined ? missing : {};

function run(...args: string[]) {
  return spawnSync(PYTHON as string, [VERIFIER, VECTOR, ...args], { encoding: 'utf8' });
}

// verifyReceipt does not check root inclusion, so comparing it with a run that
// does compares different questions. A Merkle leaf is the whole receipt, so
// any signature-array change legitimately puts a receipt outside the root.
function runReceipt(receipt: unknown) {
  return runReceiptText(JSON.stringify(receipt));
}

// Takes the receipt as raw JSON text. Round-tripping through JSON.stringify
// erases the difference between 3 and 3.0 before Python ever sees it, which
// is precisely the case being compared.
function runReceiptText(text: string) {
  return spawnSync(PYTHON as string, [VERIFIER, VECTOR, text, '--no-root'], { encoding: 'utf8' });
}

// Asks verify.py for the root verdict alone, so it can be compared against
// verifyRoot and verifyRootInclusion rather than against a whole run.
function runRoot(receipt: unknown, doc: unknown, proof: unknown) {
  const script = [
    'import json, sys, importlib.util',
    `spec = importlib.util.spec_from_file_location("v", ${JSON.stringify(VERIFIER)})`,
    'm = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)',
    `g = json.load(open(${JSON.stringify(VECTOR)}))`,
    'receipt, doc, proof = json.loads(sys.argv[1]), json.loads(sys.argv[2]), json.loads(sys.argv[3])',
    'ok, _ = m.root_verdict(receipt, doc, proof, [g["keys"]["registry_public"]])',
    'print("INCLUDED" if ok else "NOT")',
  ].join('\n');
  return spawnSync(PYTHON as string,
    ['-c', script, JSON.stringify(receipt), JSON.stringify(doc), JSON.stringify(proof)],
    { encoding: 'utf8' });
}

test('a second implementation verifies every receipt in the golden vector', when, () => {
  const result = run();
  assert.equal(result.status, 0, result.stdout + result.stderr);
  // One verdict for the run, and every one of the three receipts reported.
  assert.match(result.stdout, /VERIFIED/);
  assert.doesNotMatch(result.stdout, /FAIL/);
  assert.equal((result.stdout.match(/\[PASS\] Receipt integrity/g) ?? []).length, 3);
  assert.equal((result.stdout.match(/\[PASS\] Agent signature/g) ?? []).length, 3);
  assert.equal((result.stdout.match(/\[PASS\] Root inclusion/g) ?? []).length, 3);
});

test('a second implementation rejects the same tampering this one does', when, () => {
  const vector = JSON.parse(readFileSync(VECTOR, 'utf8')) as {
    receipts: { receipt: Record<string, unknown> }[];
  };
  const genuine = vector.receipts[0]?.receipt as Record<string, unknown>;

  const tampered = JSON.parse(JSON.stringify(genuine)) as Record<string, unknown>;
  (tampered.action as Record<string, unknown>).files_changed = 300;
  assert.equal(run(JSON.stringify(tampered)).status, 1);

  // Content edited and the id recomputed to match: only the agent signature
  // catches this, which is the difference between a receipt and a log.
  const resealed = JSON.parse(JSON.stringify(genuine)) as Record<string, unknown>;
  (resealed.task as Record<string, unknown>).description = 'Something else entirely';
  const recomputed = run(JSON.stringify(resealed));
  assert.equal(recomputed.status, 1);
  assert.match(recomputed.stdout, /Agent signature/);
});

// The test that matters most. Agreeing on a valid receipt is easy; the whole
// point of a second implementation is that it agrees on the INVALID ones too.
// A verifier that accepts a receipt the reference rejects is worse than no
// second implementation at all, because it turns a claim of interoperability
// into a false one. This caught exactly that: verify.py had no shape
// validation and passed a receipt with no timestamp.
test('the two implementations agree on malformed receipts, not just good ones', when, () => {
  const vector = JSON.parse(readFileSync(VECTOR, 'utf8')) as GoldenVector;
  const keys = { registryKeys: [vector.keys.registry_public] };
  const item = vector.receipts[0] as GoldenVector['receipts'][number];

  // Each mutation produces a receipt that is signed consistently but wrong in
  // one specific way, so a verifier without that rule reports it verified.
  const mutations: [string, (core: Record<string, unknown>) => void][] = [
    ['no timestamp', (c) => { delete c.timestamp; }],
    ['timestamp is a number', (c) => { c.timestamp = 1757000000; }],
    ['no action', (c) => { delete c.action; }],
    ['action.type is not a string', (c) => { (c.action as Record<string, unknown>).type = 7; }],
    ['no task', (c) => { delete c.task; }],
    ['task is a string', (c) => { c.task = 'fix the bug'; }],
    ['inputs is an object', (c) => { c.inputs = { kind: 'prompt' }; }],
    ['an input has no digest', (c) => { c.inputs = [{ kind: 'prompt' }]; }],
    ['outputs is missing', (c) => { delete c.outputs; }],
    ['environment is null', (c) => { c.environment = null; }],
    ['policy is a string', (c) => { c.policy = 'default'; }],
    ['agent is not an age:agent: id', (c) => { c.agent = 'someone'; }],
    ['agent id has an empty thumbprint', (c) => { c.agent = 'age:agent:'; }],
    ['receipt_version is 0.2', (c) => { c.receipt_version = '0.2'; }],
    ['a fractional number', (c) => { (c.action as Record<string, unknown>).ratio = 1.5; }],
    ['a number past the safe range', (c) => { (c.action as Record<string, unknown>).n = 1e21; }],
    ['a fraction inside an input', (c) => { c.inputs = [{ kind: 'prompt', digest: `sha256:${'aa'.repeat(32)}`, size: 0.5 }]; }],
  ];

  for (const [label, mutate] of mutations) {
    const core = JSON.parse(JSON.stringify(item.core)) as Record<string, unknown>;
    mutate(core);
    // Sign it properly, so only the rule under test can reject it.
    const bytes = canonicalBytes(core);
    const receipt = {
      ...core,
      id: sha256Digest(bytes),
      signatures: [{
        role: 'agent',
        signer: agentIdOf(bareJwk(vector.keys.agent_public)),
        alg: 'Ed25519',
        key: bareJwk(vector.keys.agent_public),
        signature: signBytes(bytes, vector.keys.agent_private),
      }],
    } as unknown as Receipt;

    const reference = verifyReceipt(receipt, keys).ok;
    const second = runReceipt(receipt).status === 0;
    assert.equal(reference, false, `the reference should reject: ${label}`);
    assert.equal(second, reference, `the two implementations disagree on: ${label}`);
  }
});

test('the two implementations agree that a padded signature is not a signature', when, () => {
  const vector = JSON.parse(readFileSync(VECTOR, 'utf8')) as GoldenVector;
  const receipt = JSON.parse(JSON.stringify(vector.receipts[0]?.receipt)) as Receipt;
  const entry = receipt.signatures[0] as { signature: string };
  entry.signature = `${entry.signature}=`;
  assert.equal(verifyReceipt(receipt, { registryKeys: [vector.keys.registry_public] }).ok, false);
  assert.equal(run(JSON.stringify(receipt)).status, 1);
});

// The forged-signature classes, run against both implementations. The first
// version of verify.py took the first entry of each role, exactly the defect
// the reference had removed, so a forged second registry entry, a bogus alg,
// and a decorated embedded key all read as verified there while the reference
// rejected them.
test('the two implementations agree on forged and malformed signature entries', when, () => {
  const vector = JSON.parse(readFileSync(VECTOR, 'utf8')) as GoldenVector;
  const keys = { registryKeys: [vector.keys.registry_public] };
  const genuine = vector.receipts[0]?.receipt as Receipt;

  const attacks: [string, (r: Receipt) => void][] = [
    ['a forged second registry entry', (r) => {
      r.signatures.push({
        role: 'registry', signer: `age:registry:${'A'.repeat(43)}`, alg: 'Ed25519',
        sequence: 9999, registered_at: '2099-01-01T00:00:00Z', signature: 'A'.repeat(86),
      } as never);
    }],
    ['a second agent entry', (r) => { r.signatures.push({ ...r.signatures[0] } as never); }],
    ['the agent claims HS256', (r) => { (r.signatures[0] as { alg: string }).alg = 'HS256'; }],
    ['the registry claims HS256', (r) => { (r.signatures[1] as { alg: string }).alg = 'HS256'; }],
    ['an extra kid on the embedded key', (r) => {
      (r.signatures[0] as unknown as { key: Record<string, unknown> }).key.kid = 'label';
    }],
    ['the embedded key claims another curve', (r) => {
      (r.signatures[0] as unknown as { key: Record<string, unknown> }).key.crv = 'P-256';
    }],
    ['a signature entry that is null', (r) => { r.signatures.push(null as never); }],
    ['the registry sequence is rewritten', (r) => {
      (r.signatures[1] as { sequence: number }).sequence = 1;
    }],
  ];

  for (const [label, attack] of attacks) {
    const receipt = JSON.parse(JSON.stringify(genuine)) as Receipt;
    attack(receipt);
    const reference = verifyReceipt(receipt, keys).ok;
    const second = runReceipt(receipt).status === 0;
    assert.equal(reference, false, `the reference should reject: ${label}`);
    assert.equal(second, reference, `the two implementations disagree on: ${label}`);
  }
});

test('neither implementation raises on input that is not a receipt', when, () => {
  const hostile = ['null', '42', '"receipt"', '[]', '{}',
    JSON.stringify({ receipt_version: '0.1', signatures: [null] }),
    JSON.stringify({ receipt_version: '0.1', signatures: {} })];
  for (const input of hostile) {
    const result = run(input);
    assert.equal(result.status, 1, `expected a verdict, not a crash, for ${input}`);
    assert.doesNotMatch(result.stdout + result.stderr, /Traceback|AttributeError|TypeError/,
      `${input} raised instead of reporting`);
  }
});

// Three cases where a fix on one side alone silently changed the rules. Each
// was caught by comparing verdicts rather than by either suite on its own.
test('the two implementations agree on surrogates, nesting depth, and non-string roles', when, () => {
  const vector = JSON.parse(readFileSync(VECTOR, 'utf8')) as GoldenVector;
  const keys = { registryKeys: [vector.keys.registry_public] };
  const item = vector.receipts[0] as GoldenVector['receipts'][number];

  const sign = (core: Record<string, unknown>): Receipt => {
    const bytes = canonicalBytes(core);
    return {
      ...core,
      id: sha256Digest(bytes),
      signatures: [{
        role: 'agent', signer: agentIdOf(bareJwk(vector.keys.agent_public)), alg: 'Ed25519',
        key: bareJwk(vector.keys.agent_public), signature: signBytes(bytes, vector.keys.agent_private),
      }],
    } as unknown as Receipt;
  };

  // An unpaired surrogate is escaped as \udXXX by a well-formed
  // JSON.stringify. A canonicalizer that emits it raw produces different
  // bytes, so this receipt verifies in one implementation and not the other
  // with nothing visibly wrong.
  const surrogate = JSON.parse(JSON.stringify(item.core)) as Record<string, unknown>;
  (surrogate.task as Record<string, unknown>).description = 'lone \ud800 surrogate';
  const signedSurrogate = sign(surrogate);
  assert.equal(verifyReceipt(signedSurrogate, keys).ok, true, 'a surrogate is legal content');
  assert.equal(run(JSON.stringify(signedSurrogate)).status, 0, 'the two canonicalizers disagree on a surrogate');

  // Just inside and just outside the depth limit.
  const nested = (levels: number) => {
    const core = JSON.parse(JSON.stringify(item.core)) as Record<string, unknown>;
    let leaf: Record<string, unknown> = { deepest: 1 };
    for (let i = 0; i < levels; i += 1) leaf = { n: leaf };
    core.environment = leaf;
    return core;
  };
  const shallow = sign(nested(50));
  assert.equal(verifyReceipt(shallow, keys).ok, true, '50 levels is well inside the limit');
  assert.equal(run(JSON.stringify(shallow)).status, 0, 'disagreement at 50 levels');

  // Past the limit neither may sign, so the receipt is built by hand and both
  // must reject it rather than recursing.
  const tooDeep = { ...nested(200), id: `sha256:${'0'.repeat(64)}`, signatures: [] } as unknown as Receipt;
  assert.equal(verifyReceipt(tooDeep, keys).ok, false);
  const deepResult = run(JSON.stringify(tooDeep));
  assert.equal(deepResult.status, 1, 'the two disagree past the depth limit');
  assert.doesNotMatch(deepResult.stdout + deepResult.stderr, /RecursionError|Traceback/);

  // A role that is not a string is not a signature, and is not skippable.
  const badRole = JSON.parse(JSON.stringify(item.receipt)) as Receipt;
  badRole.signatures.push({ role: 7, signer: 'x', signature: 'y' } as never);
  assert.equal(verifyReceipt(badRole, keys).ok, false);
  assert.equal(runReceipt(badRole).status, 1, 'the two disagree on a non-string role');
});

// Four more places a rule lived on one side only. Absent-versus-null is the
// sharpest: a language whose lookup returns null for a missing member cannot
// tell them apart unless it asks, and the reference requires policy to be
// present.
test('the two implementations agree on absent policy, key surrogates, empty roles, and sequences', when, () => {
  const vector = JSON.parse(readFileSync(VECTOR, 'utf8')) as GoldenVector;
  const keys = { registryKeys: [vector.keys.registry_public] };
  const item = vector.receipts[0] as GoldenVector['receipts'][number];

  const sign = (core: Record<string, unknown>): Receipt => {
    const bytes = canonicalBytes(core);
    return {
      ...core,
      id: sha256Digest(bytes),
      signatures: [{
        role: 'agent', signer: agentIdOf(bareJwk(vector.keys.agent_public)), alg: 'Ed25519',
        key: bareJwk(vector.keys.agent_public), signature: signBytes(bytes, vector.keys.agent_private),
      }],
    } as unknown as Receipt;
  };

  // policy must be present. An explicit null is fine; absent is not.
  const noPolicy = JSON.parse(JSON.stringify(item.core)) as Record<string, unknown>;
  delete noPolicy.policy;
  const signedNoPolicy = sign(noPolicy);
  assert.equal(verifyReceipt(signedNoPolicy, keys).ok, false, 'an absent policy must fail');
  assert.equal(run(JSON.stringify(signedNoPolicy)).status, 1, 'the two disagree on an absent policy');

  const nullPolicy = sign({ ...JSON.parse(JSON.stringify(item.core)) as object, policy: null });
  assert.equal(verifyReceipt(nullPolicy, keys).ok, true, 'an explicit null policy is valid');
  assert.equal(run(JSON.stringify(nullPolicy)).status, 0, 'the two disagree on a null policy');

  // An unpaired surrogate in a KEY, not just a value: it has to survive both
  // the sort and the output.
  const surrogateKey = JSON.parse(JSON.stringify(item.core)) as Record<string, unknown>;
  surrogateKey.environment = { '\ud800': 'lone surrogate key', ok: 1 };
  const signedKey = sign(surrogateKey);
  assert.equal(verifyReceipt(signedKey, keys).ok, true);
  assert.equal(run(JSON.stringify(signedKey)).status, 0, 'the two disagree on a surrogate in a key');

  // Any string role is an unknown role, empty included.
  for (const role of ['', '   ', 'runtime']) {
    const receipt = JSON.parse(JSON.stringify(item.receipt)) as Receipt;
    receipt.signatures.push({ role, signer: 'x', signature: 'y' } as never);
    assert.equal(verifyReceipt(receipt, keys).ok, true, `role ${JSON.stringify(role)} should be skipped`);
    assert.equal(runReceipt(receipt).status, 0, `the two disagree on role ${JSON.stringify(role)}`);
  }

  // A sequence past the safe integer range is a signed number breaking the
  // same rule the core obeys.
  const bigSequence = JSON.parse(JSON.stringify(item.receipt)) as Receipt;
  (bigSequence.signatures[1] as { sequence: number }).sequence = 2 ** 53;
  assert.equal(verifyReceipt(bigSequence, keys).ok, false);
  assert.equal(runReceipt(bigSequence).status, 1, 'the two disagree on an unsafe sequence');
});

// The eight tests above are regression tests: each names a bug that once
// existed and records why its rule is there, which is something a generator
// cannot do. What they cannot do is find a rule nobody thought to write a
// case for, and four review rounds found defects sitting next to cases the
// enumerated suite already covered. So this one generates instead, from a
// fixed seed so a failure is reproducible.
test('a generated corpus finds no disagreement between the two implementations', when, () => {
  const vector = JSON.parse(readFileSync(VECTOR, 'utf8')) as GoldenVector;
  const keys = { registryKeys: [vector.keys.registry_public] };
  const item = vector.receipts[0] as GoldenVector['receipts'][number];

  // mulberry32: a small deterministic PRNG, so CI failures are reproducible.
  let state = 0x9e3779b9;
  const random = () => {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const pick = <T,>(xs: T[]): T => xs[Math.floor(random() * xs.length)] as T;

  // The values that historically broke one implementation and not the other:
  // booleans where an integer is read, absent versus null, surrogates,
  // numbers outside the safe range, and wrong-typed containers.
  const HOSTILE: unknown[] = [
    null, true, false, 0, -1, 1.5, 2 ** 53, 1e21, '', '   ', '\ud800', 'age:agent:',
    [], {}, [null], { role: 7 }, 'sha256:' + 'z'.repeat(64), Number.MAX_SAFE_INTEGER,
  ];

  const paths = ['receipt_version', 'agent', 'timestamp', 'task', 'action', 'inputs',
    'outputs', 'environment', 'policy', 'id'];

  let compared = 0;
  for (let i = 0; i < 120; i += 1) {
    const core = JSON.parse(JSON.stringify(item.core)) as Record<string, unknown>;
    const mutations = 1 + Math.floor(random() * 3);
    for (let m = 0; m < mutations; m += 1) {
      const key = pick(paths);
      if (random() < 0.25) delete core[key];
      else core[key] = pick(HOSTILE);
    }

    // Sign with the raw primitives so only shape and canonicalization decide
    // the verdict; agentSign would reject most of these before signing.
    let receipt: Receipt;
    try {
      const bytes = canonicalBytes(core);
      receipt = {
        ...core, id: sha256Digest(bytes),
        signatures: [{
          role: 'agent', signer: agentIdOf(bareJwk(vector.keys.agent_public)), alg: 'Ed25519',
          key: bareJwk(vector.keys.agent_public), signature: signBytes(bytes, vector.keys.agent_private),
        }],
      } as unknown as Receipt;
    } catch {
      continue; // canonicalization refused it, which is a signer's job
    }

    // The reference must always answer, never raise.
    let reference: boolean;
    try {
      reference = verifyReceipt(receipt, keys).ok;
    } catch (error) {
      assert.fail(`the reference raised instead of reporting: ${String(error)}\n${JSON.stringify(core).slice(0, 300)}`);
    }
    const result = runReceipt(receipt);
    assert.doesNotMatch(result.stdout + result.stderr, /Traceback/,
      `verify.py raised on: ${JSON.stringify(core).slice(0, 300)}`);
    assert.equal(result.status === 0, reference,
      `the two implementations disagree on: ${JSON.stringify(core).slice(0, 300)}`);
    compared += 1;
  }
  assert.ok(compared > 100, `expected most cases to be comparable, got ${compared}`);
});

// The root and proof surface had no differential coverage at all for four
// review rounds, which is why a boolean index verifying as index 0 survived
// there. JSON has no boolean-as-number, but Python counts False as 0.
test('the two implementations agree on hostile roots and proofs', when, () => {
  const vector = JSON.parse(readFileSync(VECTOR, 'utf8')) as GoldenVector;
  const registryKeys = keyMapFromJwks([vector.keys.registry_public]);
  const item = vector.receipts[0] as GoldenVector['receipts'][number];
  const doc = vector.root.document;
  const proof = item.proof;

  const both = (d: unknown, p: unknown, label: string) => {
    let reference: boolean;
    try {
      reference = verifyRoot(d as never, registryKeys) && verifyRootInclusion(item.receipt, p as never, d as never);
    } catch (error) {
      assert.fail(`the reference raised on ${label}: ${String(error)}`);
    }
    const result = runRoot(item.receipt, d, p);
    assert.doesNotMatch(result.stdout + result.stderr, /Traceback/, `verify.py raised on ${label}`);
    assert.equal(result.stdout.trim() === 'INCLUDED', reference, `the two disagree on ${label}`);
  };

  both(doc, proof, 'the genuine root and proof');
  assert.equal(runRoot(item.receipt, doc, proof).stdout.trim(), 'INCLUDED', 'the genuine pair must verify');

  // A boolean where an integer is read. This is the direction that matters:
  // the reference says not included, and verify.py once said included.
  for (const field of ['index', 'size', 'sequence']) {
    for (const value of [false, true]) {
      both(doc, { ...proof, [field]: value }, `proof.${field} = ${value}`);
    }
  }
  for (const field of ['sequence_start', 'sequence_end']) {
    both({ ...doc, [field]: false }, proof, `root.${field} = false`);
  }

  const hostileDocs: unknown[] = [null, 42, 'x', [], {}, true,
    { ...doc, registry: 7 }, { ...doc, registry: 'nope' }, { ...doc, sequence_end: '3' },
    { ...doc, sequence_start: null }, { ...doc, root: 5 }, { ...doc, root: 'sha256:zz' },
    { ...doc, root_version: null }, { ...doc, signature: null }, { ...doc, sequence_end: 1 }];
  const hostileProofs: unknown[] = [null, 42, 'x', [], {},
    { ...proof, path: 'abc' }, { ...proof, path: [1, 2] }, { ...proof, path: ['zz'] },
    { ...proof, path: null }, { ...proof, index: -1 }, { ...proof, size: 0 },
    { ...proof, sequence: null }, { ...proof, index: 1.5 }];

  for (const d of hostileDocs) {
    for (const p of hostileProofs) {
      both(d, p, `${JSON.stringify(d).slice(0, 60)} with ${JSON.stringify(p).slice(0, 60)}`);
    }
  }
});

// JavaScript erases the difference between 3 and 3.0 before the value is ever
// text, so no object-level mutation can produce this case. The literal has to
// be spliced into the serialized JSON after signing, which is how a release
// review found it: one implementation asked whether the value was an integer
// and the other asked whether the type was.
test('the two implementations agree on integers written as floats', when, () => {
  const vector = JSON.parse(readFileSync(VECTOR, 'utf8')) as GoldenVector;
  const keys = { registryKeys: [vector.keys.registry_public] };
  const receipt = vector.receipts[0]?.receipt as Receipt;
  const text = JSON.stringify(receipt);
  assert.match(text, /"files_changed":3\b/, 'the seed carries the integer this test rewrites');

  // Every spelling of the same value canonicalizes to 3, so the id and both
  // signatures still cover identical bytes and only the number rule decides.
  for (const literal of ['3.0', '3e0', '300e-2', '3.00000']) {
    const spliced = text.replace('"files_changed":3', `"files_changed":${literal}`);
    const parsed = JSON.parse(spliced) as Receipt;
    assert.equal(verifyReceipt(parsed, keys).ok, true, `${literal} denotes 3 and must verify`);
    assert.equal(runReceiptText(spliced).status, 0, `the two disagree on the literal ${literal}`);
  }

  // A value that is not a whole number is still refused, from either spelling.
  for (const literal of ['3.5', '3.0000001']) {
    const spliced = text.replace('"files_changed":3', `"files_changed":${literal}`);
    const parsed = JSON.parse(spliced) as Receipt;
    assert.equal(verifyReceipt(parsed, keys).ok, false, `${literal} is not an integer`);
    assert.equal(runReceiptText(spliced).status, 1, `the two disagree on the literal ${literal}`);
  }
});
