import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  verifyReceipt, canonicalBytes, sha256Digest, signBytes, bareJwk, agentIdOf,
  type PrivateJwk, type PublicJwk, type Receipt, type ReceiptCore,
} from '../src/index.ts';

interface GoldenVector {
  keys: { agent_private: PrivateJwk; agent_public: PublicJwk; registry_public: PublicJwk };
  receipts: { core: ReceiptCore; receipt: Receipt }[];
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
    const second = run(JSON.stringify(receipt)).status === 0;
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
    const second = run(JSON.stringify(receipt)).status === 0;
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

