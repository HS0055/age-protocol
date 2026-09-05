import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  agentSign, registrySign, verifyReceipt, buildRoot, proofFor, verifyRoot, verifyRootInclusion, attestationOf,
  registrySignatureOf, canonicalize, canonicalBytes, agentIdOf, registryIdOf, receiptIdOf, rootSigningInput, rootLeaves,
  RECEIPT_VERSION, ATTESTATION_VERSION, ROOT_VERSION,
  type PrivateJwk, type PublicJwk, type Receipt, type ReceiptCore, type RegistryAssignment, type RootDocument, type RootProof,
} from '../src/index.ts';

interface GoldenReceipt {
  core: ReceiptCore;
  agent_signing_input: string;
  signed: Receipt;
  assignment: RegistryAssignment;
  attestation: Record<string, unknown>;
  registry_signing_input: string;
  receipt: Receipt;
  proof: RootProof;
}

interface Golden {
  versions: { receipt: string; attestation: string; root: string };
  keys: { agent_private: PrivateJwk; agent_public: PublicJwk; agent_id: string; registry_private: PrivateJwk; registry_public: PublicJwk; registry_id: string };
  receipts: GoldenReceipt[];
  root: { document: RootDocument; signing_input: string; leaves: string[] };
}

const fixtureText = readFileSync(join(import.meta.dirname, 'fixtures', 'golden.json'), 'utf8');
const golden = JSON.parse(fixtureText) as Golden;
const receipts = golden.receipts.map((item) => item.receipt);

test('the published copy is byte identical to the fixture', () => {
  const published = readFileSync(join(import.meta.dirname, '..', '..', '..', 'docs', 'protocol', 'golden-v0.1.json'), 'utf8');
  assert.equal(published, fixtureText);
});

test('the vector pins the version strings and derived ids', () => {
  assert.deepEqual(golden.versions, { receipt: RECEIPT_VERSION, attestation: ATTESTATION_VERSION, root: ROOT_VERSION });
  assert.equal(agentIdOf(golden.keys.agent_public), golden.keys.agent_id);
  assert.equal(registryIdOf(golden.keys.registry_public), golden.keys.registry_id);
  for (const item of golden.receipts) assert.equal(item.core.agent, golden.keys.agent_id);
});

test('all three agent-signed receipts are reproduced byte for byte', () => {
  assert.equal(golden.receipts.length, 3);
  for (const item of golden.receipts) {
    assert.equal(canonicalize(item.core), item.agent_signing_input);
    const signed = agentSign(item.core, golden.keys.agent_private);
    assert.deepEqual(signed, item.signed);
    assert.equal(signed.id, receiptIdOf(item.core));
  }
});

test('the vector pins the two canonicalization corners RFC 8785 is easiest to get wrong', () => {
  // Key order is by UTF-16 code unit, so the supplementary-plane key sorts
  // before U+FFFF even though its code point is larger.
  const environment = golden.receipts[1]?.core.environment as Record<string, unknown>;
  const keys = Object.keys(environment);
  const toolchain = keys.findIndex((key) => key.codePointAt(0) === 0x1f527);
  const sentinel = keys.findIndex((key) => key.codePointAt(0) === 0xffff);
  assert.ok(toolchain >= 0 && sentinel >= 0, 'the vector carries both keys');
  const order = canonicalize(environment);
  assert.ok(order.indexOf(keys[toolchain] as string) < order.indexOf(keys[sentinel] as string), 'UTF-16 code unit order');

  // Numbers are serialized the ES6 way: an integral value has no fractional
  // part, and one beyond the safe integer range is exponential.
  const action = golden.receipts[2]?.core.action as Record<string, unknown>;
  assert.equal(action.regressions, 1);
  assert.equal(action.operations, 1e21);
  assert.match(golden.receipts[2]?.agent_signing_input ?? '', /"operations":1e\+21/);
  assert.match(golden.receipts[2]?.agent_signing_input ?? '', /"regressions":1,/);
});

test('all three registered receipts and their attestations are reproduced byte for byte', () => {
  for (const item of golden.receipts) {
    const receipt = registrySign(item.signed, item.assignment, golden.keys.registry_private);
    assert.deepEqual(receipt, item.receipt);
    const entry = registrySignatureOf(receipt);
    assert.ok(entry);
    assert.deepEqual(attestationOf(receipt, entry), item.attestation);
    assert.equal(canonicalize(item.attestation), item.registry_signing_input);
  }
});

test('every registered receipt passes all four checks against the registry key', () => {
  for (const item of golden.receipts) {
    const result = verifyReceipt(item.receipt, { registryKeys: [golden.keys.registry_public] });
    assert.equal(result.ok, true, item.receipt.id);
    assert.deepEqual(result.checks.map((c) => [c.name, c.status]), [
      ['integrity', 'pass'], ['agent_signature', 'pass'], ['agent_identity', 'pass'], ['registry_signature', 'pass'],
    ]);
  }
});

test('the daily root over three leaves is reproduced and every proof verifies', () => {
  const root = buildRoot(receipts, '2026-09-05', golden.keys.registry_private);
  assert.deepEqual(root, golden.root.document);
  assert.equal(Buffer.from(rootSigningInput(root)).toString('utf8'), golden.root.signing_input);
  assert.deepEqual(rootLeaves(receipts, golden.keys.registry_id).map((leaf) => Buffer.from(leaf).toString('utf8')), golden.root.leaves);
  assert.deepEqual(receipts.map((receipt) => Buffer.from(canonicalBytes(receipt)).toString('utf8')), golden.root.leaves);
  assert.equal(verifyRoot(golden.root.document, [golden.keys.registry_public]), true);
  assert.deepEqual([root.sequence_start, root.sequence_end], [184, 186]);

  for (const item of golden.receipts) {
    const proof = proofFor(receipts, item.receipt, golden.keys.registry_id);
    assert.deepEqual(proof, item.proof);
    assert.ok(proof.path.length > 0, 'every proof path is exercised');
    assert.equal(verifyRootInclusion(item.receipt, item.proof, golden.root.document), true, `sequence ${proof.sequence}`);
  }
  assert.deepEqual(golden.receipts.map((item) => item.proof.path.length), [2, 2, 1]);
});
