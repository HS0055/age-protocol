import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  agentSign, registrySign, verifyReceipt, buildRoot, proofFor, verifyRoot, verifyRootInclusion, attestationOf,
  registrySignatureOf, canonicalize, canonicalBytes, agentIdOf, registryIdOf, receiptIdOf, rootSigningInput,
  RECEIPT_VERSION, ATTESTATION_VERSION, ROOT_VERSION,
  type PrivateJwk, type PublicJwk, type Receipt, type ReceiptCore, type RegistryAssignment, type RootDocument, type RootProof,
} from '../src/index.ts';

interface Golden {
  versions: { receipt: string; attestation: string; root: string };
  keys: { agent_private: PrivateJwk; agent_public: PublicJwk; agent_id: string; registry_private: PrivateJwk; registry_public: PublicJwk; registry_id: string };
  core: ReceiptCore;
  agent_signing_input: string;
  signed: Receipt;
  assignment: RegistryAssignment;
  attestation: Record<string, unknown>;
  registry_signing_input: string;
  receipt: Receipt;
  root: { document: RootDocument; signing_input: string; leaves: string[] };
  proof: RootProof;
}

const fixtureText = readFileSync(join(import.meta.dirname, 'fixtures', 'golden.json'), 'utf8');
const golden = JSON.parse(fixtureText) as Golden;

test('the published copy is byte identical to the fixture', () => {
  const published = readFileSync(join(import.meta.dirname, '..', '..', '..', 'docs', 'protocol', 'golden-v0.1.json'), 'utf8');
  assert.equal(published, fixtureText);
});

test('the vector pins the version strings and derived ids', () => {
  assert.deepEqual(golden.versions, { receipt: RECEIPT_VERSION, attestation: ATTESTATION_VERSION, root: ROOT_VERSION });
  assert.equal(agentIdOf(golden.keys.agent_public), golden.keys.agent_id);
  assert.equal(registryIdOf(golden.keys.registry_public), golden.keys.registry_id);
  assert.equal(golden.core.agent, golden.keys.agent_id);
});

test('the agent-signed receipt is reproduced byte for byte', () => {
  assert.equal(canonicalize(golden.core), golden.agent_signing_input);
  const signed = agentSign(golden.core, golden.keys.agent_private);
  assert.deepEqual(signed, golden.signed);
  assert.equal(signed.id, receiptIdOf(golden.core));
});

test('the registered receipt and its attestation are reproduced byte for byte', () => {
  const receipt = registrySign(golden.signed, golden.assignment, golden.keys.registry_private);
  assert.deepEqual(receipt, golden.receipt);
  const entry = registrySignatureOf(receipt);
  assert.ok(entry);
  assert.deepEqual(attestationOf(receipt, entry), golden.attestation);
  assert.equal(canonicalize(golden.attestation), golden.registry_signing_input);
});

test('the registered receipt passes all four checks against the registry key', () => {
  const result = verifyReceipt(golden.receipt, { registryKeys: [golden.keys.registry_public] });
  assert.equal(result.ok, true);
  assert.deepEqual(result.checks.map((c) => [c.name, c.status]), [
    ['integrity', 'pass'], ['agent_signature', 'pass'], ['agent_identity', 'pass'], ['registry_signature', 'pass'],
  ]);
});

test('the daily root and proof are reproduced and verify', () => {
  const root = buildRoot([golden.receipt], '2026-09-05', golden.keys.registry_private);
  assert.deepEqual(root, golden.root.document);
  assert.equal(Buffer.from(rootSigningInput(root)).toString('utf8'), golden.root.signing_input);
  assert.deepEqual([Buffer.from(canonicalBytes(golden.receipt)).toString('utf8')], golden.root.leaves);
  assert.equal(verifyRoot(golden.root.document, [golden.keys.registry_public]), true);
  assert.deepEqual(proofFor([golden.receipt], golden.receipt, golden.keys.registry_id), golden.proof);
  assert.equal(verifyRootInclusion(golden.receipt, golden.proof, golden.root.document), true);
});
