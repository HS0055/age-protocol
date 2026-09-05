import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  agentSign, registrySign, buildRoot, proofFor, verifyRoot, verifyRootInclusion, sequenceOf, rootLeaves,
  rootSigningInput, generateKeyPair, agentIdOf, registryIdOf, canonicalBytes, verifyBytes, ROOT_VERSION, RECEIPT_VERSION,
  type Receipt, type ReceiptCore, type RootDocument,
} from '../src/index.ts';

const agent = generateKeyPair();
const registry = generateKeyPair();
const stranger = generateKeyPair();

function issue(sequence: number): Receipt {
  const core: ReceiptCore = {
    receipt_version: RECEIPT_VERSION, agent: agentIdOf(agent.publicJwk), timestamp: `2026-09-05T03:${String(sequence).padStart(2, '0')}:00Z`,
    task: { id: `tsk_${sequence}` }, action: { type: 'git.commit', commit: 'a'.repeat(40) }, inputs: [], outputs: [], environment: {}, policy: null,
  };
  return registrySign(agentSign(core, agent.privateJwk), { sequence, registered_at: '2026-09-05T04:00:00Z' }, registry.privateJwk);
}

const five = issue(5);
const six = issue(6);
const seven = issue(7);

test('buildRoot orders leaves by sequence and signs the document without its signature', () => {
  const doc = buildRoot([seven, five, six], '2026-09-05', registry.privateJwk);
  assert.equal(doc.root_version, ROOT_VERSION);
  assert.equal(doc.registry, registryIdOf(registry.publicJwk));
  assert.equal(doc.sequence_start, 5);
  assert.equal(doc.sequence_end, 7);
  assert.match(doc.root, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(rootLeaves([seven, five, six]), [five, six, seven].map((r) => canonicalBytes(r)));
  assert.equal(verifyBytes(rootSigningInput(doc), doc.signature, registry.publicJwk), true);
  assert.equal(verifyRoot(doc, [registry.publicJwk]), true);
  assert.equal(verifyRoot(doc, [stranger.publicJwk]), false);
  assert.equal(verifyRoot({ ...doc, date: '2026-09-06' }, [registry.publicJwk]), false);
  assert.equal(verifyRoot({ ...doc, root_version: '0.0' } as unknown as RootDocument, [registry.publicJwk]), false);
});

test('every receipt has an inclusion proof that verifies against the root', () => {
  const all = [five, six, seven];
  const doc = buildRoot(all, '2026-09-05', registry.privateJwk);
  for (const receipt of all) {
    const proof = proofFor(all, receipt);
    assert.equal(proof.sequence, sequenceOf(receipt));
    assert.equal(proof.index, proof.sequence - doc.sequence_start);
    assert.equal(proof.size, 3);
    assert.equal(verifyRootInclusion(receipt, proof, doc), true, `sequence ${proof.sequence}`);
  }
});

test('inclusion fails for a tampered receipt, a wrong sequence, a wrong size, or a foreign root', () => {
  const all = [five, six, seven];
  const doc = buildRoot(all, '2026-09-05', registry.privateJwk);
  const proof = proofFor(all, six);
  assert.equal(verifyRootInclusion({ ...six, timestamp: '2026-09-05T03:59:00Z' }, proof, doc), false);
  assert.equal(verifyRootInclusion(six, { ...proof, sequence: 7 }, doc), false);
  assert.equal(verifyRootInclusion(six, { ...proof, size: 2 }, doc), false);
  const other = buildRoot([five, six], '2026-09-05', registry.privateJwk);
  assert.equal(verifyRootInclusion(six, proof, other), false);
});

test('buildRoot needs receipts and sequenceOf needs a registration', () => {
  assert.throws(() => buildRoot([], '2026-09-05', registry.privateJwk), /no receipts/);
  const unregistered = agentSign({ ...five, signatures: [] } as unknown as ReceiptCore, agent.privateJwk);
  assert.throws(() => sequenceOf(unregistered), /not registered/);
  assert.throws(() => proofFor([five], six), /not among/);
});
