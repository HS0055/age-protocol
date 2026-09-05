import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  agentSign, registrySign, buildRoot, proofFor, verifyRoot, verifyRootInclusion, sequenceOf, rootLeaves,
  rootSigningInput, generateKeyPair, agentIdOf, registryIdOf, canonicalBytes, verifyBytes, ROOT_VERSION, RECEIPT_VERSION,
  bareJwk, toPublicJwk, signBytes, registrySigningInput,
  type PrivateJwk, type PublicJwk, type Receipt, type ReceiptCore, type RegistrySignature, type RootDocument, type RootProof,
} from '../src/index.ts';

const agent = generateKeyPair();
const registry = generateKeyPair();
const second = generateKeyPair();
const stranger = generateKeyPair();

function issue(sequence: number): Receipt {
  const core: ReceiptCore = {
    receipt_version: RECEIPT_VERSION, agent: agentIdOf(agent.publicJwk), timestamp: `2026-09-05T03:${String(sequence).padStart(2, '0')}:00Z`,
    task: { id: `tsk_${sequence}` }, action: { type: 'git.commit', commit: 'a'.repeat(40) }, inputs: [], outputs: [], environment: {}, policy: null,
  };
  return registrySign(agentSign(core, agent.privateJwk), { sequence, registered_at: '2026-09-05T04:00:00Z' }, registry.privateJwk);
}

const REGISTRY_ID = registryIdOf(registry.publicJwk);
const SECOND_ID = registryIdOf(second.publicJwk);

// registrySign issues a first registration only. A second registry
// countersigns with the same exported primitives it would use itself.
function countersign(receipt: Receipt, sequence: number, registryPrivate: PrivateJwk): Receipt {
  const signer = registryIdOf(bareJwk(toPublicJwk(registryPrivate)));
  const registered_at = '2026-09-05T06:00:00Z';
  const signature = signBytes(registrySigningInput(receipt, { sequence, registered_at, signer }), registryPrivate);
  const entry: RegistrySignature = { role: 'registry', signer, alg: 'Ed25519', sequence, registered_at, signature };
  return { ...receipt, signatures: [...receipt.signatures, entry] };
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
  assert.deepEqual(rootLeaves([seven, five, six], REGISTRY_ID), [five, six, seven].map((r) => canonicalBytes(r)));
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
    const proof = proofFor(all, receipt, REGISTRY_ID);
    assert.equal(proof.sequence, sequenceOf(receipt, REGISTRY_ID));
    assert.equal(proof.index, proof.sequence - doc.sequence_start);
    assert.equal(proof.size, 3);
    assert.equal(verifyRootInclusion(receipt, proof, doc), true, `sequence ${proof.sequence}`);
  }
});

test('inclusion fails for a tampered receipt, a wrong sequence, a wrong size, or a foreign root', () => {
  const all = [five, six, seven];
  const doc = buildRoot(all, '2026-09-05', registry.privateJwk);
  const proof = proofFor(all, six, REGISTRY_ID);
  assert.equal(verifyRootInclusion({ ...six, timestamp: '2026-09-05T03:59:00Z' }, proof, doc), false);
  assert.equal(verifyRootInclusion(six, { ...proof, sequence: 7 }, doc), false);
  assert.equal(verifyRootInclusion(six, { ...proof, size: 2 }, doc), false);
  const other = buildRoot([five, six], '2026-09-05', registry.privateJwk);
  assert.equal(verifyRootInclusion(six, proof, other), false);
});

test('buildRoot needs receipts and sequenceOf needs a registration', () => {
  assert.throws(() => buildRoot([], '2026-09-05', registry.privateJwk), /no receipts/);
  const unregistered = agentSign({ ...five, signatures: [] } as unknown as ReceiptCore, agent.privateJwk);
  assert.throws(() => sequenceOf(unregistered, REGISTRY_ID), /not registered/);
  assert.throws(() => sequenceOf(five, registryIdOf(stranger.publicJwk)), /not registered/);
  assert.throws(() => proofFor([five], six, REGISTRY_ID), /not among/);
});

test('verifyRoot and verifyRootInclusion answer false for malformed input instead of throwing', () => {
  const all = [five, six, seven];
  const doc = buildRoot(all, '2026-09-05', registry.privateJwk);
  const proof = proofFor(all, six, REGISTRY_ID);
  for (const value of [null, undefined, 42, 'root', [], {}, true]) {
    const label = String(value);
    assert.equal(verifyRoot(value as unknown as RootDocument, [registry.publicJwk]), false, `root ${label}`);
    assert.equal(verifyRootInclusion(six, proof, value as unknown as RootDocument), false, `doc ${label}`);
    assert.equal(verifyRootInclusion(value as unknown as Receipt, proof, doc), false, `receipt ${label}`);
    assert.equal(verifyRootInclusion(six, value as unknown as RootProof, doc), false, `proof ${label}`);
  }
  assert.equal(verifyRoot({ ...doc, signature: null } as unknown as RootDocument, [registry.publicJwk]), false);
  assert.equal(verifyRoot({ ...doc, registry: null } as unknown as RootDocument, [registry.publicJwk]), false);
  assert.equal(verifyRoot(doc, null as unknown as PublicJwk[]), false);
  assert.equal(verifyRoot(doc, [null] as unknown as PublicJwk[]), false);
  assert.equal(verifyRootInclusion(six, { ...proof, path: null } as unknown as RootProof, doc), false);
  assert.equal(verifyRootInclusion(six, { ...proof, index: 'one' } as unknown as RootProof, doc), false);
  assert.equal(verifyRootInclusion(six, proof, { ...doc, sequence_start: 'five' } as unknown as RootDocument), false);
  assert.equal(verifyRootInclusion(six, proof, { ...doc, root: 42 } as unknown as RootDocument), false);
});

test('buildRoot refuses a sequence range with a gap or a duplicate, and proofFor refuses the same', () => {
  assert.throws(() => buildRoot([five, seven], '2026-09-05', registry.privateJwk), /5.*7/);
  assert.throws(() => buildRoot([five, five, six], '2026-09-05', registry.privateJwk), /5/);
  assert.throws(() => buildRoot([five, five, six], '2026-09-05', registry.privateJwk), /twice/);
  assert.throws(() => proofFor([five, seven], five, REGISTRY_ID), /5.*7/);
  const doc = buildRoot([five, six, seven], '2026-09-05', registry.privateJwk);
  for (const receipt of [five, six, seven]) {
    assert.equal(verifyRootInclusion(receipt, proofFor([five, six, seven], receipt, REGISTRY_ID), doc), true);
  }
});

test('a root belongs to one registry, and a proof does not cross to another', () => {
  // The second registry registers the same three receipts in the opposite
  // order, so the two registries disagree about both sequence and position.
  const a = countersign(five, 102, second.privateJwk);
  const b = countersign(six, 101, second.privateJwk);
  const c = countersign(seven, 100, second.privateJwk);
  const all = [a, b, c];

  const rootA = buildRoot(all, '2026-09-05', registry.privateJwk);
  const rootB = buildRoot(all, '2026-09-05', second.privateJwk);
  assert.equal(rootA.registry, REGISTRY_ID);
  assert.equal(rootB.registry, SECOND_ID);
  assert.deepEqual([rootA.sequence_start, rootA.sequence_end], [5, 7]);
  assert.deepEqual([rootB.sequence_start, rootB.sequence_end], [100, 102]);
  assert.notEqual(rootA.root, rootB.root);
  assert.equal(verifyRoot(rootA, [registry.publicJwk]), true);
  assert.equal(verifyRoot(rootB, [second.publicJwk]), true);

  for (const receipt of all) {
    const proofA = proofFor(all, receipt, REGISTRY_ID);
    const proofB = proofFor(all, receipt, SECOND_ID);
    assert.equal(proofA.sequence, sequenceOf(receipt, REGISTRY_ID));
    assert.equal(proofB.sequence, sequenceOf(receipt, SECOND_ID));
    assert.equal(verifyRootInclusion(receipt, proofA, rootA), true, 'own root');
    assert.equal(verifyRootInclusion(receipt, proofB, rootB), true, 'own root');
    assert.equal(verifyRootInclusion(receipt, proofA, rootB), false, 'foreign root');
    assert.equal(verifyRootInclusion(receipt, proofB, rootA), false, 'foreign root');
  }
});
