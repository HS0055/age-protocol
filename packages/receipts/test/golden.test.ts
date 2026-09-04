import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  canonicalize, canonicalBytes, cloudSign, cloudSigningInput, inclusionProof, merkleRoot, nodeSign,
  receiptHash, thumbprint, verifyBytes, verifyChain, verifyInclusion, verifyReceipt, RECEIPT_TYP, ROOT_TYP,
  type CloudAssigned, type InclusionProof, type PrivateJwk, type PublicJwk, type Receipt, type ReceiptEnvelope,
} from '../src/index.ts';

interface GoldenReceipt {
  envelope: ReceiptEnvelope;
  node_signing_input: string;
  node_sig: string;
  assigned: CloudAssigned;
  cloud_signing_input: string;
  receipt: Receipt;
  receipt_hash: string;
}

interface RootDocument {
  typ: string;
  date: string;
  size: number;
  root: string;
  cloud: { jkt: string };
  sig: string;
}

interface Golden {
  typ: { receipt: string; root: string };
  keys: {
    node_private: PrivateJwk;
    node_public: PublicJwk;
    node_jkt: string;
    cloud_private: PrivateJwk;
    cloud_public: PublicJwk;
    cloud_jkt: string;
  };
  receipts: GoldenReceipt[];
  root: { document: RootDocument; signing_input: string; leaves: string[] };
  proof: InclusionProof;
}

const fixtureText = readFileSync(join(import.meta.dirname, 'fixtures', 'golden.json'), 'utf8');
const golden = JSON.parse(fixtureText) as Golden;
const keys = [golden.keys.node_public, golden.keys.cloud_public];

test('the published copy of the vector is byte identical to the fixture', () => {
  const published = readFileSync(
    join(import.meta.dirname, '..', '..', '..', 'docs', 'protocol', 'golden-v0.json'),
    'utf8',
  );
  assert.equal(published, fixtureText);
});

test('the vector pins the current typ values and thumbprints', () => {
  assert.equal(golden.typ.receipt, RECEIPT_TYP);
  assert.equal(golden.typ.root, ROOT_TYP);
  assert.equal(thumbprint(golden.keys.node_public), golden.keys.node_jkt);
  assert.equal(thumbprint(golden.keys.cloud_public), golden.keys.cloud_jkt);
});

for (const [index, entry] of golden.receipts.entries()) {
  test(`receipt ${index} is reproduced byte for byte from the fixed inputs`, () => {
    const signed = nodeSign(entry.envelope, golden.keys.node_private);
    assert.equal(canonicalize(signed), entry.node_signing_input);
    assert.equal(signed.node_sig, entry.node_sig);

    const receipt = cloudSign(signed, entry.assigned, golden.keys.cloud_private);
    assert.equal(Buffer.from(cloudSigningInput(receipt)).toString('utf8'), entry.cloud_signing_input);
    assert.equal(receipt.cloud_sig, entry.receipt.cloud_sig);
    assert.deepEqual(receipt, entry.receipt);
    assert.equal(canonicalize(receipt), canonicalize(entry.receipt));
    assert.equal(receiptHash(receipt), entry.receipt_hash);
  });

  test(`receipt ${index} verifies against the published keys`, () => {
    assert.deepEqual(verifyReceipt(entry.receipt, keys), { ok: true, node: 'valid', cloud: 'valid', errors: [] });
  });
}

test('the second receipt verifies from its embedded node key alone', () => {
  const second = golden.receipts[1] as GoldenReceipt;
  assert.equal(second.receipt.node?.jwk?.x, golden.keys.node_public.x);
  assert.equal(verifyReceipt(second.receipt, [golden.keys.cloud_public]).ok, true);
});

test('the two receipts form a chain', () => {
  const chain = golden.receipts.map((entry) => entry.receipt);
  assert.equal(chain[1]?.prev, golden.receipts[0]?.receipt_hash);
  assert.deepEqual(verifyChain(chain), { ok: true, length: 2, errors: [] });
});

test('the daily root is the Merkle root over the canonical receipts in seq order', () => {
  const leaves = golden.receipts.map((entry) => canonicalBytes(entry.receipt));
  assert.deepEqual(leaves.map((leaf) => Buffer.from(leaf).toString('utf8')), golden.root.leaves);
  assert.equal(merkleRoot(leaves).toString('hex'), golden.root.document.root);
});

test('the root signature covers typ, date, size, and root', () => {
  const document = golden.root.document;
  const input = canonicalize({ typ: document.typ, date: document.date, size: document.size, root: document.root });
  assert.equal(input, golden.root.signing_input);
  assert.equal(verifyBytes(new TextEncoder().encode(input), document.sig, golden.keys.cloud_public), true);
});

test('the inclusion proof for the second receipt is reproduced and verifies', () => {
  const leaves = golden.receipts.map((entry) => canonicalBytes(entry.receipt));
  assert.deepEqual(inclusionProof(leaves, 1), golden.proof);
  assert.equal(verifyInclusion(leaves[1] as Uint8Array, golden.proof, golden.root.document.root), true);
});
