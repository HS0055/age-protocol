// Regenerates the golden interop vector. Run it from the repository root with
//   node packages/receipts/test/fixtures/generate-golden.ts
// It writes packages/receipts/test/fixtures/golden.json and the published copy
// docs/protocol/golden-v0.json. Only run it when the receipt format changes on
// purpose: golden.test.ts recomputes every value here from the same inputs, so
// an accidental change to canonicalization or to a signing input fails the
// suite instead of silently rewriting the vector.
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import {
  canonicalize, canonicalBytes, cloudSign, inclusionProof, merkleRoot, nodeSign, nodeSigningInput,
  cloudSigningInput, receiptHash, signBytes, toPublicJwk, thumbprint, RECEIPT_TYP, ROOT_TYP,
  type CloudAssigned, type PrivateJwk, type Receipt, type ReceiptEnvelope,
} from '../../src/index.ts';

// Test keys. They are committed on purpose and protect nothing.
const NODE_PRIVATE: PrivateJwk = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'IJjrqzBsYmLNgOh76Cph8OYAeIkpxHXR0k28xf8SjXI',
  d: 'CvQU_DK7O3sM-JrIFU921zbpLfsPPo2T66nUuJAYOco',
};
const CLOUD_PRIVATE: PrivateJwk = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: '4yPv79M7Uisr3EgqnoMis3sP1oNS8ZS-dOC6pl7AZxA',
  d: 'kiC9G4g5LyH7sSXVF5lR4WkHCVUBsa9ANwMdb27Ymug',
};

const NODE_PUBLIC = toPublicJwk(NODE_PRIVATE);
const CLOUD_PUBLIC = toPublicJwk(CLOUD_PRIVATE);
const NODE_JKT = thumbprint(NODE_PUBLIC);
const CLOUD_JKT = thumbprint(CLOUD_PUBLIC);
const DATE = '2026-09-04';

const first: ReceiptEnvelope = {
  typ: RECEIPT_TYP,
  v: 1,
  ts: '2026-09-04T14:02:11Z',
  company: 'org_golden',
  mission: 'msn_1',
  task: 'tsk_1',
  run: 'run_1',
  actor: { type: 'agent', jkt: 'agent_golden', level: 0 },
  node: { jkt: NODE_JKT },
  cloud: { jkt: CLOUD_JKT },
  action: { type: 'session.started', adapter: 'claude-code' },
  inputs: [{ kind: 'prompt_bundle', sha256: 'aa'.repeat(32) }],
  outputs: [],
  gate: null,
};

// The second envelope embeds the node public key, which a verifier accepts
// only because it hashes to the same jkt.
const second: ReceiptEnvelope = {
  ...first,
  ts: '2026-09-04T14:09:48Z',
  node: { jkt: NODE_JKT, jwk: NODE_PUBLIC },
  action: { type: 'git.commit', ref: '9f1c2ab', files: 3 },
  outputs: [{ kind: 'diff', sha256: 'bb'.repeat(32) }],
};

interface GoldenReceipt {
  envelope: ReceiptEnvelope;
  node_signing_input: string;
  node_sig: string;
  assigned: CloudAssigned;
  cloud_signing_input: string;
  receipt: Receipt;
  receipt_hash: string;
}

function issue(envelope: ReceiptEnvelope, assigned: CloudAssigned): GoldenReceipt {
  const signed = nodeSign(envelope, NODE_PRIVATE);
  const receipt = cloudSign(signed, assigned, CLOUD_PRIVATE);
  return {
    envelope,
    node_signing_input: canonicalize(signed),
    node_sig: signed.node_sig,
    assigned,
    cloud_signing_input: Buffer.from(cloudSigningInput(receipt)).toString('utf8'),
    receipt,
    receipt_hash: receiptHash(receipt),
  };
}

const one = issue(first, { id: 'rcpt_golden_1', seq: 1, prev: null });
const two = issue(second, { id: 'rcpt_golden_2', seq: 2, prev: one.receipt_hash });

// The daily tree takes the canonical bytes of every receipt issued that UTC
// day as its leaves, in ascending seq order.
const leaves = [one.receipt, two.receipt].map((receipt) => canonicalBytes(receipt));
const rootHex = merkleRoot(leaves).toString('hex');
const rootDocument = {
  typ: ROOT_TYP,
  date: DATE,
  size: leaves.length,
  root: rootHex,
  cloud: { jkt: CLOUD_JKT },
  sig: signBytes(canonicalBytes({ typ: ROOT_TYP, date: DATE, size: leaves.length, root: rootHex }), CLOUD_PRIVATE),
};

const golden = {
  note: 'Golden interop vector for the AGIE receipt protocol v0. Fixed keys, fixed events, byte-identical output. Ed25519 is deterministic, so any conforming implementation reproduces every signature here.',
  typ: { receipt: RECEIPT_TYP, root: ROOT_TYP },
  keys: {
    node_private: NODE_PRIVATE,
    node_public: NODE_PUBLIC,
    node_jkt: NODE_JKT,
    cloud_private: CLOUD_PRIVATE,
    cloud_public: CLOUD_PUBLIC,
    cloud_jkt: CLOUD_JKT,
  },
  receipts: [one, two],
  root: {
    document: rootDocument,
    signing_input: canonicalize({ typ: ROOT_TYP, date: DATE, size: leaves.length, root: rootHex }),
    leaves: leaves.map((leaf) => Buffer.from(leaf).toString('utf8')),
  },
  proof: inclusionProof(leaves, 1),
};

const here = import.meta.dirname;
const repository = join(here, '..', '..', '..', '..');
const text = `${JSON.stringify(golden, null, 2)}\n`;
for (const target of [join(here, 'golden.json'), join(repository, 'docs', 'protocol', 'golden-v0.json')]) {
  writeFileSync(target, text);
  process.stdout.write(`wrote ${target.slice(dirname(repository).length + 1)}\n`);
}
