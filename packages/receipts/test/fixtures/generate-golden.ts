// Regenerates the golden interop vector for AGE Protocol v0.1. Run from the
// repository root:
//   node packages/receipts/test/fixtures/generate-golden.ts
// It writes packages/receipts/test/fixtures/golden.json and the published copy
// docs/protocol/golden-v0.1.json. Only run it when the format changes on
// purpose: golden.test.ts recomputes every value here from the same inputs.
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  agentSign, registrySign, buildRoot, proofFor, attestationOf, registrySignatureOf, canonicalize, canonicalBytes,
  agentIdOf, registryIdOf, toPublicJwk, bareJwk, rootSigningInput,
  RECEIPT_VERSION, ATTESTATION_VERSION, ROOT_VERSION,
  type PrivateJwk, type ReceiptCore,
} from '../../src/index.ts';

// Test keys. They are committed on purpose and protect nothing.
const AGENT_PRIVATE: PrivateJwk = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'IJjrqzBsYmLNgOh76Cph8OYAeIkpxHXR0k28xf8SjXI',
  d: 'CvQU_DK7O3sM-JrIFU921zbpLfsPPo2T66nUuJAYOco',
};
const REGISTRY_PRIVATE: PrivateJwk = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: '4yPv79M7Uisr3EgqnoMis3sP1oNS8ZS-dOC6pl7AZxA',
  d: 'kiC9G4g5LyH7sSXVF5lR4WkHCVUBsa9ANwMdb27Ymug',
};

const AGENT_PUBLIC = bareJwk(toPublicJwk(AGENT_PRIVATE));
const REGISTRY_PUBLIC = bareJwk(toPublicJwk(REGISTRY_PRIVATE));
const AGENT_ID = agentIdOf(AGENT_PUBLIC);
const REGISTRY_ID = registryIdOf(REGISTRY_PUBLIC);
const COMMIT = '8fa72c1e5b9d4a3f2e1c0b9a8d7f6e5c4b3a2918';
const JWKS_URL = 'https://registry.ageprotocol.dev/.well-known/age-jwks.json';

const core: ReceiptCore = {
  receipt_version: RECEIPT_VERSION,
  agent: AGENT_ID,
  timestamp: '2026-09-05T03:20:00Z',
  task: { id: 'tsk_91', description: 'Fix authentication bug' },
  action: {
    type: 'git.commit',
    repository: 'https://github.com/ageprotocol/demo',
    commit: COMMIT,
    files_changed: 3,
    insertions: 214,
    deletions: 38,
    tests: 'passed',
  },
  inputs: [{ kind: 'prompt', digest: `sha256:${'aa'.repeat(32)}` }],
  outputs: [{ kind: 'commit', digest: `sha256:${'bb'.repeat(32)}`, ref: COMMIT }],
  environment: { runtime: 'claude-code/2.1.0', workspace: 'github.com/ageprotocol/demo', digest: `sha256:${'cc'.repeat(32)}` },
  policy: { id: 'default', version: '1', hash: `sha256:${'dd'.repeat(32)}`, decision: 'allowed' },
};

const signed = agentSign(core, AGENT_PRIVATE);
const receipt = registrySign(signed, { sequence: 184, registered_at: '2026-09-05T03:20:04Z', jwks: JWKS_URL }, REGISTRY_PRIVATE);
const registryEntry = registrySignatureOf(receipt);
if (!registryEntry) throw new Error('golden receipt has no registry signature');
const attestation = attestationOf(receipt, registryEntry);
const root = buildRoot([receipt], '2026-09-05', REGISTRY_PRIVATE);
const proof = proofFor([receipt], receipt, REGISTRY_ID);

const golden = {
  note: 'Golden interop vector for AGE Protocol v0.1. Fixed keys, fixed content, byte-identical output. Ed25519 is deterministic, so a conforming implementation reproduces every id and signature here.',
  versions: { receipt: RECEIPT_VERSION, attestation: ATTESTATION_VERSION, root: ROOT_VERSION },
  keys: {
    agent_private: AGENT_PRIVATE,
    agent_public: AGENT_PUBLIC,
    agent_id: AGENT_ID,
    registry_private: REGISTRY_PRIVATE,
    registry_public: REGISTRY_PUBLIC,
    registry_id: REGISTRY_ID,
  },
  core,
  agent_signing_input: canonicalize(core),
  signed,
  assignment: { sequence: 184, registered_at: '2026-09-05T03:20:04Z', jwks: JWKS_URL },
  attestation,
  registry_signing_input: canonicalize(attestation),
  receipt,
  root: {
    document: root,
    signing_input: Buffer.from(rootSigningInput(root)).toString('utf8'),
    leaves: [Buffer.from(canonicalBytes(receipt)).toString('utf8')],
  },
  proof,
};

const here = import.meta.dirname;
const repository = join(here, '..', '..', '..', '..');
const text = `${JSON.stringify(golden, null, 2)}\n`;
for (const target of [join(here, 'golden.json'), join(repository, 'docs', 'protocol', 'golden-v0.1.json')]) {
  writeFileSync(target, text);
  process.stdout.write(`wrote ${target}\n`);
}
