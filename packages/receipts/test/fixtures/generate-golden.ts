// Regenerates the golden interop vector for AGE Protocol v0.1. Run from the
// repository root:
//   node packages/receipts/test/fixtures/generate-golden.ts
// It writes packages/receipts/test/fixtures/golden.json and the published copy
// docs/protocol/golden-v0.1.json. Only run it when the format changes on
// purpose: golden.test.ts recomputes every value here from the same inputs.
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  agentSign, registrySign, buildRoot, proofFor, attestationOf, registrySignatureOf, canonicalize,
  agentIdOf, registryIdOf, toPublicJwk, bareJwk, rootSigningInput, rootLeaves,
  RECEIPT_VERSION, ATTESTATION_VERSION, ROOT_VERSION,
  type PrivateJwk, type ReceiptCore, type RegistryAssignment,
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
const DATE = '2026-09-05';

// RFC 8785 orders members by UTF-16 code unit, not by code point. A
// supplementary-plane key is a surrogate pair beginning at U+D800, so it
// sorts before U+FFFF even though its code point is far larger. An
// implementation that sorts by code point puts these two the other way round
// and reproduces neither the receipt id nor the agent signature. Both keys
// are built from code points so that no escape in this source can be
// mistranscribed into something else.
const TOOLCHAIN_KEY = String.fromCodePoint(0x1f527);
const SENTINEL_KEY = String.fromCodePoint(0xffff);

// An integral value that arrived as a float. ES6 number serialization, which
// RFC 8785 requires, writes it as 1 and never as 1.0.
const INTEGRAL_FROM_FLOAT = 3 / 3;
// Past the safe integer range, where ES6 switches to exponential form. It is
// written 1e+21, not 1000000000000000000000 and not 1.0e+21.
const BEYOND_SAFE_INTEGERS = 1e21;

const cores: ReceiptCore[] = [
  {
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
  },
  {
    receipt_version: RECEIPT_VERSION,
    agent: AGENT_ID,
    timestamp: '2026-09-05T03:41:08Z',
    task: { id: 'tsk_92', description: 'Run the release test suite' },
    action: { type: 'test.run', suite: 'release', passed: 412, failed: 0 },
    inputs: [{ kind: 'commit', digest: `sha256:${'bb'.repeat(32)}`, ref: COMMIT }],
    outputs: [{ kind: 'report', digest: `sha256:${'ee'.repeat(32)}` }],
    // The member order written here is not the canonical one on purpose.
    environment: {
      [SENTINEL_KEY]: 'canonicalization sentinel',
      runtime: 'claude-code/2.1.0',
      [TOOLCHAIN_KEY]: 'cargo 1.89.0',
      digest: `sha256:${'cc'.repeat(32)}`,
    },
    policy: null,
  },
  {
    receipt_version: RECEIPT_VERSION,
    agent: AGENT_ID,
    timestamp: '2026-09-05T04:02:51Z',
    task: { id: 'tsk_93', description: 'Benchmark the canonicalizer' },
    action: {
      type: 'benchmark.run',
      suite: 'canonicalization',
      regressions: INTEGRAL_FROM_FLOAT,
      operations: BEYOND_SAFE_INTEGERS,
      seconds: 0.5,
    },
    inputs: [{ kind: 'commit', digest: `sha256:${'bb'.repeat(32)}`, ref: COMMIT }],
    outputs: [{ kind: 'report', digest: `sha256:${'ff'.repeat(32)}` }],
    environment: { runtime: 'claude-code/2.1.0', digest: `sha256:${'cc'.repeat(32)}` },
    policy: null,
  },
];

const assignments: RegistryAssignment[] = [
  { sequence: 184, registered_at: '2026-09-05T03:20:04Z', jwks: JWKS_URL },
  { sequence: 185, registered_at: '2026-09-05T03:41:12Z', jwks: JWKS_URL },
  { sequence: 186, registered_at: '2026-09-05T04:02:57Z', jwks: JWKS_URL },
];

const registered = cores.map((core, i) => {
  const signed = agentSign(core, AGENT_PRIVATE);
  const assignment = assignments[i] as RegistryAssignment;
  const receipt = registrySign(signed, assignment, REGISTRY_PRIVATE);
  const entry = registrySignatureOf(receipt);
  if (!entry) throw new Error(`golden receipt ${i} has no registry signature`);
  const attestation = attestationOf(receipt, entry);
  return {
    core,
    agent_signing_input: canonicalize(core),
    signed,
    assignment,
    attestation,
    registry_signing_input: canonicalize(attestation),
    receipt,
  };
});

const receipts = registered.map((item) => item.receipt);
const root = buildRoot(receipts, DATE, REGISTRY_PRIVATE);

const golden = {
  note: [
    'Golden interop vector for AGE Protocol v0.1. Fixed keys, fixed content, byte-identical output.',
    'Ed25519 is deterministic, so a conforming implementation reproduces every id and signature here.',
    'Three registered receipts at sequences 184, 185, and 186 form a three-leaf Merkle tree, so every',
    'inclusion proof has a non-empty path and one of them carries an internal node hash: an',
    'implementation that omits the RFC 6962 domain prefixes cannot reproduce them.',
    'Receipt 185 carries an environment with a supplementary-plane key and a U+FFFF key, which RFC 8785',
    'orders by UTF-16 code unit: the supplementary-plane key comes first. Receipt 186 carries an',
    'integral number that must be written 1 rather than 1.0, and one beyond the safe integer range that',
    'must be written 1e+21.',
  ].join(' '),
  versions: { receipt: RECEIPT_VERSION, attestation: ATTESTATION_VERSION, root: ROOT_VERSION },
  keys: {
    agent_private: AGENT_PRIVATE,
    agent_public: AGENT_PUBLIC,
    agent_id: AGENT_ID,
    registry_private: REGISTRY_PRIVATE,
    registry_public: REGISTRY_PUBLIC,
    registry_id: REGISTRY_ID,
  },
  receipts: registered.map((item) => ({ ...item, proof: proofFor(receipts, item.receipt, REGISTRY_ID) })),
  root: {
    document: root,
    signing_input: Buffer.from(rootSigningInput(root)).toString('utf8'),
    leaves: rootLeaves(receipts, REGISTRY_ID).map((leaf) => Buffer.from(leaf).toString('utf8')),
  },
};

const here = import.meta.dirname;
const repository = join(here, '..', '..', '..', '..');
const text = `${JSON.stringify(golden, null, 2)}\n`;
for (const target of [join(here, 'golden.json'), join(repository, 'docs', 'protocol', 'golden-v0.1.json')]) {
  writeFileSync(target, text);
  process.stdout.write(`wrote ${target}\n`);
}
