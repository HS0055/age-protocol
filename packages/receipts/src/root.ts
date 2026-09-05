import { canonicalBytes } from './canonical.ts';
import { bareJwk, keyMapFromJwks, toPublicJwk, type PrivateJwk, type PublicJwk } from './keys.ts';
import { inclusionProof, merkleRoot, verifyInclusion, type InclusionProof } from './merkle.ts';
import { DIGEST_PREFIX, REGISTRY_ID_PREFIX, registryIdOf, registrySignatureOf, thumbprintOfId, type Receipt } from './receipt.ts';
import { signBytes, verifyBytes } from './signature.ts';

export const ROOT_VERSION = '0.1';

// A day's registered receipts, in sequence order, under one signed Merkle
// root. Publishing these lets anyone later witness that the registry has not
// rewritten its history; the root alone does not make history immutable.
export interface RootDocument {
  root_version: typeof ROOT_VERSION;
  registry: string;
  date: string;
  sequence_start: number;
  sequence_end: number;
  root: string;
  signature: string;
}

export interface RootProof extends InclusionProof {
  sequence: number;
}

export function sequenceOf(receipt: Receipt): number {
  const entry = registrySignatureOf(receipt);
  if (!entry) throw new Error('receipt is not registered');
  return entry.sequence;
}

function bySequence(receipts: Receipt[]): Receipt[] {
  return [...receipts].sort((a, b) => sequenceOf(a) - sequenceOf(b));
}

export function rootLeaves(receipts: Receipt[]): Uint8Array[] {
  return bySequence(receipts).map((receipt) => canonicalBytes(receipt));
}

export function rootSigningInput(doc: Omit<RootDocument, 'signature'> | RootDocument): Uint8Array {
  const { signature, ...rest } = doc as RootDocument;
  return canonicalBytes(rest);
}

export function buildRoot(receipts: Receipt[], date: string, registryPrivate: PrivateJwk): RootDocument {
  if (receipts.length === 0) throw new Error('buildRoot: no receipts');
  const ordered = bySequence(receipts);
  const leaves = ordered.map((receipt) => canonicalBytes(receipt));
  const unsigned = {
    root_version: ROOT_VERSION,
    registry: registryIdOf(bareJwk(toPublicJwk(registryPrivate))),
    date,
    sequence_start: sequenceOf(ordered[0] as Receipt),
    sequence_end: sequenceOf(ordered[ordered.length - 1] as Receipt),
    root: `${DIGEST_PREFIX}${merkleRoot(leaves).toString('hex')}`,
  } satisfies Omit<RootDocument, 'signature'>;
  return { ...unsigned, signature: signBytes(canonicalBytes(unsigned), registryPrivate) };
}

export function proofFor(receipts: Receipt[], receipt: Receipt): RootProof {
  const ordered = bySequence(receipts);
  const index = ordered.findIndex((candidate) => candidate.id === receipt.id);
  if (index < 0) throw new Error('proofFor: receipt is not among the root leaves');
  const leaves = ordered.map((candidate) => canonicalBytes(candidate));
  return { sequence: sequenceOf(receipt), ...inclusionProof(leaves, index) };
}

export function verifyRoot(doc: RootDocument, keys: PublicJwk[] | Map<string, PublicJwk>): boolean {
  if (doc.root_version !== ROOT_VERSION) return false;
  const map = keys instanceof Map ? keys : keyMapFromJwks(keys);
  const jkt = thumbprintOfId(doc.registry, REGISTRY_ID_PREFIX);
  const key = jkt === undefined ? undefined : map.get(jkt);
  if (!key || typeof doc.signature !== 'string') return false;
  return verifyBytes(rootSigningInput(doc), doc.signature, key);
}

export function verifyRootInclusion(receipt: Receipt, proof: RootProof, doc: RootDocument): boolean {
  if (typeof doc.root !== 'string' || !doc.root.startsWith(DIGEST_PREFIX)) return false;
  const entry = registrySignatureOf(receipt);
  if (!entry || entry.sequence !== proof.sequence) return false;
  const size = doc.sequence_end - doc.sequence_start + 1;
  if (proof.size !== size || proof.index !== proof.sequence - doc.sequence_start) return false;
  return verifyInclusion(canonicalBytes(receipt), proof, doc.root.slice(DIGEST_PREFIX.length));
}
