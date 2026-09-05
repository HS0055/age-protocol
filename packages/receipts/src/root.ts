import { canonicalBytes } from './canonical.ts';
import { bareJwk, keyMapFromJwks, toPublicJwk, type PrivateJwk, type PublicJwk } from './keys.ts';
import { inclusionProof, merkleRoot, verifyInclusion, type InclusionProof } from './merkle.ts';
import { DIGEST_PREFIX, REGISTRY_ID_PREFIX, registryIdOf, registrySignatureFor, registrySignatureOf, thumbprintOfId, type Receipt } from './receipt.ts';
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

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// Like the merkle layer below it, this layer answers false for anything it
// cannot make sense of. A verifier handed a hostile file reports a verdict,
// never an exception.
export function verifyRoot(doc: RootDocument, keys: PublicJwk[] | Map<string, PublicJwk>): boolean {
  const value = doc as unknown;
  if (!isObject(value)) return false;
  if (value.root_version !== ROOT_VERSION || typeof value.signature !== 'string') return false;
  const map = keys instanceof Map ? keys : keyMapFromJwks(keys as PublicJwk[]);
  const jkt = typeof value.registry === 'string' ? thumbprintOfId(value.registry, REGISTRY_ID_PREFIX) : undefined;
  const key = jkt === undefined ? undefined : map.get(jkt);
  if (!key) return false;
  try {
    return verifyBytes(rootSigningInput(doc), value.signature, key);
  } catch {
    return false;
  }
}

export function verifyRootInclusion(receipt: Receipt, proof: RootProof, doc: RootDocument): boolean {
  const document = doc as unknown;
  const claim = proof as unknown;
  if (!isObject(document) || !isObject(claim) || !isObject(receipt as unknown)) return false;
  if (typeof document.root !== 'string' || !document.root.startsWith(DIGEST_PREFIX)) return false;
  if (typeof document.registry !== 'string') return false;
  if (!Number.isInteger(document.sequence_start) || !Number.isInteger(document.sequence_end)) return false;
  const start = document.sequence_start as number;
  const entry = registrySignatureFor(receipt, document.registry);
  if (!entry || !Number.isInteger(claim.sequence) || entry.sequence !== claim.sequence) return false;
  if (claim.size !== (document.sequence_end as number) - start + 1) return false;
  if (claim.index !== (claim.sequence as number) - start) return false;
  try {
    return verifyInclusion(canonicalBytes(receipt), proof, document.root.slice(DIGEST_PREFIX.length));
  } catch {
    return false;
  }
}
