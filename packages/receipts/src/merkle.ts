import { createHash } from 'node:crypto';

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

function sha256(...parts: Uint8Array[]): Buffer {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return hash.digest();
}

export function leafHash(data: Uint8Array): Buffer {
  return sha256(LEAF_PREFIX, data);
}

function nodeHash(left: Uint8Array, right: Uint8Array): Buffer {
  return sha256(NODE_PREFIX, left, right);
}

// Largest power of two strictly less than n, for n >= 2.
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function rootOf(hashes: Buffer[]): Buffer {
  if (hashes.length === 0) return sha256();
  if (hashes.length === 1) return hashes[0] as Buffer;
  const k = splitPoint(hashes.length);
  return nodeHash(rootOf(hashes.slice(0, k)), rootOf(hashes.slice(k)));
}

export function merkleRoot(leaves: Uint8Array[]): Buffer {
  return rootOf(leaves.map(leafHash));
}

export interface InclusionProof {
  index: number;
  size: number;
  path: string[];
}

function pathOf(hashes: Buffer[], index: number): Buffer[] {
  if (hashes.length <= 1) return [];
  const k = splitPoint(hashes.length);
  if (index < k) return [...pathOf(hashes.slice(0, k), index), rootOf(hashes.slice(k))];
  return [...pathOf(hashes.slice(k), index - k), rootOf(hashes.slice(0, k))];
}

export function inclusionProof(leaves: Uint8Array[], index: number): InclusionProof {
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) {
    throw new RangeError(`inclusionProof: index ${index} out of range for ${leaves.length} leaves`);
  }
  const path = pathOf(leaves.map(leafHash), index).map((h) => h.toString('hex'));
  return { index, size: leaves.length, path };
}

// Lowercase only. Accepting both cases would mean two spellings of one proof,
// and an implementation that emits uppercase would interoperate here and
// nowhere else.
const HEX_32_BYTES = /^[0-9a-f]{64}$/;

// RFC 9162 section 2.1.3.2. A malformed proof is a false, never an exception.
//
// The walk uses division and remainder rather than the bitwise operators the
// RFC's pseudocode implies. JavaScript's >>> and & coerce to 32 bits, so a
// tree with more than 2**32 leaves made sn truncate to a small number and the
// walk was abandoned partway, rejecting proofs that are correct. Arithmetic
// is exact to 2**53, which is the range the format allows anyway.
export function verifyInclusion(leafData: Uint8Array, proof: InclusionProof, rootHex: string): boolean {
  if (!Number.isSafeInteger(proof.size) || proof.size < 1) return false;
  if (!Number.isSafeInteger(proof.index) || proof.index < 0 || proof.index >= proof.size) return false;
  if (!Array.isArray(proof.path)) return false;
  const isRight = (n: number) => n % 2 === 1;
  const up = (n: number) => Math.floor(n / 2);
  let fn = proof.index;
  let sn = proof.size - 1;
  let r: Buffer = leafHash(leafData);
  for (const entry of proof.path) {
    if (sn === 0) return false;
    if (typeof entry !== 'string' || !HEX_32_BYTES.test(entry)) return false;
    const p = Buffer.from(entry, 'hex');
    if (isRight(fn) || fn === sn) {
      r = nodeHash(p, r);
      if (!isRight(fn)) {
        while (!isRight(fn) && fn !== 0) {
          fn = up(fn);
          sn = up(sn);
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn = up(fn);
    sn = up(sn);
  }
  return sn === 0 && r.toString('hex') === rootHex.toLowerCase();
}
