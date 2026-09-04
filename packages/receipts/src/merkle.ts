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

// RFC 9162 section 2.1.3.2.
export function verifyInclusion(leafData: Uint8Array, proof: InclusionProof, rootHex: string): boolean {
  if (!Number.isInteger(proof.index) || proof.index < 0 || proof.index >= proof.size) return false;
  let fn = proof.index;
  let sn = proof.size - 1;
  let r: Buffer = leafHash(leafData);
  for (const entry of proof.path) {
    if (sn === 0) return false;
    const p = Buffer.from(entry, 'hex');
    if (p.length !== 32) return false;
    if ((fn & 1) === 1 || fn === sn) {
      r = nodeHash(p, r);
      if ((fn & 1) === 0) {
        while ((fn & 1) === 0 && fn !== 0) {
          fn >>>= 1;
          sn >>>= 1;
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn >>>= 1;
    sn >>>= 1;
  }
  return sn === 0 && r.toString('hex') === rootHex.toLowerCase();
}
