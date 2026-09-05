import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { leafHash, merkleRoot, inclusionProof, verifyInclusion, type InclusionProof } from '../src/index.ts';

const enc = (s: string) => new TextEncoder().encode(s);
const hex = (b: Buffer) => b.toString('hex');

test('empty tree root is SHA-256 of nothing', () => {
  assert.equal(hex(merkleRoot([])), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

test('leaf hash of empty input matches the CT test vector', () => {
  assert.equal(hex(leafHash(new Uint8Array())), '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d');
});

test('single leaf root equals its leaf hash', () => {
  assert.equal(hex(merkleRoot([enc('a')])), '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c');
});

test('two and three leaf roots', () => {
  assert.equal(hex(merkleRoot([enc('a'), enc('b')])), 'b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb');
  assert.equal(hex(merkleRoot([enc('a'), enc('b'), enc('c')])), '36642e73c2540ab121e3a6bf9545b0a24982cd830eb13d3cd19de3ce6c021ec1');
});

test('inclusion proofs verify for every index of trees of size 1 to 9', () => {
  for (let size = 1; size <= 9; size += 1) {
    const leaves = Array.from({ length: size }, (_, i) => enc(`leaf-${i}`));
    const root = hex(merkleRoot(leaves));
    for (let index = 0; index < size; index += 1) {
      const proof = inclusionProof(leaves, index);
      assert.equal(proof.size, size);
      assert.equal(proof.index, index);
      assert.equal(verifyInclusion(leaves[index] as Uint8Array, proof, root), true, `size ${size} index ${index}`);
    }
  }
});

test('three-leaf proof for the last leaf is the hash of the first two', () => {
  const leaves = [enc('a'), enc('b'), enc('c')];
  assert.deepEqual(inclusionProof(leaves, 2).path, ['b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb']);
});

test('inclusion fails for wrong leaf, wrong root, or wrong index', () => {
  const leaves = [enc('a'), enc('b'), enc('c'), enc('d')];
  const root = hex(merkleRoot(leaves));
  const proof = inclusionProof(leaves, 1);
  assert.equal(verifyInclusion(enc('x'), proof, root), false);
  assert.equal(verifyInclusion(enc('b'), proof, 'ff'.repeat(32)), false);
  assert.equal(verifyInclusion(enc('b'), { ...proof, index: 2 }, root), false);
  assert.equal(verifyInclusion(enc('b'), { ...proof, index: 9 }, root), false);
});

test('inclusionProof rejects an out-of-range index', () => {
  assert.throws(() => inclusionProof([enc('a')], 1), /out of range/);
});

test('verifyInclusion rejects a malformed path instead of throwing', () => {
  const leaves = [enc('a'), enc('b')];
  const root = hex(merkleRoot(leaves));
  const proof = inclusionProof(leaves, 0);
  const withPath = (path: unknown) => ({ ...proof, path }) as unknown as InclusionProof;
  for (const path of [5, undefined, null, 'abc', [1], [null], [['x']], ['zz'.repeat(32)], ['abcd']]) {
    assert.equal(verifyInclusion(enc('a'), withPath(path), root), false, `path ${JSON.stringify(path)}`);
  }
});

// A tree larger than 2**32 leaves. JavaScript's >>> and & coerce to 32 bits,
// so sn truncated to a small number partway up the walk and correct proofs
// were rejected. A release review found 136 such cases in an honest sweep;
// none of them is reachable by building an actual tree, so the expected root
// is computed here by an independent BigInt walk of RFC 9162 section 2.1.3.2.
test('inclusion holds for trees larger than 2^32 leaves', () => {
  const node = (l: Buffer, r: Buffer) =>
    createHash('sha256').update(Buffer.concat([Buffer.from([1]), l, r])).digest();

  const expectedRoot = (leaf: Uint8Array, path: string[], index: number, size: number) => {
    let fn = BigInt(index);
    let sn = BigInt(size) - 1n;
    let r = leafHash(leaf);
    for (const entry of path) {
      if (sn === 0n) return undefined;
      const p = Buffer.from(entry, 'hex');
      if (fn % 2n === 1n || fn === sn) {
        r = node(p, r);
        if (fn % 2n === 0n) {
          while (fn % 2n === 0n && fn !== 0n) { fn /= 2n; sn /= 2n; }
        }
      } else {
        r = node(r, p);
      }
      fn /= 2n;
      sn /= 2n;
    }
    return sn === 0n ? r.toString('hex') : undefined;
  };

  const leaf = Buffer.from('a receipt in a very large day');
  // 2^32 was already fine because sn is then 2^32 - 1 and still fits; 2^32 + 1
  // is the first size that truncated. 2^53 is the largest the format allows.
  for (const size of [2 ** 32, 2 ** 32 + 1, 2 ** 40, 2 ** 52, 2 ** 53 - 1]) {
    const depth = Math.ceil(Math.log2(size));
    const path = Array.from({ length: depth }, (_, i) =>
      createHash('sha256').update(`sibling ${i}`).digest().toString('hex'));
    const root = expectedRoot(leaf, path, 4, size);
    assert.ok(root, `the oracle produced a root for size ${size}`);
    assert.equal(verifyInclusion(leaf, { index: 4, size, path }, root), true,
      `a correct proof in a tree of ${size} leaves must verify`);
  }

  // A size beyond the safe integer range is not a size.
  assert.equal(verifyInclusion(leaf, { index: 0, size: 2 ** 53 + 2, path: [] }, 'a'.repeat(64)), false);
});
