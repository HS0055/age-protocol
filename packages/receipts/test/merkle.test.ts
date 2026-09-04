import { test } from 'node:test';
import assert from 'node:assert/strict';
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
