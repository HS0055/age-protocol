import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalize, canonicalBytes } from '../src/index.ts';

test('sorts object keys recursively and removes whitespace', () => {
  const out = canonicalize({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: 'x' } });
  assert.equal(out, '{"a":{"c":"x","d":[3,{"y":2,"z":1}]},"b":1}');
});

test('keeps array order', () => {
  assert.equal(canonicalize([3, 1, 2]), '[3,1,2]');
});

test('drops undefined properties and keeps null', () => {
  assert.equal(canonicalize({ a: undefined, b: null }), '{"b":null}');
});

test('serializes numbers the ES way', () => {
  assert.equal(canonicalize({ n: 1e21, m: 0.1, k: 100 }), '{"k":100,"m":0.1,"n":1e+21}');
});

test('rejects non-finite numbers', () => {
  assert.throws(() => canonicalize({ n: Number.NaN }), /non-finite/);
  assert.throws(() => canonicalize({ n: Number.POSITIVE_INFINITY }), /non-finite/);
});

test('sorts keys by UTF-16 code units', () => {
  assert.equal(canonicalize({ 'é': 1, e: 2, E: 3 }), '{"E":3,"e":2,"é":1}');
});

test('canonicalBytes is UTF-8 of canonicalize', () => {
  const bytes = canonicalBytes({ s: 'hé' });
  assert.equal(Buffer.from(bytes).toString('utf8'), '{"s":"hé"}');
});
