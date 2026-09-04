import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, signBytes, verifyBytes } from '../src/index.ts';

const data = new TextEncoder().encode('{"hello":"world"}');

test('signature verifies with the matching public key', () => {
  const { publicJwk, privateJwk } = generateKeyPair();
  const sig = signBytes(data, privateJwk);
  assert.equal(sig.length, 86);
  assert.equal(sig.includes('='), false);
  assert.equal(verifyBytes(data, sig, publicJwk), true);
});

test('signature fails for a different key', () => {
  const { privateJwk } = generateKeyPair();
  const other = generateKeyPair().publicJwk;
  assert.equal(verifyBytes(data, signBytes(data, privateJwk), other), false);
});

test('signature fails for tampered data', () => {
  const { publicJwk, privateJwk } = generateKeyPair();
  const sig = signBytes(data, privateJwk);
  assert.equal(verifyBytes(new TextEncoder().encode('{"hello":"world!"}'), sig, publicJwk), false);
});

test('verifyBytes returns false instead of throwing on garbage', () => {
  const { publicJwk } = generateKeyPair();
  assert.equal(verifyBytes(data, 'not-a-signature', publicJwk), false);
  assert.equal(verifyBytes(data, '', publicJwk), false);
});

test('verifyBytes accepts only unpadded base64url of the right length', () => {
  const { publicJwk, privateJwk } = generateKeyPair();
  const sig = signBytes(data, privateJwk);
  const standard = Buffer.from(sig, 'base64url').toString('base64');
  assert.equal(verifyBytes(data, sig, publicJwk), true);
  assert.equal(verifyBytes(data, `${sig}==`, publicJwk), false);
  assert.equal(verifyBytes(data, standard, publicJwk), false);
  assert.equal(verifyBytes(data, `${sig}trailing`, publicJwk), false);
  assert.equal(verifyBytes(data, sig.slice(0, 85), publicJwk), false);
});
