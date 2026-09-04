import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, thumbprint, withKid, toPublicJwk, publicKeyFromJwk, privateKeyFromJwk } from '../src/index.ts';

test('thumbprint matches the RFC 8037 A.3 vector', () => {
  const jwk = { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' } as const;
  assert.equal(thumbprint(jwk), 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k');
});

test('thumbprint ignores kid and other fields', () => {
  const jwk = { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo', kid: 'whatever' } as const;
  assert.equal(thumbprint(jwk), 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k');
});

test('generateKeyPair returns an Ed25519 pair whose public kid is its thumbprint', () => {
  const { publicJwk, privateJwk } = generateKeyPair();
  assert.equal(publicJwk.kty, 'OKP');
  assert.equal(publicJwk.crv, 'Ed25519');
  assert.equal(publicJwk.x.length, 43);
  assert.equal(privateJwk.d.length, 43);
  assert.equal(publicJwk.kid, thumbprint(publicJwk));
  assert.equal(privateJwk.x, publicJwk.x);
});

test('toPublicJwk strips d and adds kid', () => {
  const { privateJwk } = generateKeyPair();
  const pub = toPublicJwk(privateJwk);
  assert.equal('d' in pub, false);
  assert.equal(pub.kid, thumbprint(pub));
});

test('withKid is idempotent', () => {
  const { publicJwk } = generateKeyPair();
  assert.deepEqual(withKid(withKid(publicJwk)), publicJwk);
});

test('key objects round-trip through node:crypto', () => {
  const { publicJwk, privateJwk } = generateKeyPair();
  assert.equal(publicKeyFromJwk(publicJwk).asymmetricKeyType, 'ed25519');
  assert.equal(privateKeyFromJwk(privateJwk).asymmetricKeyType, 'ed25519');
});
