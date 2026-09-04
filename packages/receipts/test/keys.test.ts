import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, thumbprint, withKid, toPublicJwk, publicKeyFromJwk, privateKeyFromJwk, keyMapFromJwks, isPublicJwk } from '../src/index.ts';

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

test('keyMapFromJwks indexes by thumbprint and ignores the kid label', () => {
  const { publicJwk } = generateKeyPair();
  const mislabelled = { ...publicJwk, kid: 'not-the-thumbprint' };
  const map = keyMapFromJwks([mislabelled]);
  assert.equal(map.get(thumbprint(publicJwk))?.x, publicJwk.x);
  assert.equal(map.get('not-the-thumbprint'), undefined);
});

test('keyMapFromJwks skips entries that are not public JWKs', () => {
  const { publicJwk } = generateKeyPair();
  const junk = [null, 'x', 42, {}, { kty: 'OKP', crv: 'Ed25519' }, publicJwk];
  const map = keyMapFromJwks(junk as never);
  assert.equal(map.size, 1);
  assert.equal(map.has(thumbprint(publicJwk)), true);
});

test('isPublicJwk accepts a public JWK and rejects anything else', () => {
  const { publicJwk } = generateKeyPair();
  assert.equal(isPublicJwk(publicJwk), true);
  for (const value of [null, undefined, 'x', 42, [], {}, { kty: 'OKP', crv: 'Ed25519', x: 1 }]) {
    assert.equal(isPublicJwk(value), false);
  }
});
