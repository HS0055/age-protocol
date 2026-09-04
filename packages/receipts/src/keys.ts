import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { canonicalize } from './canonical.ts';

export interface PublicJwk {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  kid?: string;
}

export interface PrivateJwk extends PublicJwk {
  d: string;
}

// RFC 7638: SHA-256 over the canonical JSON of the required members only.
export function thumbprint(jwk: PublicJwk): string {
  const canonical = canonicalize({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  return createHash('sha256').update(canonical).digest('base64url');
}

export function withKid(jwk: PublicJwk): PublicJwk {
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, kid: thumbprint(jwk) };
}

export function toPublicJwk(jwk: PrivateJwk): PublicJwk {
  return withKid({ kty: jwk.kty, crv: jwk.crv, x: jwk.x });
}

export function generateKeyPair(): { publicJwk: PublicJwk; privateJwk: PrivateJwk } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const exported = privateKey.export({ format: 'jwk' }) as { kty: string; crv: string; x: string; d: string };
  const privateJwk: PrivateJwk = { kty: 'OKP', crv: 'Ed25519', x: exported.x, d: exported.d };
  const publicJwk = withKid({ kty: 'OKP', crv: 'Ed25519', x: exported.x });
  void publicKey;
  return { publicJwk, privateJwk };
}

export function publicKeyFromJwk(jwk: PublicJwk): KeyObject {
  return createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x }, format: 'jwk' });
}

export function privateKeyFromJwk(jwk: PrivateJwk): KeyObject {
  return createPrivateKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, d: jwk.d }, format: 'jwk' });
}
