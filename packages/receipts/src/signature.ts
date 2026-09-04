import { sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { privateKeyFromJwk, publicKeyFromJwk, type PrivateJwk, type PublicJwk } from './keys.ts';

export function signBytes(data: Uint8Array, privateJwk: PrivateJwk): string {
  return Buffer.from(cryptoSign(null, data, privateKeyFromJwk(privateJwk))).toString('base64url');
}

// An Ed25519 signature is 64 bytes, which is exactly 86 base64url characters
// with no padding. Buffer.from would also swallow standard base64, padding,
// and trailing garbage, so one encoding is accepted and no other.
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;

export function verifyBytes(data: Uint8Array, signature: string, publicJwk: PublicJwk): boolean {
  try {
    if (typeof signature !== 'string' || !SIGNATURE_PATTERN.test(signature)) return false;
    const raw = Buffer.from(signature, 'base64url');
    if (raw.length !== 64) return false;
    return cryptoVerify(null, data, publicKeyFromJwk(publicJwk), raw);
  } catch {
    return false;
  }
}
