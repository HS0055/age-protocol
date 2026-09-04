import { sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { privateKeyFromJwk, publicKeyFromJwk, type PrivateJwk, type PublicJwk } from './keys.ts';

export function signBytes(data: Uint8Array, privateJwk: PrivateJwk): string {
  return Buffer.from(cryptoSign(null, data, privateKeyFromJwk(privateJwk))).toString('base64url');
}

export function verifyBytes(data: Uint8Array, signature: string, publicJwk: PublicJwk): boolean {
  try {
    const raw = Buffer.from(signature, 'base64url');
    if (raw.length !== 64) return false;
    return cryptoVerify(null, data, publicKeyFromJwk(publicJwk), raw);
  } catch {
    return false;
  }
}
