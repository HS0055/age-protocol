import { receiptHash, type Receipt } from './receipt.ts';

export interface VerifyChainResult {
  ok: boolean;
  length: number;
  errors: string[];
}

export function verifyChain(receipts: Receipt[]): VerifyChainResult {
  const errors: string[] = [];
  if (receipts.length === 0) return { ok: true, length: 0, errors };

  const first = receipts[0] as Receipt;
  if (first.prev !== null) errors.push('first receipt must have prev null');

  for (let i = 1; i < receipts.length; i += 1) {
    const previous = receipts[i - 1] as Receipt;
    const current = receipts[i] as Receipt;
    const expected = receiptHash(previous);
    if (current.prev !== expected) errors.push(`receipt ${i} prev does not match hash of receipt ${i - 1}`);
    if (!(current.seq > previous.seq)) errors.push(`receipt ${i} seq ${current.seq} is not greater than ${previous.seq}`);
    if (current.mission !== first.mission) errors.push(`receipt ${i} mission differs from the chain mission`);
  }

  return { ok: errors.length === 0, length: receipts.length, errors };
}
