import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, cloudSign, receiptHash, verifyChain, thumbprint, type ReceiptEnvelope, type Receipt } from '../src/index.ts';

const cloud = generateKeyPair();

function make(seq: number, prev: string | null, mission = 'msn_1'): Receipt {
  const envelope: ReceiptEnvelope = {
    v: 1, ts: '2026-09-04T00:00:00Z', company: 'org', mission, task: null, run: null,
    actor: { type: 'system' }, node: null, cloud: { jkt: thumbprint(cloud.publicJwk) },
    action: { type: 'mission.event' }, inputs: [], outputs: [], gate: null,
  };
  return cloudSign(envelope, { id: `rcpt_${seq}`, seq, prev }, cloud.privateJwk);
}

test('a well-formed chain verifies', () => {
  const a = make(1, null);
  const b = make(2, receiptHash(a));
  const c = make(3, receiptHash(b));
  assert.deepEqual(verifyChain([a, b, c]), { ok: true, length: 3, errors: [] });
});

test('an empty chain is ok with length 0', () => {
  assert.deepEqual(verifyChain([]), { ok: true, length: 0, errors: [] });
});

test('first receipt must have prev null', () => {
  const a = make(1, 'ff'.repeat(32));
  const result = verifyChain([a]);
  assert.equal(result.ok, false);
  assert.match(result.errors[0] ?? '', /first receipt/);
});

test('a broken link is reported with its position', () => {
  const a = make(1, null);
  const b = make(2, 'ff'.repeat(32));
  const result = verifyChain([a, b]);
  assert.equal(result.ok, false);
  assert.match(result.errors[0] ?? '', /receipt 1 prev/);
});

test('seq must strictly increase', () => {
  const a = make(5, null);
  const b = make(5, receiptHash(a));
  const result = verifyChain([a, b]);
  assert.equal(result.ok, false);
  assert.match(result.errors[0] ?? '', /seq/);
});

test('all receipts must share a mission', () => {
  const a = make(1, null, 'msn_1');
  const b = make(2, receiptHash(a), 'msn_2');
  const result = verifyChain([a, b]);
  assert.equal(result.ok, false);
  assert.match(result.errors[0] ?? '', /mission/);
});
