import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateKeyPair, nodeSign, cloudSign, receiptHash, verifyReceipt, thumbprint,
  type ReceiptBody, type Receipt,
} from '../src/index.ts';

const node = generateKeyPair();
const cloud = generateKeyPair();
const stranger = generateKeyPair();

function body(overrides: Partial<ReceiptBody> = {}): ReceiptBody {
  return {
    v: 1,
    id: 'rcpt_01J8TEST0000000000000001',
    ts: '2026-09-04T14:02:11Z',
    seq: 1207,
    company: 'org_sayge',
    mission: 'msn_482',
    task: 'tsk_91',
    run: 'run_7',
    actor: { type: 'agent', jkt: 'agentjkt', level: 0 },
    node: { jkt: thumbprint(node.publicJwk) },
    cloud: { jkt: thumbprint(cloud.publicJwk) },
    action: { type: 'git.commit', ref: 'abc123', files: 3 },
    inputs: [{ kind: 'prompt_bundle', sha256: 'aa'.repeat(32) }],
    outputs: [{ kind: 'diff', sha256: 'bb'.repeat(32) }],
    gate: null,
    prev: null,
    ...overrides,
  };
}

test('node then cloud signatures verify', () => {
  const r = cloudSign(nodeSign(body(), node.privateJwk), cloud.privateJwk);
  const result = verifyReceipt(r, [node.publicJwk, cloud.publicJwk]);
  assert.deepEqual(result, { ok: true, node: 'valid', cloud: 'valid', errors: [] });
});

test('cloud-only receipt has null node and null node_sig', () => {
  const r = cloudSign(body({ node: null, actor: { type: 'human', id: 'usr_hayk' } }), cloud.privateJwk);
  assert.equal(r.node_sig, null);
  const result = verifyReceipt(r, [cloud.publicJwk]);
  assert.deepEqual(result, { ok: true, node: 'absent', cloud: 'valid', errors: [] });
});

test('tampering with the action breaks both signatures', () => {
  const r = cloudSign(nodeSign(body(), node.privateJwk), cloud.privateJwk);
  const tampered: Receipt = { ...r, action: { type: 'git.commit', ref: 'evil', files: 3 } };
  const result = verifyReceipt(tampered, [node.publicJwk, cloud.publicJwk]);
  assert.equal(result.ok, false);
  assert.equal(result.node, 'invalid');
  assert.equal(result.cloud, 'invalid');
});

test('a node signature from a stranger is rejected even if the cloud signed it', () => {
  const r = cloudSign(nodeSign(body(), stranger.privateJwk), cloud.privateJwk);
  const result = verifyReceipt(r, [node.publicJwk, cloud.publicJwk]);
  assert.equal(result.ok, false);
  assert.equal(result.node, 'invalid');
  assert.equal(result.cloud, 'valid');
});

test('unknown keys are reported, not guessed', () => {
  const r = cloudSign(nodeSign(body(), node.privateJwk), cloud.privateJwk);
  const result = verifyReceipt(r, [cloud.publicJwk]);
  assert.equal(result.ok, false);
  assert.equal(result.node, 'unknown_key');
  assert.match(result.errors[0] ?? '', /node key/);
});

test('a node present without node_sig is invalid', () => {
  const r = cloudSign(body(), cloud.privateJwk);
  const result = verifyReceipt(r, [node.publicJwk, cloud.publicJwk]);
  assert.equal(result.ok, false);
  assert.equal(result.node, 'invalid');
});

test('receiptHash is stable and changes with any field', () => {
  const r = cloudSign(nodeSign(body(), node.privateJwk), cloud.privateJwk);
  const h1 = receiptHash(r);
  assert.match(h1, /^[0-9a-f]{64}$/);
  assert.equal(receiptHash({ ...r }), h1);
  assert.notEqual(receiptHash({ ...r, seq: 1208 }), h1);
});
