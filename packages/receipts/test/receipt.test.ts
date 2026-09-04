import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateKeyPair, nodeSign, cloudSign, receiptHash, verifyReceipt, thumbprint,
  nodeSigningInput, cloudSigningInput, RECEIPT_TYP,
  type ReceiptEnvelope, type Receipt,
} from '../src/index.ts';

const node = generateKeyPair();
const cloud = generateKeyPair();
const stranger = generateKeyPair();

function envelope(overrides: Partial<ReceiptEnvelope> = {}): ReceiptEnvelope {
  return {
    typ: RECEIPT_TYP,
    v: 1,
    ts: '2026-09-04T14:02:11Z',
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
    ...overrides,
  };
}

const assigned = { id: 'rcpt_01J8TEST0000000000000001', seq: 1207, prev: null };

function issue(overrides: Partial<ReceiptEnvelope> = {}): Receipt {
  return cloudSign(nodeSign(envelope(overrides), node.privateJwk), assigned, cloud.privateJwk);
}

test('node then cloud signatures verify', () => {
  const result = verifyReceipt(issue(), [node.publicJwk, cloud.publicJwk]);
  assert.deepEqual(result, { ok: true, node: 'valid', cloud: 'valid', errors: [] });
});

test('the node signing input excludes the cloud-assigned fields', () => {
  const signed = nodeSign(envelope(), node.privateJwk);
  const receipt = cloudSign(signed, assigned, cloud.privateJwk);
  assert.equal('id' in signed, false);
  assert.equal('seq' in signed, false);
  assert.equal('prev' in signed, false);
  assert.deepEqual(nodeSigningInput(receipt), nodeSigningInput(signed));
  const text = Buffer.from(nodeSigningInput(receipt)).toString('utf8');
  for (const member of ['"id"', '"seq"', '"prev"', 'node_sig', 'cloud_sig']) {
    assert.equal(text.includes(member), false, `${member} must not be in the node signing input`);
  }
});

test('the node signature survives the cloud assigning id, seq, and prev', () => {
  const signed = nodeSign(envelope(), node.privateJwk);
  const first = cloudSign(signed, { id: 'rcpt_a', seq: 1, prev: null }, cloud.privateJwk);
  const later = cloudSign(signed, { id: 'rcpt_b', seq: 9814, prev: 'cc'.repeat(32) }, cloud.privateJwk);
  assert.equal(first.node_sig, signed.node_sig);
  assert.equal(later.node_sig, signed.node_sig);
  assert.equal(verifyReceipt(first, [node.publicJwk, cloud.publicJwk]).node, 'valid');
  assert.equal(verifyReceipt(later, [node.publicJwk, cloud.publicJwk]).node, 'valid');
});

test('changing seq after cloud signing breaks only the cloud signature', () => {
  const tampered: Receipt = { ...issue(), seq: 1208 };
  const result = verifyReceipt(tampered, [node.publicJwk, cloud.publicJwk]);
  assert.equal(result.ok, false);
  assert.equal(result.node, 'valid');
  assert.equal(result.cloud, 'invalid');
});

test('changing prev after cloud signing breaks only the cloud signature', () => {
  const tampered: Receipt = { ...issue(), prev: 'dd'.repeat(32) };
  const result = verifyReceipt(tampered, [node.publicJwk, cloud.publicJwk]);
  assert.equal(result.node, 'valid');
  assert.equal(result.cloud, 'invalid');
});

test('tampering with the action breaks both signatures', () => {
  const tampered: Receipt = { ...issue(), action: { type: 'git.commit', ref: 'evil', files: 3 } };
  const result = verifyReceipt(tampered, [node.publicJwk, cloud.publicJwk]);
  assert.equal(result.ok, false);
  assert.equal(result.node, 'invalid');
  assert.equal(result.cloud, 'invalid');
});

test('the cloud signing input carries id, seq, prev, and node_sig', () => {
  const receipt = issue();
  const text = Buffer.from(cloudSigningInput(receipt)).toString('utf8');
  assert.equal(text.includes('"id":"rcpt_01J8TEST0000000000000001"'), true);
  assert.equal(text.includes('"seq":1207'), true);
  assert.equal(text.includes('"prev":null'), true);
  assert.equal(text.includes(`"node_sig":"${receipt.node_sig}"`), true);
  assert.equal(text.includes('cloud_sig'), false);
});

test('cloud-only receipt has null node and null node_sig', () => {
  const r = cloudSign(envelope({ node: null, actor: { type: 'human', id: 'usr_hayk' } }), assigned, cloud.privateJwk);
  assert.equal(r.node_sig, null);
  assert.deepEqual(verifyReceipt(r, [cloud.publicJwk]), { ok: true, node: 'absent', cloud: 'valid', errors: [] });
});

test('a node signature from a stranger is rejected even if the cloud signed it', () => {
  const r = cloudSign(nodeSign(envelope(), stranger.privateJwk), assigned, cloud.privateJwk);
  const result = verifyReceipt(r, [node.publicJwk, cloud.publicJwk]);
  assert.equal(result.ok, false);
  assert.equal(result.node, 'invalid');
  assert.equal(result.cloud, 'valid');
});

test('unknown keys are reported, not guessed', () => {
  const result = verifyReceipt(issue(), [cloud.publicJwk]);
  assert.equal(result.ok, false);
  assert.equal(result.node, 'unknown_key');
  assert.match(result.errors[0] ?? '', /node key/);
});

test('a node present without node_sig is invalid', () => {
  const r = cloudSign(envelope(), assigned, cloud.privateJwk);
  const result = verifyReceipt(r, [node.publicJwk, cloud.publicJwk]);
  assert.equal(result.ok, false);
  assert.equal(result.node, 'invalid');
});

test('nodeSign refuses an envelope without a node', () => {
  assert.throws(() => nodeSign(envelope({ node: null }), node.privateJwk), /no node/);
});

test('receiptHash is stable and changes with any field', () => {
  const r = issue();
  const h1 = receiptHash(r);
  assert.match(h1, /^[0-9a-f]{64}$/);
  assert.equal(receiptHash({ ...r }), h1);
  assert.notEqual(receiptHash({ ...r, seq: 1208 }), h1);
});

test('the typ is part of the node signing input', () => {
  const text = Buffer.from(nodeSigningInput(issue())).toString('utf8');
  assert.equal(text.includes('"typ":"agie/receipt/1"'), true);
});

test('signing helpers reject an envelope whose typ is wrong', () => {
  const wrong = { ...envelope(), typ: 'agie/root/1' } as unknown as ReceiptEnvelope;
  assert.throws(() => nodeSign(wrong, node.privateJwk), /typ/);
  assert.throws(() => cloudSign(wrong, assigned, cloud.privateJwk), /typ/);
  const missing = { ...envelope() } as Partial<ReceiptEnvelope>;
  delete missing.typ;
  assert.throws(() => nodeSign(missing as ReceiptEnvelope, node.privateJwk), /typ/);
});

test('verifyReceipt rejects a missing or unexpected typ', () => {
  const receipt = issue();
  const keys = [node.publicJwk, cloud.publicJwk];
  const missing = { ...receipt } as Partial<Receipt>;
  delete missing.typ;
  const withoutTyp = verifyReceipt(missing as Receipt, keys);
  assert.equal(withoutTyp.ok, false);
  assert.match(withoutTyp.errors[0] ?? '', /typ/);
  const wrongTyp = verifyReceipt({ ...receipt, typ: 'agie/receipt/2' } as unknown as Receipt, keys);
  assert.equal(wrongTyp.ok, false);
  assert.match(wrongTyp.errors[0] ?? '', /typ/);
});

test('a node may carry its own public jwk', () => {
  const receipt = cloudSign(
    nodeSign(envelope({ node: { jkt: thumbprint(node.publicJwk), jwk: node.publicJwk } }), node.privateJwk),
    assigned,
    cloud.privateJwk,
  );
  assert.deepEqual(receipt.node?.jwk, node.publicJwk);
  assert.deepEqual(verifyReceipt(receipt, [node.publicJwk, cloud.publicJwk]), { ok: true, node: 'valid', cloud: 'valid', errors: [] });
});
