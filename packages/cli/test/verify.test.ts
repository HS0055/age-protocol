import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateKeyPair, nodeSign, cloudSign, receiptHash, canonicalBytes, merkleRoot, inclusionProof, signBytes, thumbprint,
  RECEIPT_TYP, ROOT_TYP,
  type ReceiptEnvelope, type Receipt,
} from '@agie/receipts';
import { runVerify } from '../src/verify.ts';

const node = generateKeyPair();
const cloud = generateKeyPair();

function envelope(seq: number): ReceiptEnvelope {
  return {
    typ: RECEIPT_TYP, v: 1, ts: '2026-09-04T00:00:00Z', company: 'org', mission: 'msn_1', task: 'tsk_1', run: 'run_1',
    actor: { type: 'agent', jkt: 'agent', level: 0 }, node: { jkt: thumbprint(node.publicJwk) }, cloud: { jkt: thumbprint(cloud.publicJwk) },
    action: { type: 'git.commit' }, inputs: [], outputs: [], gate: null,
  };
}

function issue(seq: number, prev: string | null): Receipt {
  return cloudSign(nodeSign(envelope(seq), node.privateJwk), { id: `rcpt_${seq}`, seq, prev }, cloud.privateJwk);
}

const r1 = issue(1, null);
const r2 = issue(2, receiptHash(r1));
const leaves = [r1, r2].map((r) => canonicalBytes(r));
const rootHex = merkleRoot(leaves).toString('hex');
const rootDoc = { typ: ROOT_TYP, date: '2026-09-04', size: 2, root: rootHex, cloud: { jkt: thumbprint(cloud.publicJwk) }, sig: '' };
rootDoc.sig = signBytes(
  canonicalBytes({ typ: rootDoc.typ, date: rootDoc.date, size: rootDoc.size, root: rootDoc.root }),
  cloud.privateJwk,
);

function files(extra: Record<string, unknown> = {}) {
  const store: Record<string, string> = {
    'receipt.json': JSON.stringify(r2),
    'jwks.json': JSON.stringify({ keys: [node.publicJwk, cloud.publicJwk] }),
    'chain.json': JSON.stringify([r1, r2]),
    'root.json': JSON.stringify(rootDoc),
    'proof.json': JSON.stringify(inclusionProof(leaves, 1)),
    ...Object.fromEntries(Object.entries(extra).map(([k, v]) => [k, JSON.stringify(v)])),
  };
  const out: string[] = [];
  const err: string[] = [];
  const io = {
    readFile: async (path: string) => {
      const text = store[path];
      if (text === undefined) throw new Error(`ENOENT: ${path}`);
      return text;
    },
    stdout: (line: string) => out.push(line),
    stderr: (line: string) => err.push(line),
  };
  return { io, out, err };
}

test('verifies signatures only', async () => {
  const { io, out } = files();
  const code = await runVerify(['receipt.json', '--jwks', 'jwks.json'], io);
  assert.equal(code, 0);
  assert.equal(out.join('\n'), ['receipt  rcpt_2', 'node     valid', 'cloud    valid', 'chain    skipped', 'root     skipped', 'result   verified'].join('\n'));
});

test('verifies chain, root signature, and inclusion', async () => {
  const { io, out } = files();
  const code = await runVerify(['receipt.json', '--jwks', 'jwks.json', '--chain', 'chain.json', '--root', 'root.json', '--proof', 'proof.json'], io);
  assert.equal(code, 0);
  assert.ok(out.includes('chain    valid (2 receipts)'));
  assert.ok(out.includes('root     valid (2026-09-04, size 2, included)'));
});

test('fails with exit 1 on a tampered receipt', async () => {
  const { io, out, err } = files({ 'receipt.json': { ...r2, seq: 99 } });
  const code = await runVerify(['receipt.json', '--jwks', 'jwks.json'], io);
  assert.equal(code, 1);
  assert.ok(out.includes('result   FAILED'));
  assert.ok(err.some((line) => /signature does not verify/.test(line)));
});

test('fails when the receipt is not the last element of the chain', async () => {
  const { io, err } = files({ 'receipt.json': r1 });
  const code = await runVerify(['receipt.json', '--jwks', 'jwks.json', '--chain', 'chain.json'], io);
  assert.equal(code, 1);
  assert.ok(err.some((line) => /last element/.test(line)));
});

test('fails when the root signature is wrong', async () => {
  const { io, err } = files({ 'root.json': { ...rootDoc, sig: (rootDoc.sig.startsWith('A') ? 'B' : 'A') + rootDoc.sig.slice(1) } });
  const code = await runVerify(['receipt.json', '--jwks', 'jwks.json', '--root', 'root.json', '--proof', 'proof.json'], io);
  assert.equal(code, 1);
  assert.ok(err.some((line) => /root signature/.test(line)));
});

test('a root document with the wrong typ fails', async () => {
  const { io, out, err } = files({ 'root.json': { ...rootDoc, typ: 'agie/receipt/1' } });
  const code = await runVerify(['receipt.json', '--jwks', 'jwks.json', '--root', 'root.json', '--proof', 'proof.json'], io);
  assert.equal(code, 1);
  assert.ok(out.includes('root     invalid'));
  assert.ok(err.some((line) => /typ/.test(line)));
});

test('malformed root file without cloud exits 2', async () => {
  const { io, err } = files({ 'root.json': { typ: rootDoc.typ, date: rootDoc.date, size: rootDoc.size, root: rootDoc.root, sig: rootDoc.sig } });
  const code = await runVerify(['receipt.json', '--jwks', 'jwks.json', '--root', 'root.json', '--proof', 'proof.json'], io);
  assert.equal(code, 2);
  assert.ok(err.some((line) => /root file/.test(line)));
});

test('usage errors exit 2', async () => {
  const { io, err } = files();
  assert.equal(await runVerify([], io), 2);
  assert.equal(await runVerify(['receipt.json'], io), 2);
  assert.equal(await runVerify(['receipt.json', '--jwks', 'missing.json'], io), 2);
  assert.equal(await runVerify(['receipt.json', '--jwks', 'jwks.json', '--root', 'root.json'], io), 2);
  assert.ok(err.length > 0);
});
