import { createHash } from 'node:crypto';
import { canonicalBytes } from './canonical.ts';
import { thumbprint, type PrivateJwk, type PublicJwk } from './keys.ts';
import { signBytes, verifyBytes } from './signature.ts';

export interface ReceiptActor {
  type: 'agent' | 'human' | 'system';
  jkt?: string;
  id?: string;
  level?: 0 | 1 | 2;
}

export interface ReceiptArtifact {
  kind: string;
  sha256: string;
  path_hashes?: string[];
}

export interface ReceiptGate {
  id: string;
  class: string;
  decision: 'approved' | 'rejected';
  decided_by: string;
  ts: string;
}

export interface ReceiptBody {
  v: 1;
  id: string;
  ts: string;
  seq: number;
  company: string;
  mission: string | null;
  task: string | null;
  run: string | null;
  actor: ReceiptActor;
  node: { jkt: string } | null;
  cloud: { jkt: string };
  action: { type: string } & Record<string, unknown>;
  inputs: ReceiptArtifact[];
  outputs: ReceiptArtifact[];
  gate: ReceiptGate | null;
  prev: string | null;
}

export interface NodeSignedReceipt extends ReceiptBody {
  node_sig: string;
}

export interface Receipt extends ReceiptBody {
  node_sig: string | null;
  cloud_sig: string;
}

export type SignatureStatus = 'valid' | 'invalid' | 'unknown_key';

export interface VerifyReceiptResult {
  ok: boolean;
  node: SignatureStatus | 'absent';
  cloud: SignatureStatus;
  errors: string[];
}

function stripSignatures(receipt: Partial<Receipt>): ReceiptBody {
  const { node_sig, cloud_sig, ...body } = receipt;
  void node_sig;
  void cloud_sig;
  return body as ReceiptBody;
}

export function nodeSigningInput(body: ReceiptBody): Uint8Array {
  return canonicalBytes(stripSignatures(body));
}

export function cloudSigningInput(receipt: ReceiptBody & { node_sig?: string | null }): Uint8Array {
  return canonicalBytes({ ...stripSignatures(receipt), node_sig: receipt.node_sig ?? null });
}

export function nodeSign(body: ReceiptBody, nodePrivate: PrivateJwk): NodeSignedReceipt {
  if (!body.node) throw new Error('nodeSign: receipt body has no node');
  return { ...stripSignatures(body), node_sig: signBytes(nodeSigningInput(body), nodePrivate) };
}

export function cloudSign(receipt: ReceiptBody | NodeSignedReceipt, cloudPrivate: PrivateJwk): Receipt {
  const node_sig = 'node_sig' in receipt ? receipt.node_sig : null;
  const unsigned = { ...stripSignatures(receipt), node_sig };
  return { ...unsigned, cloud_sig: signBytes(cloudSigningInput(unsigned), cloudPrivate) };
}

export function receiptHash(receipt: Receipt): string {
  return createHash('sha256').update(canonicalBytes(receipt)).digest('hex');
}

function findKey(keys: PublicJwk[], jkt: string): PublicJwk | undefined {
  return keys.find((key) => (key.kid ?? thumbprint(key)) === jkt);
}

export function verifyReceipt(receipt: Receipt, keys: PublicJwk[]): VerifyReceiptResult {
  const errors: string[] = [];
  let node: VerifyReceiptResult['node'];

  if (receipt.node === null) {
    if (receipt.node_sig !== null) {
      errors.push('node_sig present but receipt has no node');
      node = 'invalid';
    } else {
      node = 'absent';
    }
  } else if (typeof receipt.node_sig !== 'string') {
    errors.push('node present but node_sig missing');
    node = 'invalid';
  } else {
    const nodeKey = findKey(keys, receipt.node.jkt);
    if (!nodeKey) {
      errors.push(`node key ${receipt.node.jkt} not in key set`);
      node = 'unknown_key';
    } else if (verifyBytes(nodeSigningInput(receipt), receipt.node_sig, nodeKey)) {
      node = 'valid';
    } else {
      errors.push('node signature does not verify');
      node = 'invalid';
    }
  }

  let cloud: SignatureStatus;
  const cloudKey = findKey(keys, receipt.cloud.jkt);
  if (!cloudKey) {
    errors.push(`cloud key ${receipt.cloud.jkt} not in key set`);
    cloud = 'unknown_key';
  } else if (verifyBytes(cloudSigningInput(receipt), receipt.cloud_sig, cloudKey)) {
    cloud = 'valid';
  } else {
    errors.push('cloud signature does not verify');
    cloud = 'invalid';
  }

  const ok = (node === 'valid' || node === 'absent') && cloud === 'valid';
  return { ok, node, cloud, errors };
}
