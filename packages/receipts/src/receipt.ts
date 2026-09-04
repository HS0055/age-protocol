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

// What the node builds and signs. The cloud assigns id, seq, and prev when it
// stores the receipt, so those three are not part of the node signing input.
export interface ReceiptEnvelope {
  v: 1;
  ts: string;
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
}

export interface NodeSignedEnvelope extends ReceiptEnvelope {
  node_sig: string;
}

// The three members the cloud assigns after the node has signed.
export interface CloudAssigned {
  id: string;
  seq: number;
  prev: string | null;
}

export interface ReceiptBody extends ReceiptEnvelope, CloudAssigned {}

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

// Everything the node knows, without the cloud-assigned members and without
// either signature.
function envelopeOf(value: ReceiptEnvelope | Partial<Receipt>): ReceiptEnvelope {
  const { id, seq, prev, node_sig, cloud_sig, ...envelope } = value as Partial<Receipt>;
  return envelope as ReceiptEnvelope;
}

export function nodeSigningInput(value: ReceiptEnvelope | Receipt): Uint8Array {
  return canonicalBytes(envelopeOf(value));
}

export function cloudSigningInput(body: ReceiptBody & { node_sig?: string | null }): Uint8Array {
  const { cloud_sig, ...rest } = body as Receipt;
  return canonicalBytes({ ...rest, node_sig: body.node_sig ?? null });
}

export function nodeSign(envelope: ReceiptEnvelope, nodePrivate: PrivateJwk): NodeSignedEnvelope {
  if (!envelope.node) throw new Error('nodeSign: envelope has no node');
  const clean = envelopeOf(envelope);
  return { ...clean, node_sig: signBytes(canonicalBytes(clean), nodePrivate) };
}

export function cloudSign(
  envelope: ReceiptEnvelope | NodeSignedEnvelope,
  assigned: CloudAssigned,
  cloudPrivate: PrivateJwk,
): Receipt {
  const node_sig = 'node_sig' in envelope ? envelope.node_sig ?? null : null;
  const body = { ...envelopeOf(envelope), id: assigned.id, seq: assigned.seq, prev: assigned.prev, node_sig };
  return { ...body, cloud_sig: signBytes(cloudSigningInput(body), cloudPrivate) };
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
