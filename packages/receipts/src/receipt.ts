import { createHash } from 'node:crypto';
import { canonicalBytes } from './canonical.ts';
import { isPublicJwk, keyMapFromJwks, thumbprint, type PrivateJwk, type PublicJwk } from './keys.ts';
import { signBytes, verifyBytes } from './signature.ts';

// Domain separation: every signed AGIE document names its own type, so a
// signature over one structure can never be replayed as another.
export const RECEIPT_TYP = 'agie/receipt/1';
export const ROOT_TYP = 'agie/root/1';

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

// jwk is optional and self-certifying: a verifier accepts it only when its
// RFC 7638 thumbprint equals jkt.
export interface ReceiptNode {
  jkt: string;
  jwk?: PublicJwk;
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
  typ: typeof RECEIPT_TYP;
  v: 1;
  ts: string;
  company: string;
  mission: string | null;
  task: string | null;
  run: string | null;
  actor: ReceiptActor;
  node: ReceiptNode | null;
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

function assertReceiptTyp(envelope: ReceiptEnvelope, caller: string): void {
  if (envelope.typ !== RECEIPT_TYP) {
    throw new Error(`${caller}: envelope typ must be ${RECEIPT_TYP}`);
  }
}

export function nodeSign(envelope: ReceiptEnvelope, nodePrivate: PrivateJwk): NodeSignedEnvelope {
  assertReceiptTyp(envelope, 'nodeSign');
  if (!envelope.node) throw new Error('nodeSign: envelope has no node');
  const clean = envelopeOf(envelope);
  return { ...clean, node_sig: signBytes(canonicalBytes(clean), nodePrivate) };
}

export function cloudSign(
  envelope: ReceiptEnvelope | NodeSignedEnvelope,
  assigned: CloudAssigned,
  cloudPrivate: PrivateJwk,
): Receipt {
  assertReceiptTyp(envelope, 'cloudSign');
  const node_sig = 'node_sig' in envelope ? envelope.node_sig ?? null : null;
  const body = { ...envelopeOf(envelope), id: assigned.id, seq: assigned.seq, prev: assigned.prev, node_sig };
  return { ...body, cloud_sig: signBytes(cloudSigningInput(body), cloudPrivate) };
}

// A node may publish its own key inside the receipt. It counts only when it
// hashes to the jkt the two signatures cover, which makes it self-certifying.
function embeddedNodeKey(node: ReceiptNode): PublicJwk | undefined {
  if (!isPublicJwk(node.jwk)) return undefined;
  return thumbprint(node.jwk) === node.jkt ? node.jwk : undefined;
}

export function receiptHash(receipt: Receipt): string {
  return createHash('sha256').update(canonicalBytes(receipt)).digest('hex');
}

export function verifyReceipt(
  receipt: Receipt,
  keys: PublicJwk[] | Map<string, PublicJwk>,
): VerifyReceiptResult {
  const byThumbprint = Array.isArray(keys) ? keyMapFromJwks(keys) : keys;
  const errors: string[] = [];
  let node: VerifyReceiptResult['node'];

  if (receipt.typ !== RECEIPT_TYP) {
    return {
      ok: false,
      node: 'invalid',
      cloud: 'invalid',
      errors: [`receipt typ ${String(receipt.typ)} is not ${RECEIPT_TYP}`],
    };
  }

  if (receipt.node === null) {
    // A missing member and an explicit null both mean no node signature.
    if (receipt.node_sig !== null && receipt.node_sig !== undefined) {
      errors.push('node_sig present but receipt has no node');
      node = 'invalid';
    } else {
      node = 'absent';
    }
  } else if (typeof receipt.node_sig !== 'string') {
    errors.push('node present but node_sig missing');
    node = 'invalid';
  } else if (receipt.node.jwk !== undefined && !embeddedNodeKey(receipt.node)) {
    errors.push('embedded node jwk does not match node.jkt');
    node = 'invalid';
  } else {
    const nodeKey = embeddedNodeKey(receipt.node) ?? byThumbprint.get(receipt.node.jkt);
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
  const cloudKey = byThumbprint.get(receipt.cloud.jkt);
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
