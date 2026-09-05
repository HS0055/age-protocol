import { createHash } from 'node:crypto';
import { canonicalBytes } from './canonical.ts';
import { bareJwk, isPublicJwk, keyMapFromJwks, thumbprint, toPublicJwk, type PrivateJwk, type PublicJwk } from './keys.ts';
import { signBytes, verifyBytes } from './signature.ts';

export const RECEIPT_VERSION = '0.1';
export const ATTESTATION_VERSION = '0.1';
export const AGENT_ID_PREFIX = 'age:agent:';
export const REGISTRY_ID_PREFIX = 'age:registry:';
export const DIGEST_PREFIX = 'sha256:';

export function sha256Digest(bytes: Uint8Array): string {
  return `${DIGEST_PREFIX}${createHash('sha256').update(bytes).digest('hex')}`;
}

// Identities are derived from keys, never assigned: the id is the RFC 7638
// thumbprint behind a prefix that names the kind of thing it identifies.
export function agentIdOf(key: PublicJwk): string {
  return `${AGENT_ID_PREFIX}${thumbprint(key)}`;
}

export function registryIdOf(key: PublicJwk): string {
  return `${REGISTRY_ID_PREFIX}${thumbprint(key)}`;
}

export function thumbprintOfId(id: string, prefix: string): string | undefined {
  if (typeof id !== 'string' || !id.startsWith(prefix) || id.length === prefix.length) return undefined;
  return id.slice(prefix.length);
}

export interface ReceiptArtifact {
  kind: string;
  digest: string;
  ref?: string;
}

export interface ReceiptTask {
  id?: string;
  description?: string;
  [member: string]: unknown;
}

export type ReceiptPolicy = Record<string, unknown>;

// The core is what the agent asserts and signs. Everything the registry adds
// lives outside it, in id and signatures.
export interface ReceiptCore {
  receipt_version: typeof RECEIPT_VERSION;
  agent: string;
  timestamp: string;
  task: ReceiptTask;
  action: { type: string } & Record<string, unknown>;
  inputs: ReceiptArtifact[];
  outputs: ReceiptArtifact[];
  environment: Record<string, unknown>;
  policy: ReceiptPolicy | null;
}

export interface AgentSignature {
  role: 'agent';
  signer: string;
  alg: 'Ed25519';
  key: PublicJwk;
  signature: string;
}

export interface RegistrySignature {
  role: 'registry';
  signer: string;
  alg: 'Ed25519';
  sequence: number;
  registered_at: string;
  jwks?: string;
  signature: string;
}

// Roles this version does not know (runtime, hardware, organization) are
// carried and reported, never judged, so they can be added without a break.
export interface OtherSignature {
  role: string;
  signer: string;
  alg: string;
  signature: string;
  [member: string]: unknown;
}

export type ReceiptSignature = AgentSignature | RegistrySignature | OtherSignature;

export interface Receipt extends ReceiptCore {
  id: string;
  signatures: ReceiptSignature[];
}

export function coreOf(value: ReceiptCore | Receipt): ReceiptCore {
  const { id, signatures, ...core } = value as Receipt;
  return core as ReceiptCore;
}

export function receiptIdOf(value: ReceiptCore | Receipt): string {
  return sha256Digest(canonicalBytes(coreOf(value)));
}

export function agentSigningInput(value: ReceiptCore | Receipt): Uint8Array {
  return canonicalBytes(coreOf(value));
}

export interface RegistryAttestation {
  attestation_version: typeof ATTESTATION_VERSION;
  receipt: string;
  agent: string;
  sequence: number;
  registered_at: string;
  registry: string;
}

type RegistryEntryFields = Pick<RegistrySignature, 'sequence' | 'registered_at' | 'signer'>;

// The registry countersigns the receipt hash and its place in the sequence,
// nothing else. It does not re-sign the agent's content.
export function attestationOf(receipt: Receipt, entry: RegistryEntryFields): RegistryAttestation {
  return {
    attestation_version: ATTESTATION_VERSION,
    receipt: receipt.id,
    agent: receipt.agent,
    sequence: entry.sequence,
    registered_at: entry.registered_at,
    registry: entry.signer,
  };
}

export function registrySigningInput(receipt: Receipt, entry: RegistryEntryFields): Uint8Array {
  return canonicalBytes(attestationOf(receipt, entry));
}

export function agentSignatureOf(receipt: Receipt): AgentSignature | undefined {
  if (!Array.isArray(receipt.signatures)) return undefined;
  return receipt.signatures.find((entry): entry is AgentSignature => entry.role === 'agent');
}

export function registrySignatureOf(receipt: Receipt): RegistrySignature | undefined {
  if (!Array.isArray(receipt.signatures)) return undefined;
  return receipt.signatures.find((entry): entry is RegistrySignature => entry.role === 'registry');
}

function assertCore(core: ReceiptCore, caller: string): void {
  if (core.receipt_version !== RECEIPT_VERSION) {
    throw new Error(`${caller}: receipt_version must be ${RECEIPT_VERSION}`);
  }
  if (thumbprintOfId(core.agent, AGENT_ID_PREFIX) === undefined) {
    throw new Error(`${caller}: agent must be an ${AGENT_ID_PREFIX} id`);
  }
  if (typeof core.action !== 'object' || core.action === null || typeof core.action.type !== 'string') {
    throw new Error(`${caller}: action.type is required`);
  }
}

export function agentSign(core: ReceiptCore, agentPrivate: PrivateJwk): Receipt {
  assertCore(core, 'agentSign');
  const clean = coreOf(core);
  const key = bareJwk(toPublicJwk(agentPrivate));
  const signer = agentIdOf(key);
  if (signer !== clean.agent) {
    throw new Error(`agentSign: core.agent ${clean.agent} is not the id of the signing key ${signer}`);
  }
  const signature = signBytes(canonicalBytes(clean), agentPrivate);
  return { ...clean, id: receiptIdOf(clean), signatures: [{ role: 'agent', signer, alg: 'Ed25519', key, signature }] };
}

export interface RegistryAssignment {
  sequence: number;
  registered_at: string;
  jwks?: string;
}

export function registrySign(receipt: Receipt, assigned: RegistryAssignment, registryPrivate: PrivateJwk): Receipt {
  if (receipt.id !== receiptIdOf(receipt)) throw new Error('registrySign: receipt id does not match its content');
  if (!agentSignatureOf(receipt)) throw new Error('registrySign: receipt has no agent signature');
  if (registrySignatureOf(receipt)) throw new Error('registrySign: receipt already has a registry signature');
  if (!Number.isInteger(assigned.sequence) || assigned.sequence < 1) {
    throw new Error('registrySign: sequence must be a positive integer');
  }
  const signer = registryIdOf(bareJwk(toPublicJwk(registryPrivate)));
  const fields: RegistryEntryFields = { sequence: assigned.sequence, registered_at: assigned.registered_at, signer };
  const signature = signBytes(registrySigningInput(receipt, fields), registryPrivate);
  const entry: RegistrySignature = {
    role: 'registry',
    signer,
    alg: 'Ed25519',
    sequence: assigned.sequence,
    registered_at: assigned.registered_at,
    ...(assigned.jwks === undefined ? {} : { jwks: assigned.jwks }),
    signature,
  };
  return { ...receipt, signatures: [...receipt.signatures, entry] };
}

export type CheckStatus = 'pass' | 'fail' | 'skip';

export interface Check {
  name: string;
  status: CheckStatus;
  detail: string;
}

export interface VerifyReceiptResult {
  ok: boolean;
  checks: Check[];
}

export interface VerifyReceiptOptions {
  registryKeys?: PublicJwk[] | Map<string, PublicJwk>;
}

// Every check is always reported, so a reader sees the whole picture even
// when the first one fails. A receipt is ok when nothing failed; a skipped
// registry check means an unregistered receipt, which is still a valid one.
export function verifyReceipt(receipt: Receipt, options: VerifyReceiptOptions = {}): VerifyReceiptResult {
  const checks: Check[] = [];
  const report = (name: string, status: CheckStatus, detail: string) => {
    checks.push({ name, status, detail });
  };

  if (receipt.receipt_version !== RECEIPT_VERSION) {
    report('integrity', 'fail', `receipt_version ${String(receipt.receipt_version)} is not ${RECEIPT_VERSION}`);
  } else if (typeof receipt.id !== 'string' || receipt.id !== receiptIdOf(receipt)) {
    report('integrity', 'fail', 'mismatch');
  } else {
    report('integrity', 'pass', receipt.id);
  }

  const agent = agentSignatureOf(receipt);
  if (!agent) {
    report('agent_signature', 'fail', 'no agent signature');
    report('agent_identity', 'fail', 'no agent signature');
  } else if (!isPublicJwk(agent.key)) {
    report('agent_signature', 'fail', 'agent signature carries no public key');
    report('agent_identity', 'fail', 'agent signature carries no public key');
  } else {
    const signatureOk = typeof agent.signature === 'string' && verifyBytes(agentSigningInput(receipt), agent.signature, agent.key);
    report('agent_signature', signatureOk ? 'pass' : 'fail', signatureOk ? agent.signer : 'agent signature does not verify');
    const derived = agentIdOf(agent.key);
    const identityOk = derived === agent.signer && derived === receipt.agent;
    report(
      'agent_identity',
      identityOk ? 'pass' : 'fail',
      identityOk ? 'key thumbprint matches id' : `key thumbprint gives ${derived}, receipt says ${receipt.agent}, signer says ${agent.signer}`,
    );
  }

  const registry = registrySignatureOf(receipt);
  if (!registry) {
    report('registry_signature', 'skip', 'absent, unregistered receipt');
  } else {
    const keys = options.registryKeys instanceof Map ? options.registryKeys : keyMapFromJwks(options.registryKeys ?? []);
    const jkt = thumbprintOfId(registry.signer, REGISTRY_ID_PREFIX);
    const key = jkt === undefined ? undefined : keys.get(jkt);
    if (!key) {
      report('registry_signature', 'fail', `registry key ${String(registry.signer)} not available`);
    } else if (!Number.isInteger(registry.sequence) || typeof registry.registered_at !== 'string' || typeof registry.signature !== 'string') {
      report('registry_signature', 'fail', 'registry signature entry is malformed');
    } else if (verifyBytes(registrySigningInput(receipt, registry), registry.signature, key)) {
      report('registry_signature', 'pass', `${registry.signer}  sequence #${registry.sequence}`);
    } else {
      report('registry_signature', 'fail', 'registry signature does not verify');
    }
  }

  if (Array.isArray(receipt.signatures)) {
    for (const entry of receipt.signatures) {
      if (entry.role !== 'agent' && entry.role !== 'registry') {
        report(`${String(entry.role)}_signature`, 'skip', 'unknown role, not checked');
      }
    }
  }

  return { ok: checks.every((check) => check.status !== 'fail'), checks };
}
