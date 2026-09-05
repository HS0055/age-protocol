import { createHash } from 'node:crypto';
import { canonicalBytes, MAX_DEPTH } from './canonical.ts';
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

// Open-ended like the rest of the core: verifyReceipt requires only a string
// kind and digest, and canonicalization signs whatever else an artifact
// carries. A closed type here would reject at compile time what the runtime
// accepts and signs.
export interface ReceiptArtifact {
  kind: string;
  digest: string;
  ref?: string;
  [member: string]: unknown;
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

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/g;
const DETAIL_LIMIT = 72;

// Anything quoted back from the receipt is input the verifier does not
// control. It is stripped of the characters that could rewrite a terminal and
// truncated before it reaches a detail, and it never becomes a check name.
function safeText(value: unknown): string {
  const raw = typeof value === 'string' ? value
    : value === null ? 'null'
    : typeof value === 'object' ? (Array.isArray(value) ? 'an array' : 'an object')
    : typeof value === 'symbol' ? 'a symbol'
    : String(value);
  const stripped = raw.replace(CONTROL_CHARACTERS, '');
  return stripped.length > DETAIL_LIMIT ? `${stripped.slice(0, DETAIL_LIMIT)}...` : stripped;
}

// Nothing here trusts the array to hold objects, or to hold one entry per
// role. Callers that want a verdict on every entry use verifyReceipt.
function signatureEntries(receipt: Receipt): unknown[] {
  const value = receipt as unknown;
  if (!isObject(value) || !Array.isArray(value.signatures)) return [];
  return value.signatures as unknown[];
}

function entriesWithRole(receipt: Receipt, role: string): Record<string, unknown>[] {
  return signatureEntries(receipt).filter((entry): entry is Record<string, unknown> => isObject(entry) && entry.role === role);
}

export function agentSignaturesOf(receipt: Receipt): AgentSignature[] {
  return entriesWithRole(receipt, 'agent') as unknown as AgentSignature[];
}

export function registrySignaturesOf(receipt: Receipt): RegistrySignature[] {
  return entriesWithRole(receipt, 'registry') as unknown as RegistrySignature[];
}

// The singular forms below return the FIRST entry of a role and ignore the
// rest. Taking the first entry and ignoring the rest is precisely how a
// forged second registry entry once rode along invisibly, so nothing that
// decides a verdict may use them: use agentSignaturesOf and
// registrySignaturesOf, and account for every entry. These remain for callers
// that want a display value from a receipt already verified.

/** The first agent entry. Never use this to decide a verdict; see the note above. */
export function agentSignatureOf(receipt: Receipt): AgentSignature | undefined {
  return agentSignaturesOf(receipt)[0];
}

/** The first registry entry. Never use this to decide a verdict; see the note above. */
export function registrySignatureOf(receipt: Receipt): RegistrySignature | undefined {
  return registrySignaturesOf(receipt)[0];
}

// A root belongs to one registry, so a lookup names the registry it means.
export function registrySignatureFor(receipt: Receipt, registryId: string): RegistrySignature | undefined {
  return registrySignaturesOf(receipt).find((entry) => entry.signer === registryId);
}

const RECEIPT_ID = /^sha256:[0-9a-f]{64}$/;

function artifactsProblem(value: unknown, member: string): string | undefined {
  if (!Array.isArray(value)) return `${member} must be an array`;
  for (let i = 0; i < value.length; i += 1) {
    const item: unknown = value[i];
    if (!isObject(item) || typeof item.kind !== 'string' || typeof item.digest !== 'string') {
      return `${member} entry ${i} must be an object with a string kind and digest`;
    }
  }
  return undefined;
}

// RFC 8785 serializes numbers the ES6 way, and a first-time implementer
// reaching for a built-in JSON serializer will not reproduce it: an integral
// float prints as 100.0 in some languages, and the thresholds and zero
// padding of exponential notation differ (1e20, 1e-6, 1e-7 all disagree).
// Every safe integer serializes identically everywhere, so the core carries
// only those, and a stranger's first verifier is byte correct. A quantity
// that is not a whole number belongs in a string, or in a smaller unit:
// milliseconds, cents, basis points.
export function coreNumberProblem(value: unknown, path = '', depth = 0): string | undefined {
  if (depth > MAX_DEPTH) return `${safeText(path) || 'the core'} is nested deeper than ${MAX_DEPTH} levels`;
  if (typeof value === 'number') {
    if (Number.isSafeInteger(value)) return undefined;
    const where = path === '' ? 'the core' : path;
    return `${where} ${safeText(value)} must be an integer of magnitude at most ${Number.MAX_SAFE_INTEGER}`;
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      const problem = coreNumberProblem(value[i], `${path}[${i}]`, depth + 1);
      if (problem !== undefined) return problem;
    }
    return undefined;
  }
  if (isObject(value)) {
    for (const member of Object.keys(value)) {
      const problem = coreNumberProblem(value[member], path === '' ? member : `${path}.${member}`, depth + 1);
      if (problem !== undefined) return problem;
    }
    return undefined;
  }
  return undefined;
}

// What a third-party verifier that validates the schema would insist on. ok
// must never mean less than this, or a receipt this verifier calls verified
// is one another verifier rejects, which breaks interoperability in the
// direction that matters most.
export function receiptShapeProblem(value: unknown): string | undefined {
  if (!isObject(value)) return 'receipt must be an object';
  if (value.receipt_version !== RECEIPT_VERSION) {
    return `receipt_version ${safeText(value.receipt_version)} is not ${RECEIPT_VERSION}`;
  }
  if (typeof value.agent !== 'string' || thumbprintOfId(value.agent, AGENT_ID_PREFIX) === undefined) {
    return `agent must be an ${AGENT_ID_PREFIX} id`;
  }
  if (typeof value.timestamp !== 'string') return 'timestamp must be a string';
  if (!isObject(value.task)) return 'task must be an object';
  if (!isObject(value.action) || typeof value.action.type !== 'string') return 'action must be an object with a string type';
  const inputs = artifactsProblem(value.inputs, 'inputs');
  if (inputs !== undefined) return inputs;
  const outputs = artifactsProblem(value.outputs, 'outputs');
  if (outputs !== undefined) return outputs;
  if (!isObject(value.environment)) return 'environment must be an object';
  if (value.policy !== null && !isObject(value.policy)) return 'policy must be an object or null';
  if (typeof value.id !== 'string' || !RECEIPT_ID.test(value.id)) return 'id must be a sha256: digest';
  if (!Array.isArray(value.signatures)) return 'signatures must be an array';
  return coreNumberProblem(coreOf(value as unknown as Receipt));
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
  const numbers = coreNumberProblem(coreOf(core));
  if (numbers !== undefined) throw new Error(`${caller}: ${numbers}`);
}

export function agentSign(core: ReceiptCore, agentPrivate: PrivateJwk): Receipt {
  assertCore(core, 'agentSign');
  const clean = coreOf(core);
  if (!isPublicJwk(agentPrivate)) {
    throw new Error('agentSign: the signing key must carry the string members of a public JWK: kty, crv, and x');
  }
  const key = bareJwk(toPublicJwk(agentPrivate));
  const keyProblem = embeddedKeyProblem(key);
  if (keyProblem !== undefined) throw new Error(`agentSign: ${keyProblem}`);
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

const NOT_CHECKED = 'not checked, the receipt is malformed';

// A check name is rendered by the CLI, so only a plain token out of the
// receipt is ever allowed to shape one. Everything else is named
// unknown_signature and says what it saw in the detail instead.
const ROLE_TOKEN = /^[A-Za-z0-9_-]{1,32}$/;
const SIGNING_ALGORITHM = 'Ed25519';
const EMBEDDED_KEY_MEMBERS = ['crv', 'kty', 'x'];

// A receipt embeds the agent key it was signed with, so that key is signed
// input that nothing else inspects. It carries the three members RFC 7638
// hashes and no others, or a member no verifier reads could ride along inside
// the signature.
function embeddedKeyProblem(value: unknown): string | undefined {
  if (!isPublicJwk(value)) return 'agent signature carries no public key';
  const members = Object.keys(value).sort();
  if (members.length !== EMBEDDED_KEY_MEMBERS.length || members.some((member, i) => member !== EMBEDDED_KEY_MEMBERS[i])) {
    return `embedded agent key must carry exactly crv, kty, and x, not ${safeText(members.join(', '))}`;
  }
  if (value.kty !== 'OKP') return `embedded agent key kty ${safeText(value.kty)} is not OKP`;
  if (value.crv !== SIGNING_ALGORITHM) return `embedded agent key crv ${safeText(value.crv)} is not ${SIGNING_ALGORITHM}`;
  return undefined;
}

// Every check is always reported, so a reader sees the whole picture even
// when the first one fails. Every entry in the signature array is judged or
// reported by name, so no entry can hide behind another with the same role.
// A receipt is ok when nothing failed; a skipped registry check means an
// unregistered receipt, which is still a valid one.
export function verifyReceipt(receipt: Receipt, options: VerifyReceiptOptions = {}): VerifyReceiptResult {
  const checks: Check[] = [];
  const report = (name: string, status: CheckStatus, detail: string) => {
    checks.push({ name, status, detail });
  };

  const problem = receiptShapeProblem(receipt);
  if (problem !== undefined) {
    report('integrity', 'fail', problem);
    report('agent_signature', 'fail', NOT_CHECKED);
    report('agent_identity', 'fail', NOT_CHECKED);
    return { ok: false, checks };
  }

  let signingInput: Uint8Array;
  try {
    signingInput = agentSigningInput(receipt);
  } catch (error) {
    report('integrity', 'fail', `the receipt cannot be canonicalized: ${safeText(error instanceof Error ? error.message : error)}`);
    report('agent_signature', 'fail', NOT_CHECKED);
    report('agent_identity', 'fail', NOT_CHECKED);
    return { ok: false, checks };
  }

  if (receipt.id === sha256Digest(signingInput)) report('integrity', 'pass', receipt.id);
  else report('integrity', 'fail', 'mismatch');

  const agents = agentSignaturesOf(receipt);
  const agent = agents[0];
  const keyProblem = agent === undefined ? undefined : embeddedKeyProblem(agent.key);
  if (agents.length !== 1 || !agent) {
    const detail = agents.length === 0 ? 'no agent signature' : `${agents.length} agent signatures, exactly one is required`;
    report('agent_signature', 'fail', detail);
    report('agent_identity', 'fail', detail);
  } else if (keyProblem !== undefined) {
    report('agent_signature', 'fail', keyProblem);
    report('agent_identity', 'fail', keyProblem);
  } else if (agent.alg !== SIGNING_ALGORITHM) {
    // The identity still holds: the key is genuine and binds the id. Only the
    // claim about how it was used is wrong, so only that check fails.
    report('agent_signature', 'fail', `alg ${safeText(agent.alg)} is not ${SIGNING_ALGORITHM}`);
    reportAgentIdentity(receipt, agent, report);
  } else {
    const signatureOk = typeof agent.signature === 'string' && verifyBytes(signingInput, agent.signature, agent.key);
    report('agent_signature', signatureOk ? 'pass' : 'fail', signatureOk ? safeText(agent.signer) : 'agent signature does not verify');
    reportAgentIdentity(receipt, agent, report);
  }

  // Zero registry entries is an unregistered receipt. One keeps the name the
  // CLI already labels. More than one is legitimate once a second registry
  // countersigns, and every one of them has to verify on its own.
  const registries = registrySignaturesOf(receipt);
  if (registries.length === 0) {
    report('registry_signature', 'skip', 'absent, unregistered receipt');
  } else {
    const keys = options.registryKeys instanceof Map ? options.registryKeys : keyMapFromJwks(options.registryKeys ?? []);
    registries.forEach((entry, position) => {
      const name = registries.length === 1 ? 'registry_signature' : `registry_signature_${position + 1}`;
      const [status, detail] = registryVerdict(receipt, entry, keys);
      report(name, status, detail);
    });
  }

  const entries = signatureEntries(receipt);
  for (let i = 0; i < entries.length; i += 1) {
    const entry: unknown = entries[i];
    if (isObject(entry) && (entry.role === 'agent' || entry.role === 'registry')) continue;
    if (!isObject(entry)) {
      report('unknown_signature', 'fail', `signature entry ${i} is ${safeText(entry)}, not an object`);
    } else if (typeof entry.role !== 'string') {
      report('unknown_signature', 'fail', `signature entry ${i} has a role that is ${safeText(entry.role)}, not a string`);
    } else if (!ROLE_TOKEN.test(entry.role)) {
      report('unknown_signature', 'skip', `unknown role ${safeText(entry.role)}, not checked`);
    } else {
      report(`${entry.role}_signature`, 'skip', 'unknown role, not checked');
    }
  }

  return { ok: checks.every((check) => check.status !== 'fail'), checks };
}

type Report = (name: string, status: CheckStatus, detail: string) => void;

function reportAgentIdentity(receipt: Receipt, agent: AgentSignature, report: Report): void {
  const derived = agentIdOf(agent.key);
  const identityOk = derived === agent.signer && derived === receipt.agent;
  report(
    'agent_identity',
    identityOk ? 'pass' : 'fail',
    identityOk ? 'key thumbprint matches id'
      : `key thumbprint gives ${derived}, receipt says ${safeText(receipt.agent)}, signer says ${safeText(agent.signer)}`,
  );
}

function registryVerdict(receipt: Receipt, entry: RegistrySignature, keys: Map<string, PublicJwk>): [CheckStatus, string] {
  if (entry.alg !== SIGNING_ALGORITHM) return ['fail', `alg ${safeText(entry.alg)} is not ${SIGNING_ALGORITHM}`];
  const jkt = thumbprintOfId(entry.signer, REGISTRY_ID_PREFIX);
  const key = jkt === undefined ? undefined : keys.get(jkt);
  if (!key) return ['fail', `registry key ${safeText(entry.signer)} not available`];
  if (!Number.isInteger(entry.sequence) || typeof entry.registered_at !== 'string' || typeof entry.signature !== 'string') {
    return ['fail', 'registry signature entry is malformed'];
  }
  if (!verifyBytes(registrySigningInput(receipt, entry), entry.signature, key)) return ['fail', 'registry signature does not verify'];
  return ['pass', `${safeText(entry.signer)}  sequence #${entry.sequence}`];
}
