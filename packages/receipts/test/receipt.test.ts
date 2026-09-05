import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  agentSign, registrySign, verifyReceipt, receiptIdOf, agentIdOf, registryIdOf, thumbprintOfId, coreOf,
  agentSignatureOf, registrySignatureOf, attestationOf, canonicalize, canonicalBytes, generateKeyPair, bareJwk,
  keyMapFromJwks, sha256Digest, signBytes, registrySigningInput, toPublicJwk, receiptShapeProblem,
  AGENT_ID_PREFIX, REGISTRY_ID_PREFIX, RECEIPT_VERSION, ATTESTATION_VERSION,
  type PrivateJwk, type Receipt, type ReceiptCore, type RegistrySignature,
} from '../src/index.ts';

const agent = generateKeyPair();
const registry = generateKeyPair();
const second = generateKeyPair();
const stranger = generateKeyPair();
const AGENT_ID = agentIdOf(agent.publicJwk);
const ASSIGNED = { sequence: 184, registered_at: '2026-09-05T03:20:04Z', jwks: 'https://registry.test/.well-known/age-jwks.json' };

function core(overrides: Partial<ReceiptCore> = {}): ReceiptCore {
  return {
    receipt_version: RECEIPT_VERSION,
    agent: AGENT_ID,
    timestamp: '2026-09-05T03:20:00Z',
    task: { id: 'tsk_91', description: 'Fix authentication bug' },
    action: { type: 'git.commit', commit: '8fa72c1e5b9d4a3f2e1c0b9a8d7f6e5c4b3a2918', files_changed: 3, tests: 'passed' },
    inputs: [{ kind: 'prompt', digest: `sha256:${'aa'.repeat(32)}` }],
    outputs: [{ kind: 'commit', digest: `sha256:${'bb'.repeat(32)}`, ref: '8fa72c1e5b9d4a3f2e1c0b9a8d7f6e5c4b3a2918' }],
    environment: { runtime: 'claude-code/2.1.0', workspace: 'github.com/ageprotocol/demo' },
    policy: null,
    ...overrides,
  };
}

function registered(overrides: Partial<ReceiptCore> = {}): Receipt {
  return registrySign(agentSign(core(overrides), agent.privateJwk), ASSIGNED, registry.privateJwk);
}

function statuses(receipt: Receipt, keys = [registry.publicJwk]) {
  return Object.fromEntries(verifyReceipt(receipt, { registryKeys: keys }).checks.map((c) => [c.name, c.status]));
}

// Signs an arbitrary object as if it were a receipt core, with the same
// exported primitives an implementer would use. Everything about the result
// is consistent; only the schema is wrong.
function forge(fields: Record<string, unknown>): Receipt {
  const bytes = canonicalBytes(fields);
  const entry = { role: 'agent', signer: AGENT_ID, alg: 'Ed25519', key: bareJwk(agent.publicJwk), signature: signBytes(bytes, agent.privateJwk) };
  return { ...fields, id: sha256Digest(bytes), signatures: [entry] } as unknown as Receipt;
}

function coreWithout(member: string): Record<string, unknown> {
  const fields = core() as unknown as Record<string, unknown>;
  delete fields[member];
  return fields;
}

// A second registry countersigns an already registered receipt. registrySign
// issues the first registration only, so the entry is built from the same
// exported primitives a second registry would use.
function countersign(receipt: Receipt, sequence: number, registryPrivate: PrivateJwk): Receipt {
  const signer = registryIdOf(bareJwk(toPublicJwk(registryPrivate)));
  const registered_at = '2026-09-05T05:00:00Z';
  const signature = signBytes(registrySigningInput(receipt, { sequence, registered_at, signer }), registryPrivate);
  const entry: RegistrySignature = { role: 'registry', signer, alg: 'Ed25519', sequence, registered_at, signature };
  return { ...receipt, signatures: [...receipt.signatures, entry] };
}

test('agentSign derives the id from the canonical core and embeds the bare public key', () => {
  const signed = agentSign(core(), agent.privateJwk);
  assert.equal(signed.id, sha256Digest(canonicalBytes(core())));
  assert.equal(signed.id, receiptIdOf(signed));
  assert.match(signed.id, /^sha256:[0-9a-f]{64}$/);
  assert.equal(signed.signatures.length, 1);
  const entry = agentSignatureOf(signed);
  assert.ok(entry);
  assert.deepEqual(entry.key, bareJwk(agent.publicJwk));
  assert.equal(entry.signer, AGENT_ID);
  assert.equal(entry.alg, 'Ed25519');
  assert.equal(entry.signature.length, 86);
  assert.deepEqual(coreOf(signed), core());
});

test('the agent id is the key thumbprint with the age:agent: prefix', () => {
  assert.equal(AGENT_ID, `${AGENT_ID_PREFIX}${agent.publicJwk.kid}`);
  assert.equal(thumbprintOfId(AGENT_ID, AGENT_ID_PREFIX), agent.publicJwk.kid);
  assert.equal(thumbprintOfId(AGENT_ID, REGISTRY_ID_PREFIX), undefined);
  assert.equal(thumbprintOfId('age:agent:', AGENT_ID_PREFIX), undefined);
  assert.equal(registryIdOf(registry.publicJwk), `${REGISTRY_ID_PREFIX}${registry.publicJwk.kid}`);
});

test('agentSign refuses a core that does not name the signing key, a wrong version, or a missing action type', () => {
  assert.throws(() => agentSign(core({ agent: agentIdOf(stranger.publicJwk) }), agent.privateJwk), /is not the id of the signing key/);
  assert.throws(() => agentSign(core({ agent: 'not-an-id' }), agent.privateJwk), /age:agent:/);
  assert.throws(() => agentSign({ ...core(), receipt_version: '0.0' as '0.1' }, agent.privateJwk), /receipt_version/);
  assert.throws(() => agentSign(core({ action: {} as { type: string } }), agent.privateJwk), /action\.type/);
});

test('an unregistered receipt verifies with the registry check skipped', () => {
  const signed = agentSign(core(), agent.privateJwk);
  const result = verifyReceipt(signed);
  assert.equal(result.ok, true);
  assert.deepEqual(result.checks.map((c) => [c.name, c.status]), [
    ['integrity', 'pass'], ['agent_signature', 'pass'], ['agent_identity', 'pass'], ['registry_signature', 'skip'],
  ]);
});

test('registrySign appends an attestation over the id, agent, sequence, and time', () => {
  const receipt = registered();
  const entry = registrySignatureOf(receipt);
  assert.ok(entry);
  assert.equal(entry.signer, registryIdOf(registry.publicJwk));
  assert.equal(entry.sequence, 184);
  assert.equal(entry.registered_at, ASSIGNED.registered_at);
  assert.equal(entry.jwks, ASSIGNED.jwks);
  assert.deepEqual(attestationOf(receipt, entry), {
    attestation_version: ATTESTATION_VERSION, receipt: receipt.id, agent: AGENT_ID, sequence: 184,
    registered_at: ASSIGNED.registered_at, registry: entry.signer,
  });
  const result = verifyReceipt(receipt, { registryKeys: [registry.publicJwk] });
  assert.equal(result.ok, true);
  assert.deepEqual(statuses(receipt), { integrity: 'pass', agent_signature: 'pass', agent_identity: 'pass', registry_signature: 'pass' });
  assert.match(result.checks[3]?.detail ?? '', /sequence #184/);
});

test('registry keys may be given as a JWKS array or a thumbprint map, and kid labels are ignored', () => {
  const receipt = registered();
  const mislabelled = { ...bareJwk(stranger.publicJwk), kid: registry.publicJwk.kid };
  assert.equal(statuses(receipt, [mislabelled]).registry_signature, 'fail');
  assert.equal(verifyReceipt(receipt, { registryKeys: keyMapFromJwks([registry.publicJwk]) }).ok, true);
  assert.equal(statuses(receipt, []).registry_signature, 'fail');
  assert.equal(verifyReceipt(receipt).ok, false);
});

test('changing one member of the core breaks integrity and the agent signature', () => {
  const receipt = registered();
  const tampered: Receipt = { ...receipt, task: { ...receipt.task, description: 'Fix authentication bug!' } };
  const s = statuses(tampered);
  assert.equal(s.integrity, 'fail');
  assert.equal(s.agent_signature, 'fail');
  assert.equal(s.agent_identity, 'pass');
  assert.equal(verifyReceipt(tampered, { registryKeys: [registry.publicJwk] }).ok, false);
  assert.equal(verifyReceipt(tampered, { registryKeys: [registry.publicJwk] }).checks[0]?.detail, 'mismatch');
});

test('swapping the embedded key for a stranger key fails the signature and the identity', () => {
  const receipt = registered();
  const entry = agentSignatureOf(receipt);
  assert.ok(entry);
  const swapped: Receipt = { ...receipt, signatures: [{ ...entry, key: bareJwk(stranger.publicJwk) }, ...receipt.signatures.slice(1)] };
  const s = statuses(swapped);
  assert.equal(s.agent_signature, 'fail');
  assert.equal(s.agent_identity, 'fail');
});

test('a receipt whose agent field disagrees with the signing key fails identity even with a valid signature', () => {
  const receipt = registered();
  const forged: Receipt = { ...receipt, agent: agentIdOf(stranger.publicJwk) };
  forged.id = receiptIdOf(forged);
  const s = statuses(forged);
  assert.equal(s.integrity, 'pass');
  assert.equal(s.agent_signature, 'fail');
  assert.equal(s.agent_identity, 'fail');
});

test('registrySign refuses a wrong id, a missing agent signature, a second registration, and a bad sequence', () => {
  const signed = agentSign(core(), agent.privateJwk);
  assert.throws(() => registrySign({ ...signed, id: `sha256:${'00'.repeat(32)}` }, ASSIGNED, registry.privateJwk), /does not match/);
  assert.throws(() => registrySign({ ...signed, signatures: [] }, ASSIGNED, registry.privateJwk), /no agent signature/);
  assert.throws(() => registrySign(registered(), ASSIGNED, registry.privateJwk), /already has a registry signature/);
  assert.throws(() => registrySign(signed, { ...ASSIGNED, sequence: 0 }, registry.privateJwk), /sequence/);
});

test('a malformed or wrongly keyed registry entry fails, and an unknown role is reported but not judged', () => {
  const receipt = registered();
  const entry = registrySignatureOf(receipt);
  assert.ok(entry);
  const wrongSequence: Receipt = { ...receipt, signatures: [receipt.signatures[0]!, { ...entry, sequence: 185 }] };
  assert.equal(statuses(wrongSequence).registry_signature, 'fail');
  const strangerSigned = registrySign(agentSign(core(), agent.privateJwk), ASSIGNED, stranger.privateJwk);
  assert.equal(statuses(strangerSigned).registry_signature, 'fail');
  const withRuntime: Receipt = { ...receipt, signatures: [...receipt.signatures, { role: 'runtime', signer: 'age:runtime:x', alg: 'Ed25519', signature: 'A'.repeat(86) }] };
  const result = verifyReceipt(withRuntime, { registryKeys: [registry.publicJwk] });
  assert.equal(result.ok, true);
  assert.deepEqual(result.checks.at(-1), { name: 'runtime_signature', status: 'skip', detail: 'unknown role, not checked' });
});

test('a wrong receipt_version fails integrity', () => {
  const receipt = registered();
  const bumped = { ...receipt, receipt_version: '0.2' } as unknown as Receipt;
  assert.equal(statuses(bumped).integrity, 'fail');
});

test('the canonical core is what the agent signs', () => {
  const signed = agentSign(core(), agent.privateJwk);
  assert.equal(canonicalize(coreOf(signed)), canonicalize(core()));
  assert.equal(Buffer.from(canonicalBytes(coreOf(signed))).toString('utf8').includes('"signatures"'), false);
});

test('a forged second registry entry is reported and fails the receipt', () => {
  const receipt = registered();
  const forged: Receipt = {
    ...receipt,
    signatures: [...receipt.signatures, {
      role: 'registry', signer: registryIdOf(stranger.publicJwk), alg: 'Ed25519', sequence: 9999,
      registered_at: '2026-09-05T03:20:04Z', signature: 'A'.repeat(86),
    }],
  };
  const result = verifyReceipt(forged, { registryKeys: [registry.publicJwk] });
  assert.equal(result.ok, false);
  assert.deepEqual(result.checks.map((c) => [c.name, c.status]), [
    ['integrity', 'pass'], ['agent_signature', 'pass'], ['agent_identity', 'pass'],
    ['registry_signature_1', 'pass'], ['registry_signature_2', 'fail'],
  ]);
  assert.match(result.checks[4]?.detail ?? '', /not available/);
  const withKey = verifyReceipt(forged, { registryKeys: [registry.publicJwk, stranger.publicJwk] });
  assert.equal(withKey.ok, false);
  assert.equal(withKey.checks[4]?.detail, 'registry signature does not verify');
});

test('prepending a junk agent entry does not pass because a later valid entry exists', () => {
  const receipt = registered();
  const junk = { role: 'agent', signer: agentIdOf(stranger.publicJwk), alg: 'Ed25519', key: bareJwk(stranger.publicJwk), signature: 'A'.repeat(86) };
  const forged: Receipt = { ...receipt, signatures: [junk, ...receipt.signatures] };
  const result = verifyReceipt(forged, { registryKeys: [registry.publicJwk] });
  assert.equal(result.ok, false);
  assert.equal(statuses(forged).agent_signature, 'fail');
  assert.equal(statuses(forged).agent_identity, 'fail');
  assert.match(result.checks[1]?.detail ?? '', /2 agent signatures/);
});

test('two entries with role agent, both individually valid, is a failure', () => {
  const signed = agentSign(core(), agent.privateJwk);
  const twice: Receipt = { ...signed, signatures: [...signed.signatures, ...signed.signatures] };
  const s = statuses(twice);
  assert.equal(s.agent_signature, 'fail');
  assert.equal(s.agent_identity, 'fail');
  assert.equal(verifyReceipt(twice).ok, false);
});

test('two genuine registry entries both verify and are both reported', () => {
  const receipt = countersign(registered(), 12, second.privateJwk);
  const result = verifyReceipt(receipt, { registryKeys: [registry.publicJwk, second.publicJwk] });
  assert.equal(result.ok, true);
  assert.deepEqual(result.checks.map((c) => [c.name, c.status]), [
    ['integrity', 'pass'], ['agent_signature', 'pass'], ['agent_identity', 'pass'],
    ['registry_signature_1', 'pass'], ['registry_signature_2', 'pass'],
  ]);
  assert.match(result.checks[3]?.detail ?? '', /sequence #184/);
  assert.match(result.checks[4]?.detail ?? '', /sequence #12/);
});

test('reordering a valid receipt signature array does not change the verdict', () => {
  const receipt = registered();
  const reordered: Receipt = { ...receipt, signatures: [...receipt.signatures].reverse() };
  const before = verifyReceipt(receipt, { registryKeys: [registry.publicJwk] });
  const after = verifyReceipt(reordered, { registryKeys: [registry.publicJwk] });
  assert.equal(after.ok, true);
  assert.deepEqual(after.checks, before.checks);
});

test('verifyReceipt returns a result for hostile input instead of throwing', () => {
  const valid = registered();
  const withSignatures = (signatures: unknown) => ({ ...valid, signatures }) as unknown as Receipt;
  const cases: Array<[string, Receipt]> = [
    ['null', null as unknown as Receipt],
    ['undefined', undefined as unknown as Receipt],
    ['a number', 42 as unknown as Receipt],
    ['a string', 'receipt' as unknown as Receipt],
    ['an array', [] as unknown as Receipt],
    ['an empty object', {} as unknown as Receipt],
    ['signatures deleted', coreWithout('signatures') as unknown as Receipt],
    ['signatures null', withSignatures(null)],
    ['signatures an object', withSignatures({})],
    ['signatures holding null', withSignatures([null])],
    ['signatures holding a number', withSignatures([42])],
    ['an entry with no role', withSignatures([{ signer: AGENT_ID, alg: 'Ed25519', signature: 'A'.repeat(86) }])],
  ];
  for (const [label, value] of cases) {
    const result = verifyReceipt(value, { registryKeys: [registry.publicJwk] });
    assert.equal(result.ok, false, label);
    assert.ok(result.checks.length > 0, label);
  }
  const nulled = verifyReceipt(withSignatures([null, ...valid.signatures]), { registryKeys: [registry.publicJwk] });
  assert.equal(nulled.ok, false);
  assert.ok(nulled.checks.some((c) => c.status === 'fail' && /not an object/.test(c.detail)), 'the null entry is a failing check');
  const roleless = verifyReceipt(withSignatures([{ signer: AGENT_ID }, ...valid.signatures]), { registryKeys: [registry.publicJwk] });
  assert.equal(roleless.ok, false);
  assert.ok(roleless.checks.some((c) => c.status === 'fail' && /role/.test(c.detail)), 'the roleless entry is a failing check');
});

test('a receipt that is not structurally conformant fails integrity, naming the member', () => {
  assert.equal(receiptShapeProblem(registered()), undefined);
  const cases: Array<[string, Receipt, RegExp]> = [
    ['no action', forge(coreWithout('action')), /action/],
    ['inputs is an object', forge({ ...core(), inputs: {} }), /inputs/],
    ['policy is a string', forge({ ...core(), policy: 'default' }), /policy/],
    ['id is not a digest', { ...forge({ ...core() }), id: 'receipt-1' } as Receipt, /id/],
  ];
  for (const [label, receipt, member] of cases) {
    const result = verifyReceipt(receipt, { registryKeys: [registry.publicJwk] });
    assert.equal(result.ok, false, label);
    assert.deepEqual(result.checks.map((c) => [c.name, c.status]), [
      ['integrity', 'fail'], ['agent_signature', 'fail'], ['agent_identity', 'fail'],
    ], label);
    assert.match(result.checks[0]?.detail ?? '', member, label);
  }
});
