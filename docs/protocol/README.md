# AGE Protocol v0.1, and the AGIE Cloud to Runtime draft

This document has two halves. **Receipts**, from that heading onward, is AGE
Protocol v0.1: the receipt format, identity, canonicalization, signatures,
daily roots, and verification. It is implemented, frozen by the interop vector
beside this file, and normative.

Everything before it is the draft contract between AGIE Cloud and an AGIE
Runtime node. That half is **parked**, not implemented, and will change. It is
published here, in the open runtime repository, so anyone can build a runtime
or a client. Breaking changes are expected until v1 is tagged.

## Principles

- The runtime only dials out. It never listens on a public port.
- Every runtime request is signed with the node key (RFC 9449 DPoP proof
  with an EdDSA JWK). The cloud stores public keys only.
- Source code never crosses the wire. Logs, metadata, and hashes do.
- Every meaningful event becomes a receipt signed by the agent and
  countersigned by a registry (see Receipts below).

## Identities

| Entity | Key | Id |
|---|---|---|
| Node | Ed25519, generated on the machine | RFC 7638 thumbprint (`jkt`) |
| Agent | Ed25519, generated on the machine (Alien Agent ID format) | `jkt` |
| Cloud | Ed25519, published in JWKS | `jkt` |

Cloud discovery: `GET https://<cloud>/.well-known/agie.json` returns

```json
{
  "version": 0,
  "jwks_uri": "https://<cloud>/.well-known/agie-jwks.json",
  "roots_uri": "https://<cloud>/.well-known/agie-roots/",
  "roots_mirror": "https://github.com/<org>/<repo>",
  "api": "https://<cloud>/api/runtime"
}
```

The JWKS document is `{ "keys": [PublicJwk] }`. Each key carries a `kid` equal
to its thumbprint, but a verifier must not trust that label: it identifies a
key by recomputing the RFC 7638 thumbprint of the key material itself, so a
JWKS with wrong or missing `kid` values changes nothing.

## Link flow

1. `agie runtime link` generates the node key and prints a one-time code.
2. The user opens `https://<cloud>/link/<code>` while signed in and chooses an org.
3. The runtime polls `POST /api/runtime/link/exchange` with the code and its
   public key until the cloud returns a node credential bound to the key.
4. From then on every request carries `Authorization: DPoP <credential>` and
   a `DPoP` proof JWT signed by the node key.

## Heartbeat

`POST /api/runtime/heartbeat` every 30 seconds with
`{ "runtime_version", "capabilities": { "cpu_cores", "ram_gb", "gpu", "disk_gb", "os", "arch", "agent_clis": [], "max_sessions" } }`.

## Jobs

- `GET /api/runtime/jobs?wait=25` long-polls for up to 25 seconds and returns
  at most one job: `{ "id", "run_id", "adapter", "repo": { "url", "ref" }, "prompt_bundle_url", "policy": { ... } }`.
- `POST /api/runtime/jobs/:id/claim` claims it atomically; a second claim returns 409.
- `POST /api/runtime/jobs/:id/logs` appends `{ "stream": "stdout" | "stderr", "seq", "chunk" }`.
- `POST /api/runtime/jobs/:id/events` posts an agent-signed receipt for
  `session.started`, `tool.gated`, `git.commit`, `session.finished`, in the
  AGE Protocol v0.1 form specified under Receipts below. The registry
  countersigns it with a sequence and returns the full receipt. The agent
  signature covers the core alone, so it still verifies afterwards.
- `POST /api/runtime/jobs/:id/result` posts
  `{ "exit_code", "session_id", "usage", "changed_files": [{ "path_hash", "sha256" }], "work_products": [] }`.

## Gates

When the runtime's PreToolUse hook intercepts a gated action it posts
`POST /api/runtime/gates` with `{ "run_id", "class", "summary" }` and receives
`{ "decision": "approved" | "rejected" | "pending", "approval_id" }`. While
pending, the runtime polls `GET /api/runtime/gates/:approval_id` every 5 seconds.

## Receipts

Receipts follow **AGE Protocol v0.1**, specified below. The implementation in
`packages/receipts` is normative, and `golden-v0.1.json` next to this file is
the interop vector: fixed keys, fixed content, and the exact bytes every value
below must have. Ed25519 is deterministic, so a conforming implementation
reproduces it byte for byte. The vector carries three registered receipts
forming a three-leaf Merkle tree, so no inclusion proof has an empty path.

### Domain separation

Every signed AGE document names its own kind with exactly one `*_version`
member, and that member is part of the bytes the signature covers. A receipt
core carries `receipt_version`, a registry attestation carries
`attestation_version`, and a daily root document carries `root_version`. The
three member names are distinct and their values are distinct, so a signature
made over one kind of document cannot be read as a signature over another.

A verifier must reject a document whose expected version member is absent or
holds a version it does not implement, and must not accept a document that
carries a version member it did not ask for. The three member sets must never
be merged into one structure, and no later version may reuse a `*_version`
member name for a different kind of document. Domain separation in AGE rests
on these member names alone; there is no separate type tag to fall back on.

### The receipt

A receipt has three parts. The **core** is what the agent asserts. The **id**
is derived from it. The **signatures** are what other parties say about it.

```json
{
  "receipt_version": "0.1",
  "agent": "age:agent:<thumbprint>",
  "timestamp": "2026-09-05T03:20:00Z",
  "task": { "id": "tsk_91", "description": "Fix authentication bug" },
  "action": { "type": "git.commit", "commit": "<40 hex>", "files_changed": 3 },
  "inputs": [{ "kind": "prompt", "digest": "sha256:<64 hex>" }],
  "outputs": [{ "kind": "commit", "digest": "sha256:<64 hex>", "ref": "<40 hex>" }],
  "environment": { "runtime": "claude-code/2.1.0" },
  "policy": { "id": "default", "decision": "allowed" },

  "id": "sha256:<64 hex>",
  "signatures": [ ... ]
}
```

`task`, `action`, `environment`, and `policy` are open-ended, and so is each
entry of `inputs` and `outputs`. Every member an implementation does not
recognise is still canonicalized and still signed, so nothing can be smuggled
into a receipt outside the signature. `policy` may be `null`. `action.type`
must be a string; each artifact must carry a string `kind` and `digest`.

`id` is `sha256:` followed by the lowercase hex SHA-256 of the canonical bytes
of the core, that is, of the receipt with `id` and `signatures` removed.

### Canonicalization

Canonical JSON is RFC 8785 (JCS): object members sorted by key, no
insignificant whitespace, and ES6 number and string serialization. Two rules
deserve emphasis because they are where independent implementations diverge.

**Keys sort by UTF-16 code unit, not by code point.** A supplementary-plane
key such as U+1F527 sorts *before* U+FFFF. A language that sorts by code point
produces different bytes and therefore a different signature. Receipt 185 of
the interop vector pins this.

**Numbers in a core must be integers with an absolute value no greater than
9007199254740991.** RFC 8785 requires ES6 number serialization, which many
built-in JSON serializers do not reproduce: an integral float prints as
`100.0` in some languages, and the thresholds and zero padding of exponential
notation differ (`1e20`, `1e-6`, and `1e-7` all disagree between JavaScript
and Python). Every safe integer, by contrast, serializes identically
everywhere. Restricting the core to safe integers means an implementer who
reaches for a built-in serializer, which everyone does first, gets byte-correct
output. A quantity that is not a whole number belongs in a string, or in a
smaller unit: milliseconds, cents, basis points. A signer must refuse a core
that breaks this rule, and a verifier must fail such a receipt.

Signatures are Ed25519, encoded base64url without padding, over the canonical
bytes of the document being signed.

### Identity

An agent identity is `age:agent:` followed by the RFC 7638 JWK thumbprint of
its Ed25519 public key. A registry identity is `age:registry:` followed by the
same thumbprint of its key. Identities are therefore *derived*, never issued:
`agectl identity init` mints one locally with no network and no account, and a
registry can only recognise a key it is shown, never grant one.

Public keys are looked up by computed thumbprint, never by a `kid` label, so a
mislabelled key cannot bind an identity to a key that does not hash to it.

### Signatures

`signatures` is an array of entries, each naming a `role`. Order carries no
meaning, and every entry is judged or reported by name, so no entry can hide
behind another that shares its role.

| role | count in v0.1 | what it attests |
| --- | --- | --- |
| `agent` | exactly one, required | the content of the core |
| `registry` | zero or more | that this receipt id was registered at a sequence and time |
| anything else | any | reported, never judged by a v0.1 verifier |

The agent entry embeds the public key it was signed with:

```json
{ "role": "agent", "signer": "age:agent:<thumbprint>", "alg": "Ed25519",
  "key": { "kty": "OKP", "crv": "Ed25519", "x": "<base64url>" },
  "signature": "<base64url>" }
```

The embedded key carries exactly `kty`, `crv`, and `x`, with `kty` `OKP` and
`crv` `Ed25519`, and nothing else. This is not cosmetic: the key sits outside
the core, so two receipts whose embedded keys differ share one `id`, and a
proof is matched by id while a Merkle leaf is the full receipt bytes. A
verifier must reject an embedded key carrying any other member.

The receipt is self-certifying: `age:agent:` plus the thumbprint of the
embedded key must equal both the entry's `signer` and the core's `agent`, and
the core's `agent` is inside the signed bytes.

`alg` must be `Ed25519` on an `agent` or `registry` entry. Roles a verifier
does not know are reported and skipped, never judged, so `runtime`,
`hardware`, and `organization` signers can be added later without breaking
verifiers written against v0.1.

### Registry attestation

A registry does not re-sign content. It signs a short statement about a
receipt id:

```json
{ "attestation_version": "0.1", "receipt": "sha256:<64 hex>",
  "agent": "age:agent:<thumbprint>", "sequence": 184,
  "registered_at": "2026-09-05T03:20:04Z", "registry": "age:registry:<thumbprint>" }
```

The signature over the canonical bytes of exactly those six members becomes a
`registry` entry carrying `role`, `signer`, `alg`, `sequence`,
`registered_at`, an optional `jwks` hint URL, and `signature`.

Because the registry vouches only for sequence and time, a tampered receipt
can still carry a valid registry signature: what breaks is the link between
the id and the content, which the integrity and agent checks catch. Keeping
the claims separate is deliberate.

### Daily roots

A registry publishes a signed document per UTC day over a contiguous run of
its own sequences:

```json
{ "root_version": "0.1", "registry": "age:registry:<thumbprint>",
  "date": "2026-09-05", "sequence_start": 184, "sequence_end": 186,
  "root": "sha256:<64 hex>", "signature": "<base64url>" }
```

The tree is RFC 6962 over the canonical bytes of each receipt, ordered by that
registry's sequence, with the RFC 6962 domain prefixes (`0x00` for a leaf,
`0x01` for a node). The signature covers the canonical bytes of the document
without its `signature`. Sequences must be contiguous and unique: a signer
must refuse to build a root over a range with a gap or a duplicate, because
every inclusion proof for such a range would fail.

An inclusion proof is `{ "sequence", "index", "size", "path" }` per RFC 9162.
Verifying inclusion requires the document's `root_version` to be `0.1` and the
receipt to carry a registry entry from the registry the document names.
Inclusion is not a substitute for checking the document's signature; both are
required.

These roots are published, not immutable. Witnessing and anchoring are
possible later and are not part of v0.1.

### Verification

A verifier reports every check and reaches a verdict only from them. A
receipt is verified when no check failed; a skipped check is not a failure.

| check | fails when |
| --- | --- |
| Receipt integrity | the core is malformed, carries a number outside the safe integer range, or its hash is not `id` |
| Agent signature | there is not exactly one agent entry, its embedded key is wrong, `alg` is not `Ed25519`, or the signature does not verify |
| Agent identity | the embedded key's thumbprint does not equal both `signer` and the core's `agent` |
| Registry signature | any registry entry fails to verify, or names a key the verifier cannot obtain |
| Commit binding | `action.type` is `git.commit` and the commit is not a 40-hex id listed in `outputs` |
| Root inclusion | a root and proof were supplied and the receipt is not in that tree |

A receipt with no registry entry skips the registry check and can still be
verified: a receipt is valid before it is registered. A check for a role the
verifier does not know is always reported as skipped.

Every one of these must answer for hostile input rather than throwing. A
verifier handed `null`, a primitive, or a `signatures` array holding `null`
returns a verdict, never an exception.
