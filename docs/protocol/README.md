# AGE Protocol v0.1

AGE is the trust and verification layer for work performed by AI agents.

This document specifies what an AGE receipt is, how an agent signs it, how a
registry countersigns it, how daily roots are built, and how anyone verifies
all of it without trusting AGE. It is normative. The reference implementation
is `@ageprotocol/receipts`, the reference verifier is `agectl verify`, a second
independent implementation is `verify.py` beside this file, and the interop
vector every implementation must reproduce is `golden-v0.1.json`.

## Principles

- **The agent is the primary signer.** A receipt says "this work record was
  signed by this agent identity", not "this computer produced it".
- **Identities are derived from keys, never issued.** `age:agent:<thumbprint>`
  is computed on the agent's own machine, with no network and no account. A
  registry recognises an identity from a sequence number onward; it cannot
  mint one, and it cannot take one away.
- **Everything a verifier needs is public**: this specification, the canonical
  form, the signature format, the registry's keys, and the verifier itself. A
  receipt still verifies if the registry disappears.
- **Signature roles are open.** Version 0.1 defines `agent` and `registry`. A
  verifier reports roles it does not know and never fails on them, so
  `runtime`, `hardware`, and `organization` can be added without breaking
  verifiers written against this version.
- **Roots are published, not immutable.** A daily root is a signed statement
  about a range of sequences. Witnessing and anchoring are possible later and
  are not part of v0.1. Nothing here requires a blockchain.

## Primitives

- Canonical JSON: RFC 8785 (JCS).
- Digests: SHA-256, written as `sha256:` followed by 64 lowercase hex characters.
- Keys: Ed25519 as JWK, `{ "kty": "OKP", "crv": "Ed25519", "x": "..." }`.
- Thumbprints: RFC 7638 over `{ "crv", "kty", "x" }`, base64url.
- Signatures: Ed25519 over canonical bytes, base64url without padding, 86 characters.
- Trees: RFC 6962 (RFC 9162), leaf prefix `0x00`, node prefix `0x01`.

## Identifiers

| Kind | Form |
|---|---|
| Agent | `age:agent:` and the RFC 7638 thumbprint of the agent's public key |
| Registry | `age:registry:` and the thumbprint of the registry's public key |
| Receipt | `sha256:` and the hex SHA-256 of the canonical receipt core |

## Domain separation

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

## The receipt

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

## Canonicalization

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

## Identity

An agent identity is `age:agent:` followed by the RFC 7638 JWK thumbprint of
its Ed25519 public key. A registry identity is `age:registry:` followed by the
same thumbprint of its key. Identities are therefore *derived*, never issued:
`agectl identity init` mints one locally with no network and no account, and a
registry can only recognise a key it is shown, never grant one.

Public keys are looked up by computed thumbprint, never by a `kid` label, so a
mislabelled key cannot bind an identity to a key that does not hash to it.

## Signatures

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

## Registry attestation

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

## Daily roots

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

## Verification

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

## Check this specification against a second implementation

`verify.py` beside this file is a complete AGE v0.1 verifier in about two
hundred lines of Python: another language, another crypto library, its own
canonicalizer, written from this document rather than from the reference
code. It agrees with the reference on every value of the interop vector, and
a test in `packages/receipts` re-checks that agreement.

```
python3 verify.py golden-v0.1.json
```

It is there to be read and doubted. A specification is interoperable when a
second implementation agrees with the first, not when its author says so, and
a receipt is only worth something if verifying it never requires trusting the
party that issued it.

## Registry API

A registry is a convenience, not an authority: the receipt and root formats
above are the contract, and the transport is free to differ. The reference
registry is open source and ships in a later release with `POST /agents`,
`GET /agents/:id`, `POST /receipts`, `GET /receipts/:id`, `GET /receipts`,
`GET /roots/:date`, `GET /.well-known/age.json`, and
`GET /.well-known/age-jwks.json`.

## Interop vector

`golden-v0.1.json` fixes an agent key and a registry key, both test keys that
protect nothing, and three receipts registered at sequences 184, 185, and 186.
For each it carries the core, the exact canonical bytes the agent signed, the
signed and registered forms, the registry attestation and its signing bytes,
and an inclusion proof. It also carries the signed daily root over all three.

Three leaves means every proof has a non-empty path and one carries an
internal node hash, so an implementation that omits the RFC 6962 domain
prefixes cannot reproduce it. Receipt 185 pins UTF-16 key ordering with a
supplementary-plane key. Receipt 186 pins the number rules. Ed25519 is
deterministic, so a conforming implementation reproduces every id and
signature byte for byte.
