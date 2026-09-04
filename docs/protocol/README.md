# AGIE Cloud to Runtime Protocol, v0 (draft)

This document is the contract between AGIE Cloud and an AGIE Runtime node.
It is published here, in the open runtime repository, so anyone can build a
runtime or a client. Version 0 is a draft; breaking changes are expected
until v1 is tagged.

## Principles

- The runtime only dials out. It never listens on a public port.
- Every runtime request is signed with the node key (RFC 9449 DPoP proof
  with an EdDSA JWK). The cloud stores public keys only.
- Source code never crosses the wire. Logs, metadata, and hashes do.
- Every meaningful event becomes a receipt signed by the node and
  countersigned by the cloud (see Receipts below).

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
- `POST /api/runtime/jobs/:id/events` posts a node-signed receipt envelope for
  `session.started`, `tool.gated`, `git.commit`, `session.finished`. The cloud
  assigns `id`, `seq`, and `prev`, countersigns, stores it, and returns the
  full receipt. The node signature covers the envelope only, so it still
  verifies after the cloud has filled those three in.
- `POST /api/runtime/jobs/:id/result` posts
  `{ "exit_code", "session_id", "usage", "changed_files": [{ "path_hash", "sha256" }], "work_products": [] }`.

## Gates

When the runtime's PreToolUse hook intercepts a gated action it posts
`POST /api/runtime/gates` with `{ "run_id", "class", "summary" }` and receives
`{ "decision": "approved" | "rejected" | "pending", "approval_id" }`. While
pending, the runtime polls `GET /api/runtime/gates/:approval_id` every 5 seconds.

## Receipts

Receipt schema, signing inputs, chain rules, and Merkle roots are implemented
in `packages/receipts` and are normative. `golden-v0.json` next to this file is
the interop vector: fixed keys, fixed events, and the exact bytes every value
below must have. Ed25519 is deterministic, so a conforming implementation
reproduces it byte for byte.

### Envelope and body

The node builds and signs an envelope. The cloud assigns three members and
countersigns. Nothing else is added.

| Member | Written by | In the node signing input |
|---|---|---|
| `typ`, `v`, `ts`, `company`, `mission`, `task`, `run` | node | yes |
| `actor`, `node`, `cloud`, `action`, `inputs`, `outputs`, `gate` | node | yes |
| `id`, `seq`, `prev` | cloud | no |
| `node_sig` | node | no |
| `cloud_sig` | cloud | no |

- canonical form: RFC 8785 (JCS). A member named `__proto__` is an ordinary
  member and is canonicalized like any other.
- `typ` is `"agie/receipt/1"` for a receipt and `"agie/root/1"` for a daily
  root document. It is the first line of defence against replaying a signature
  over one structure as a signature over another, and a verifier rejects a
  document whose `typ` is missing or unexpected.
- node signature: Ed25519 over the canonical envelope, which is the receipt
  without `id`, `seq`, `prev`, `node_sig`, and `cloud_sig`.
- cloud signature: Ed25519 over the canonical body including `id`, `seq`,
  `prev`, and `node_sig` (null when the cloud issued the receipt alone),
  without `cloud_sig`.
- signatures are base64url with no padding, 86 characters. No other encoding
  of the same bytes is accepted.
- receipt hash: SHA-256 hex over the canonical full receipt, both signatures
  included.
- chain: `prev` is the hash of the previous receipt in the same mission; `seq`
  is global and strictly increasing.

### Node public keys

`node` is `null` for a cloud-only receipt, otherwise
`{ "jkt": string, "jwk"?: PublicJwk }`. The optional `jwk` lets a receipt carry
the key that signed it, so a verifier needs nothing but the receipt and the
cloud JWKS. It is self-certifying and is accepted only when its RFC 7638
thumbprint equals `jkt`, which both signatures cover. Without it, the verifier
takes the node key from the JWKS it was given, again matched by thumbprint.

### Daily roots

The daily tree is an RFC 6962 (RFC 9162) Merkle tree whose leaves are the
canonical bytes of every receipt issued that UTC day, in ascending `seq` order.
The root document is

```json
{ "typ": "agie/root/1", "date": "2026-09-04", "size": 2, "root": "<hex>", "cloud": { "jkt": "<jkt>" }, "sig": "<base64url>" }
```

where `sig` signs the canonical bytes of `{ typ, date, size, root }`.

Daily roots are published at
`https://<cloud>/.well-known/agie-roots/<YYYY-MM-DD>.json` and mirrored to the
public git repository named by `roots_mirror` in the cloud's
`/.well-known/agie.json`, so a root the cloud later changes leaves a trace
outside the cloud.

An inclusion proof is

```json
{ "index": 1, "size": 2, "path": ["<64 hex characters>", "..."] }
```

`index` is the position of the receipt in that day's tree, `size` is the tree
size the proof was made against and must equal the `size` in the root
document, and `path` holds the audit path from the leaf upwards.

`agie verify` checks all of the above offline.
