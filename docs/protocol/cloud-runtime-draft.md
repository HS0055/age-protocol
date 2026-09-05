# AGIE Cloud to Runtime Protocol, v0 (draft)

**Parked.** This is a design sketch for the contract between AGIE Cloud and an
AGIE Runtime node. It is not implemented and it will change. It is kept here
because the runtime bridge is a real part of the plan and this is what was
worked out; do not read it as a description of anything that exists.

For the protocol that is implemented and frozen, see `README.md` beside this
file: AGE Protocol v0.1.

## Principles

- The runtime only dials out. It never listens on a public port.
- Every runtime request is signed with the node key (RFC 9449 DPoP proof
  with an EdDSA JWK). The cloud stores public keys only.
- Source code never crosses the wire. Logs, metadata, and hashes do.
- Every meaningful event becomes a receipt signed by the agent and
  countersigned by a registry, in the form specified by AGE Protocol v0.1
  (`README.md` beside this file).

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
  AGE Protocol v0.1 form. The registry
  countersigns it with a sequence and returns the full receipt. The agent
  signature covers the core alone, so it still verifies afterwards.
- `POST /api/runtime/jobs/:id/result` posts
  `{ "exit_code", "session_id", "usage", "changed_files": [{ "path_hash", "sha256" }], "work_products": [] }`.

## Gates

When the runtime's PreToolUse hook intercepts a gated action it posts
`POST /api/runtime/gates` with `{ "run_id", "class", "summary" }` and receives
`{ "decision": "approved" | "rejected" | "pending", "approval_id" }`. While
pending, the runtime polls `GET /api/runtime/gates/:approval_id` every 5 seconds.
