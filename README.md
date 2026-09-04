# AGIE Runtime

The open-source half of AGIE. This repository holds the receipt library, the
offline verifier, and the protocol between AGIE Cloud and a runtime node.

Receipts are the proof that an agent did a piece of work: who acted, on which
machine, under which mission, with which approval. A receipt is signed twice,
first by the node that did the work, then by AGIE Cloud. Anyone can verify a
receipt with `agie verify` and nothing else.

## Layout

- `packages/receipts`: canonical JSON, keys, signatures, receipts, chains, Merkle roots
- `packages/cli`: the `agie` command line, starting with `agie verify`
- `docs/protocol`: the cloud-to-runtime protocol

## Develop

Requires Node 22.18 or newer and pnpm 10.

```
pnpm install
pnpm test
pnpm typecheck
```

Everything runs from TypeScript source with Node's native type stripping.
There is no build step and there are no runtime dependencies.

## Verify a receipt

```
agie verify receipt.json --jwks agie-jwks.json
agie verify receipt.json --jwks agie-jwks.json --chain mission-482.json --root 2026-09-04.json --proof proof.json
```

Exit code 0 means every check passed, 1 means a check failed, 2 means the
inputs could not be read. The protocol, including where the JWKS and daily
roots are published, is in `docs/protocol/README.md`.
