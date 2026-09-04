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
