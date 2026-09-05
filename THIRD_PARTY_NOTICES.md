# Third-party notices

This repository contains no vendored third-party code. Both packages have zero
third-party runtime dependencies: everything cryptographic comes from Node's
own `node:crypto`. The only third-party code involved in development is the
TypeScript compiler and Node type definitions, declared in `package.json`.

The projects below are related to AGE but are **not** included in this
repository or in the published packages. They are listed so their licenses are
acknowledged ahead of any future use, not because their code is here.

| Project | Author | License | Relationship |
|---|---|---|---|
| Orca | Stably AI, https://github.com/stablyai/orca | MIT | candidate runtime engine, not vendored |
| Paperclip | Paperclip Labs, https://github.com/paperclipai/paperclip | MIT | used by AGIE Cloud in a separate repository, not here |
| Alien Agent ID | Alien, https://github.com/alien-id/agent-id | see upstream | a compatible agent identity model, no code used |

If any of that code is ever vendored, its license will be reproduced in full
beside it and this file will say where.

## Standards implemented

- RFC 8785, JSON Canonicalization Scheme
- RFC 8037 and RFC 7638, Ed25519 JWK and JWK thumbprints
- RFC 6962, Merkle tree hashing with leaf and node domain prefixes
- RFC 9162, inclusion proof verification

`docs/protocol/verify.py` uses the Python `cryptography` package
(Apache 2.0 or BSD 3-Clause) for Ed25519. It is a development and
documentation aid and is not part of either published package.
