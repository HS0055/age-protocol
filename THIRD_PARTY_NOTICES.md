# Third-party notices

AGIE Runtime builds on open-source work. Each upstream keeps its own license,
reproduced in full in the directory where its code is vendored.

| Upstream | Author | License | Where |
|---|---|---|---|
| Orca | Stably AI, https://github.com/stablyai/orca | MIT | vendored in a later release as the runtime engine (`orcad`) and workspace web client |
| Paperclip | Paperclip Labs, https://github.com/paperclipai/paperclip | MIT | used by AGIE Cloud, not vendored here |
| Alien Agent ID | Alien, https://github.com/alien-id/agent-id | see upstream | identity primitives, vendored in a later release |

Standards implemented: RFC 8785 (JSON Canonicalization Scheme), RFC 8037 and
RFC 7638 (Ed25519 JWK and thumbprints), RFC 6962 (Merkle tree hashing).
