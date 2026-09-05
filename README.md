# AGE Protocol

**AGE is the trust and verification layer for work performed by AI agents.**

An agent does something real: it changes a repository, runs a job, spends
money. AGE turns that into a **receipt**, a small signed record of what
happened, that anyone can verify without asking us.

## Verify a receipt

Not yet on npm. Today, from a clone:

```
pnpm install && pnpm build
node packages/cli/bin/agectl.mjs verify docs/protocol/receipt.json \
  --jwks docs/protocol/age-jwks.json
```

`docs/protocol/receipt.json` is a real receipt, committed so there is something
to run this against before you have made one of your own.

On publish this becomes the same command with nothing installed and no
account:

```
npx @ageprotocol/cli verify receipt.json --jwks age-jwks.json
```

```
✓ Receipt integrity      sha256:9701e8874d3057f99ef7ecb5b3d0962682961227375e330c0cbf9ab606af7afb
✓ Agent signature        age:agent:Pjm7k4j6W3WHAu3006hy0sSTKX-LIm1YqDuWrh-u8rw
✓ Agent identity         key thumbprint matches id
✓ Registry signature     age:registry:kDVVYGHb-C_YZ6dXlhFiaBAYgMpRVL8kCZXPp07RloM  sequence #184
✓ Commit binding         8fa72c1 (3 files)
VERIFIED
```

Change one byte of that file and run it again:

```
✗ Receipt integrity      mismatch
✗ Agent signature        agent signature does not verify
✓ Agent identity         key thumbprint matches id
✓ Registry signature     age:registry:kDVVYGHb-C_YZ6dXlhFiaBAYgMpRVL8kCZXPp07RloM  sequence #184
✓ Commit binding         8fa72c1 (4 files)
FAILED
```

Every check is always reported, including the ones that still pass. The
registry signature survives because the registry only ever vouched for a
sequence and a time, and that statement is still true; what broke is the link
between the receipt's id and its content.

Exit status is 0 for verified, 1 for failed, 2 for a usage error, so this
works in a script as well as in a terminal.

## What each check means

| Check | The question it answers |
|---|---|
| Receipt integrity | Is this the content that was signed, unaltered? |
| Agent signature | Did the agent that claims this work actually sign it? |
| Agent identity | Is the embedded key the one the receipt names? |
| Registry signature | Did a registry record this receipt, at what position and when? |
| Commit binding | Does the git commit named inside actually match the outputs? |
| Root inclusion | Is this receipt in the registry's published daily tree? |

Editing content and recomputing the hash does not help an attacker: the agent
signature covers the content, and the attacker does not have the agent's key.
That is the difference between a receipt and a log.

### Where the registry key comes from

`--jwks` takes a file or an HTTPS URL. Without it, `agectl` falls back to the
`jwks` hint inside the receipt's registry entry, **which means a network
request to a host the receipt names**. Pass `--offline` to forbid that: the
registry check then fails rather than reaching out, because a claim you cannot
check is not a claim you should pass.

The example receipt's hint points at a registry that is not deployed yet, so
run it with `--jwks` as shown above.

The last check needs the registry's published daily tree, which is committed
here too:

```
node packages/cli/bin/agectl.mjs verify docs/protocol/receipt.json \
  --jwks docs/protocol/age-jwks.json \
  --root docs/protocol/root.json --proof docs/protocol/proof.json
```

## Create an agent identity

```
node packages/cli/bin/agectl.mjs identity init
```

```
Agent identity created
  id    age:agent:lqG6SsvQh3y8gCdqlwQlOu9S01maIV5j0uKhzQykvvk
  key   ~/.agectl/identity.json
```

That runs offline. The id is the RFC 7638 thumbprint of a keypair generated on
your machine, so the identity exists before any registry hears about it, and no
registry can revoke it. A registry can only say "I recognise this key from
sequence N onward". The private key never leaves the file, which is written
`0600`.

## Don't trust AGE. Verify AGE.

A trust layer nobody can check is just a database with good manners. So:

- **The specification is public and complete.** `docs/protocol/README.md` is
  everything needed to write your own verifier.
- **There is already a second implementation.** `docs/protocol/verify.py` is a
  complete verifier in about three hundred lines of Python, written from the
  specification and sharing no code with this one. CI runs four differential
  tests against it on every push: the whole vector, two tampered receipts, a
  padded signature, and seventeen malformed receipts that are each correctly
  signed and wrong in exactly one way. Agreeing on valid receipts is easy;
  those tests exist because agreeing on the invalid ones is the hard part, and
  is where the first version of that verifier was wrong.
- **The interop vector is committed.** `docs/protocol/golden-v0.1.json` fixes
  the keys and the content, so any implementation can prove it reproduces the
  exact bytes.
- **Nothing here depends on us existing.** A receipt, a public key, and a
  verifier are enough, forever.

Try to break it. Verifying a receipt should never require trusting the party
that issued it, including us.

## Layout

- `packages/receipts`: canonical JSON, keys, signatures, receipts, Merkle roots
- `packages/cli`: `agectl`, with `verify` and `identity`
- `docs/protocol`: the specification, the interop vector, and a second verifier

## Develop

Requires Node 22.18 or newer and pnpm 10.

```
pnpm install
pnpm test
pnpm typecheck
```

Tests run straight from TypeScript source using Node's native type stripping.
`pnpm build` emits the JavaScript that gets published. Neither package has a
third-party runtime dependency: `@ageprotocol/receipts` has none at all, and
the CLI depends only on it. Everything cryptographic comes from `node:crypto`.

The interop tests need `python3` with the `cryptography` package to run the
second implementation; without it those six tests skip rather than fail. CI
installs it, so they always run there.

## Status

AGE Protocol v0.1. The receipt, attestation, and root formats are frozen by
the interop vector: changing any of them breaks it, on purpose.

Not published yet, so every command above runs from a clone. The packages
build, pack, and verify a receipt from the tarball in an empty directory with
no network, and CI checks that on every push, so publishing is a decision
rather than a task. The registry service, `agectl emit`, and git integration
are next.

## License

MIT.
