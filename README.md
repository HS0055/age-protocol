# AGE Protocol

**AGE is the trust and verification layer for work performed by AI agents.**

An agent does something real: it changes a repository, runs a job, spends
money. AGE turns that into a **receipt**, a small signed record of what
happened, that anyone can verify without asking us.

## Verify a receipt

Nothing to install and no account:

```
curl -sO https://raw.githubusercontent.com/HS0055/age-protocol/main/docs/protocol/receipt.json
curl -sO https://raw.githubusercontent.com/HS0055/age-protocol/main/docs/protocol/age-jwks.json
npx @ageprotocol/cli verify receipt.json --jwks age-jwks.json
```

That receipt is committed in `docs/protocol/`, so there is something to run
this against before you have made one of your own.

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

## Emit a receipt for real work

Commit something, then:

```
npx @ageprotocol/cli emit --task "Fix the login redirect" --out receipt.json
npx @ageprotocol/cli verify receipt.json --repo .
```

`emit` reads the commit and signs a receipt describing it with the identity on
this machine. Every value in it comes from git and nothing is estimated: the
commit, its subject, its parents, when it was authored and when it was
committed, and the files, insertions and deletions it changed. A prompt passed
with `--prompt` is recorded as a digest, never as text.

It refuses rather than guessing. In a shallow clone, which is what CI checkouts
are by default, git cannot see the commit's parent and would report every file
in the repository as changed, so `emit` stops and says to fetch the rest.

**Given `--repo`, `verify` recomputes those claims instead of repeating them.**
A receipt that says a commit changed 42 files, checked against the repository
that shows it changed one, fails:

```
✗ Commit binding         the repository disagrees: files_changed says 42, repository says 1
FAILED
```

Without `--repo` the counts are reported as unchecked, because saying so is the
difference between reporting a claim and confirming it.

An emitted receipt is unregistered until a registry countersigns it, which is
valid: the registry check reads as skipped rather than failed. The open
registry service is next.

## Don't trust AGE. Verify AGE.

A trust layer nobody can check is just a database with good manners. So:

- **The specification is public and complete.** `docs/protocol/README.md` is
  everything needed to write your own verifier.
- **There is already a second implementation.** `docs/protocol/verify.py` is a
  complete verifier in about three hundred and fifty lines of Python, written
  from the specification and sharing no code with this one. CI runs ten
  differential tests against it on every push. Eight are named cases, each
  recording a rule that once existed in only one of the two implementations.
  Two are generated from a fixed seed: a hundred and twenty mutated receipts,
  and every combination of fifteen malformed root documents with thirteen
  malformed proofs. Agreeing on valid receipts is easy. Those tests exist
  because agreeing on the invalid ones is the hard part, and it is where this
  verifier was wrong nine separate times.
- **The interop vector is committed.** `docs/protocol/golden-v0.1.json` fixes
  the keys and the content, so any implementation can prove it reproduces the
  exact bytes.
- **Nothing here depends on us existing.** A receipt, a public key, and a
  verifier are enough, forever.

Try to break it. Verifying a receipt should never require trusting the party
that issued it, including us.

## Layout

- `packages/receipts`: canonical JSON, keys, signatures, receipts, Merkle roots
- `packages/cli`: `agectl`, with `verify`, `identity`, and `emit`
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
second implementation; without it those ten tests skip rather than fail. CI
installs it, so they always run there.

## Status

**AGE Protocol v0.1 is frozen.** The receipt, attestation, and root formats
are fixed, and the interop vector enforces it: changing any of them breaks the
vector, on purpose.

Six review rounds gated the freeze. The last one ran 142,336 generated cases
across three corpora and found zero disagreements between the two
implementations, zero exceptions, and zero false positives, with every receipt
that verified also accepted by a third verifier written independently from the
specification. Earlier rounds found and closed a forged registry entry that
read as verified, a Merkle walk that truncated above 2^32 leaves, unbounded
recursion, a publish path that shipped no code, and eleven rules that existed
in one implementation and not the other.

Published on npm as `@ageprotocol/receipts` and `@ageprotocol/cli`. Every
release is built and published by the workflow in this repository, which runs
the full suite and verifies a receipt from the packed tarballs before
publishing. From 0.1.1 both packages carry an npm provenance attestation tying
them to that workflow run; 0.1.0 does not, because `pnpm publish` ignored the
flag without a word.

The registry service is next.

## License

MIT.
