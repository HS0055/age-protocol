# Publishing

Nothing here has been published. There is no git remote, the npm scope
`@ageprotocol` is unclaimed, and no registry is deployed. This file is the
checklist for the day that changes, written down because two of these steps
are invisible until they fail.

## Before the first publish

1. ~~**Create the public repository and push.**~~ Done:
   https://github.com/HS0055/age-protocol. Both manifests carry `repository`,
   `homepage`, and `bugs`, which npm provenance requires.

2. **Claim the npm scope** `@ageprotocol`. Both packages already carry
   `"publishConfig": { "access": "public" }`; a scoped package publishes
   restricted by default and the first publish is otherwise refused.

3. **Check the version.** Both packages are `0.1.0`. A version cannot be
   republished once it is taken.

## Publishing

**Publishing happens in CI, not on a laptop.** npm will only attest provenance
for a build it can witness, using an OIDC token that exists only inside a
supported CI run. A package published from a workstation cannot gain
provenance later.

So: create a GitHub release, and `.github/workflows/publish.yml` runs the full
suite, verifies a receipt from the packed tarballs, and then publishes both
packages with `--provenance --access public`. It needs one repository secret,
`NPM_TOKEN`, an npm automation token.

To rehearse without publishing, run the workflow manually with `dry_run` left
true.

`pnpm release` remains for a local publish without provenance. Prefer the
workflow.
Each package also builds on `prepack`, because `dist/` is gitignored: without
that hook the published tarball would contain a `bin` script importing a
`dist/index.js` that was never built. That failure is invisible to a local
`pnpm pack` run after a build, so verify it the way CI does:

```
git clone <repo> /tmp/check && cd /tmp/check && pnpm install
cd packages/cli && npm pack --dry-run     # expect 8 files, including dist/
cd ../receipts && npm pack --dry-run      # expect 15 files
```

## After publishing

Confirm the thing the README promises actually works, from a directory that
has never seen this repository:

```
cd $(mktemp -d)
npx @ageprotocol/cli verify receipt.json --jwks age-jwks.json
```

## Not yet true

The README shows `npx @ageprotocol/cli verify receipt.json --jwks ...` with an
explicit key file. The flagless form, where the verifier follows the `jwks`
hint inside the receipt, needs a deployed registry serving
`/.well-known/age-jwks.json`. Until then the hint in the example receipt names
a host that does not resolve.
