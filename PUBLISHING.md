# Publishing

Nothing here has been published. There is no git remote, the npm scope
`@ageprotocol` is unclaimed, and no registry is deployed. This file is the
checklist for the day that changes, written down because two of these steps
are invisible until they fail.

## Before the first publish

1. **Create the public repository and push.** Then add `repository` to both
   package manifests:

   ```json
   "repository": { "type": "git", "url": "git+https://github.com/<org>/<repo>.git" }
   ```

   npm provenance requires it, and without it the package page has no link to
   the source. It is deliberately absent today rather than pointing at a
   repository that does not exist.

2. **Claim the npm scope** `@ageprotocol`. Both packages already carry
   `"publishConfig": { "access": "public" }`; a scoped package publishes
   restricted by default and the first publish is otherwise refused.

3. **Check the version.** Both packages are `0.1.0`. A version cannot be
   republished once it is taken.

## Publishing

```
pnpm install && pnpm test
pnpm release
```

`pnpm release` builds both packages and publishes them in dependency order.
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
