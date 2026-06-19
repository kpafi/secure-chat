# Vendored dependencies

These are **byte-identical** copies of files from npm, vendored so the no-build
browser client can load the post-quantum identity code over the same origin
(CSP `script-src 'self'`) without a bundler. The browser resolves the bare
`@noble/*` specifiers via the import map in `../index.html`.

Only the transitive closure actually reached from
`@noble/post-quantum/ml-dsa.js` is vendored (12 files), keeping the served and
auditable surface minimal.

Provenance (pinned in `../package.json` / `package-lock.json`):

| package               | version |
|-----------------------|---------|
| `@noble/post-quantum` | 0.6.1   |
| `@noble/hashes`       | 2.2.0   |
| `@noble/curves`       | 2.2.0   |

To refresh after a dependency bump: `npm install` in `../`, then re-copy the
closure of `@noble/post-quantum/ml-dsa.js` from `node_modules/` into this tree
(see the project PROGRESS log for the closure-tracing one-liner).
