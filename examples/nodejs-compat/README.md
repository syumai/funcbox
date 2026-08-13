# nodejs-compat

Demonstrates `compat.nodejs: true` and resolving a bare specifier
(`import camelCase from "camelcase"`) against a bundled `node_modules`.

```yaml
compat:
  nodejs: true
```

`camelcase` (npm) was picked deliberately: `"type": "module"`, a single
JS file, zero dependencies of its own, and no `node:*` imports — so it
isolates what `compat.nodejs` actually gets you today (node_modules /
`exports`-map resolution + CommonJS interop) from what it doesn't yet
(`node:*` core modules — see below).

## Before running: install the dependency

`node_modules` is **not** committed (see `.gitignore`); install it first:

```sh
pnpm install
# or: npm install
```

pnpm's default `node_modules` layout uses **symlinks** into its
content-addressable store (`node_modules/camelcase -> .pnpm/camelcase@.../
node_modules/camelcase`). The funcbox CLI's bundle collector
(`internal/cli/collect.go`) follows directory (and regular-file) symlinks
when gathering a project's files, so plain `pnpm install` works out of the
box now — no `.npmrc` override needed.

## Run it locally

```sh
go run ./cmd/funcbox dev examples/nodejs-compat
curl "http://127.0.0.1:8787/dev/nodejs-compat?text=hello%20world"
# hello world -> helloWorld
```

## Deploy it

```sh
funcbox deploy --owner <your-handle> examples/nodejs-compat
```

`node_modules` is only included in the deploy bundle because
`compat.nodejs: true` is set (otherwise it's excluded like any other
dependency directory, deployed or not). Keep dependencies minimal: the
bundle's total **unpacked** size limit is 5 MiB (the whole function host
is in-memory — see the top-level README's "Function authoring" section),
and that budget now has to cover `node_modules` too.

## What doesn't work yet

`node:*` core modules (`node:fs`, `node:crypto`, `node:http`, ...) are
**not** available in v1: `compat/nodejs`'s core-module installer has no
hook into the pooling layer funcbox uses yet. A deploy that statically
imports one fails fast with an actionable error at deploy time rather
than a 500 on first invocation. `node_modules` resolution and CommonJS
interop (what this example uses) are unaffected by that gap.
