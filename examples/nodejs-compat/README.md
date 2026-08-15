# nodejs-compat

Demonstrates `compat.nodejs: true`: resolving a bare specifier
(`import camelCase from "camelcase"`) against a bundled `node_modules`,
and importing a `node:*` core module (`node:crypto`) directly.

```yaml
compat:
  nodejs: true
```

`camelcase` (npm) was picked deliberately: `"type": "module"`, a single
JS file, zero dependencies of its own — it isolates node_modules /
`exports`-map resolution + CommonJS interop from the rest of what
`compat.nodejs` provides. `node:crypto` demonstrates the other half:
`compat.nodejs` installs the full Node runtime (`nodejs.Install`), so
`node:*` core modules just work, with no extra flag.

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
# hello world -> helloWorld (sha256: <12 hex chars>...)
```

## Deploy it

```sh
funcbox deploy --owner <your-user-id> examples/nodejs-compat
```

`node_modules` is only included in the deploy bundle because
`compat.nodejs: true` is set (otherwise it's excluded like any other
dependency directory, deployed or not). Keep dependencies minimal: the
bundle's total **unpacked** size limit is 5 MiB (the whole function host
is in-memory — see the top-level README's "Function authoring" section),
and that budget now has to cover `node_modules` too.

## node:* core modules

`node:*` core modules (`node:fs`, `node:crypto`, `node:http`, ...) are
fully available once `compat.nodejs: true` is set — funcbox's own runtime
(`runtime/enginepool`, see the top-level README's "Runtime" section)
installs the complete Node compatibility layer, not just module
resolution. A deploy that statically imports a `node:*` module WITHOUT
`compat.nodejs: true` fails fast with an actionable
"enable compat.nodejs" error at deploy time, rather than a 500 on first
invocation.
