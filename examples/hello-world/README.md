# hello-world

The minimal funcbox function: one file, no dependencies, no manifest fields
beyond `name`.

- `index.js` — `export default { fetch }`, the same handler shape used by
  `Deno.serve` and `Bun.serve`'s default export.
- `funcbox.yaml` — just `name` and `description`. Everything else (main
  entry point, timeout, memory, permissions, visibility) falls back to its
  documented default (see the top-level README's "Function authoring"
  section).

## Run it locally

From the repository root:

```sh
go run ./cmd/funcbox dev examples/hello-world
```

This hosts the function at `http://127.0.0.1:8787/dev/hello-world` (`dev`
is the placeholder owner `funcbox dev` uses when the manifest doesn't set
one) and hot-reloads on file changes. Verify it:

```sh
curl http://127.0.0.1:8787/dev/hello-world/anything
# Hello from funcbox! You requested /dev/hello-world/anything
```

## Deploy it

```sh
funcbox login --server https://your-funcbox-server
funcbox deploy --owner <your-handle> examples/hello-world
```

Flags must come before the directory argument (`funcbox deploy --owner X
dir`, not `funcbox deploy dir --owner X`) — the CLI's flag parser stops at
the first positional argument.
