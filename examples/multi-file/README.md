# multi-file

Shows ESM imports across several files in the same bundle, without any
compat layer or external dependency.

```
multi-file/
├── funcbox.yaml
├── index.js            imports ./lib/greet.js and ./lib/format/shout.js
└── lib/
    ├── greet.js
    └── format/
        └── shout.js
```

## The two rules this demonstrates

funcbox's default module resolution (no `compat.nodejs`) only understands
relative specifiers, and enforces two things a typical bundler-based setup
usually hides from you:

1. **Only `./` / `../` specifiers resolve.** A bare specifier like
   `import "lib/greet"` (no leading `./`) is treated as an npm-style
   package name and rejected unless `compat.nodejs: true` is set (see
   `examples/nodejs-compat`).
2. **The file extension is required.** `import "./lib/greet"` fails —
   it must be `import "./lib/greet.js"`. This lets the loader tell a
   genuine relative import apart from a bundle-root-relative bare
   specifier without guessing.

## Run it locally

```sh
go run ./cmd/funcbox dev examples/multi-file
curl "http://127.0.0.1:8787/dev/multi-file?name=funcbox"
# HELLO, FUNCBOX!
```

## Deploy it

```sh
funcbox deploy --owner <your-user-id> examples/multi-file
```
