# funcbox

funcbox is a self-hosted serverless function platform for internal use
inside an organization. Deploy an ESM JavaScript project and it's
reachable at `https://<host>/<owner>/<function>` — no Node.js on the
hosting/runtime side, permission control at the organization / workspace /
function-manifest level, and everything (dashboard, management API,
function runtime) runs from a single Go binary per role.

## How it works

- **Handlers** are `export default { fetch(request, env, ctx) }` — the
  same shape used by `Deno.serve`, `Bun.serve`'s default export, and
  Cloudflare Workers.
- **The runtime is Go all the way down.** Function execution uses
  [go-spidermonkey](https://github.com/goccy/go-spidermonkey): SpiderMonkey
  compiled to wasm32-wasi and pre-translated to Go, so there's no CGo and
  no Node.js at deploy or invocation time. funcbox uses go-spidermonkey's
  official compat layers rather than a homegrown polyfill/bridge:
  `compat/web` (WinterTC Web APIs — fetch, Request/Response, streams,
  crypto, timers, ...) is always on; `compat/cfworkers` provides the
  `fetch(req, env, ctx)` execution model, per-function instance pooling,
  and `ctx.waitUntil`; `compat/nodejs` is installed per-function when a
  manifest opts in with `compat.nodejs: true`.
- **Capability-based sandboxing.** The JS engine itself has zero I/O —
  no filesystem, network, or subprocess access exists until the host
  grants it. funcbox grants exactly what a function's *effective* policy
  allows via go-spidermonkey's `Resolve`/`Dial`/`FS` hooks, evaluated on
  every call (a policy change takes effect immediately, no redeploy or
  pool rebuild needed).
- **Two binaries, shared internal packages.** `funcbox-server` hosts the
  dashboard, management API, auth, and function invocation behind one
  HTTP listener. `funcbox` is the separate CLI (`login` / `dev` / `deploy`
  / `logs` / `rollback` / `list`) that talks to it over HTTP only — it
  never touches the database or blob storage directly, so it carries none
  of the server's dependencies (DB drivers, blob backends, auth, embedded
  dashboard assets).
- **Pluggable backends.** Database (SQLite, Turso, any PostgreSQL,
  DynamoDB) and blob storage (local filesystem, S3-compatible, GCS) are
  selected by URI scheme at startup; local development defaults to SQLite
  + local filesystem with no external services.

## Quick start

Requires Go 1.26+ and, only for building the dashboard, pnpm + Node
(the dashboard's *build output* is embedded into the server binary —
nothing Node-related ships or runs at serve time).

### 1. Build

```sh
make server   # pnpm -C dashboard install/build, then go build ./cmd/funcbox-server
make funcbox  # the CLI, no dashboard build needed
```

### 2. Run locally with dev auth

`FUNCBOX_AUTH_MODE=dev` turns on a built-in stub OIDC identity provider
(`/dev/oidc/*`) so you can log in with any email, without a real Google
OAuth client — the verification code path is otherwise identical to
production. It's guarded to loopback listeners only:

```sh
export FUNCBOX_ADDR=127.0.0.1:8080
export FUNCBOX_BASE_URL=http://127.0.0.1:8080
export FUNCBOX_AUTH_MODE=dev
export FUNCBOX_SESSION_SECRET=$(openssl rand -hex 32)
# FUNCBOX_DB / FUNCBOX_BLOB are left unset here, which defaults to
# sqlite:funcbox.db and fs:./data/blobs in the current directory.
./bin/funcbox-server
```

Open `http://127.0.0.1:8080/auth/login` in a browser and sign in with any
email address. **The first successful login becomes the organization
admin** (this only happens once — the first row in an empty `users`
table). From the dashboard, go to Settings and create an API token.

### 3. Deploy and invoke the sample function

```sh
./bin/funcbox login --server http://127.0.0.1:8080   # paste the API token
./bin/funcbox deploy --owner <your-handle> testdata/hello
```

Flags may appear before, after, or interspersed around the directory
argument for every subcommand that takes one (`dev`, `deploy`): e.g.
`funcbox deploy testdata/hello --owner x` and `funcbox deploy --owner x
testdata/hello` are equivalent.

`testdata/hello`'s manifest sets `permissions.fetch.mode: deny` and
declares no `visibility`, so it falls back to the organization's default
(`org` — any org member). Open the printed URL in the *same* browser
you're logged into the dashboard with (session-cookie auth is accepted
for same-origin `GET`/`HEAD`), or call it with a Google ID token /
`Authorization: Bearer` for `org`/`workspace`-visibility functions from a
script.

See [`examples/`](./examples) for more deployable sample projects, and
`funcbox dev testdata/hello` to run the sample without deploying anywhere.

## Examples

The [`examples/`](./examples) directory has complete funcbox projects,
each with its own README; all but one are runnable with `funcbox dev`
today (see the exception below):

| Example | Demonstrates |
|---|---|
| [`hello-world`](./examples/hello-world) | The minimal case: one file, no dependencies |
| [`multi-file`](./examples/multi-file) | ESM imports across files; explicit-extension relative-import rules |
| [`fetch-allowlist`](./examples/fetch-allowlist) | `permissions.fetch` host allowlisting and a declared `env` key |
| [`streaming`](./examples/streaming) | A `ReadableStream` `Response`, delivered incrementally |
| [`nodejs-compat`](./examples/nodejs-compat) | `compat.nodejs: true` and a bundled npm dependency |
| [`vinext`](./examples/vinext) | vinext (Next.js on Vite) for Cloudflare Workers, wrapped for funcbox's asset model — **currently blocked**: the built worker statically imports `node:async_hooks`, which funcbox doesn't provide (see its README) |

## Function authoring

### Handler shape

```js
export default {
  async fetch(request, env, ctx) {
    // request: standard Web API Request
    // env: only the keys this function's manifest declares under `env:`
    // ctx.waitUntil(promise): extends execution past the response for
    //   background work (draining up to a fixed timeout)
    return new Response("ok");
  },
};
```

### `funcbox.yaml` reference

Place `funcbox.yaml` (or `.yml`, or `funcbox.json` — all parsed as YAML,
JSON being a syntactic subset) at the project root. A manifest is
optional; every field has a documented default.

```yaml
name: hello-world          # required (here or via --name at deploy time).
                            # ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$, unique per owner
owner: data                 # optional; deploy-target owner handle, used by the
                            # CLI. Resolution order: --owner flag > this field
                            # > (no further fallback — the CLI requires one)
main: src/index.js          # optional; default index.js, then index.mjs
description: Sample function  # optional, max 500 chars

timeout: 10s                 # optional; effective = min(this, workspace/org limits)
memory: 128MiB               # optional; same clamping as timeout

compat:
  nodejs: true                # default false; node_modules resolution + CJS
                               # interop (see examples/nodejs-compat). Can be
                               # disabled org-wide regardless of this field.

permissions:
  fetch:
    mode: allowlist            # deny (default) | allowlist | allow-all
    allow:                     # host[:port] patterns; scheme/path are never
      - api.github.com         # part of a pattern (see examples/fetch-allowlist)
      - "*.internal.example.com"

env:                          # declares which keys this function receives;
  - GITHUB_TOKEN               # values are registered separately (dashboard/API),
  - REPORT_CHANNEL              # never written here. Undeclared keys are never passed.

visibility: org                # public | org | workspace; can't exceed the
                                # organization/workspace's configured maximum
```

Field-by-field detail lives in `tmp/04-manifest.md` (Japanese design doc);
the authoritative source is `internal/manifest`.

Reserved names — rejected for both function names and owner handles,
since they'd collide with top-level routing — are `dashboard`, `api`,
`auth`, `dev`, `assets`, `healthz`, `favicon.ico`, `robots.txt`, and
anything starting with `_`.

### Bundle limits and module resolution

- **5 MiB unpacked bundle limit.** A deploy's files, once decompressed,
  must total 5 MiB or less (the system maximum; an organization may set a
  lower cap). This is a hard limit because every function's bundle is
  held fully in memory — nothing is ever written to disk on the server.
- **ESM only**, no server-side TypeScript transpilation — build/bundle
  before uploading.
- **Default mode** (no `compat.nodejs`): only `./`/`../` relative
  specifiers resolve, and the file extension is required
  (`./lib/x.js`, not `./lib/x`) — see `examples/multi-file`. Bare
  specifiers (npm-style package names) fail with a message pointing at
  `compat.nodejs`.
- **`compat.nodejs: true`**: adds `node_modules` resolution (with
  `exports`-map support) and CommonJS interop, so bare specifiers work —
  see `examples/nodejs-compat`. **`node:*` core modules (`node:fs`,
  `node:crypto`, ...) are not available yet**: go-spidermonkey's
  `compat/nodejs` core-module installer has no hook into the pooling
  layer funcbox builds on (`cfworkers.Pool`) — tracked upstream. A static
  `node:*` import is caught at deploy time with an actionable error
  rather than failing on first invocation.

## Configuration

`funcbox-server` is configured entirely by environment variables (no
flags, except its `gc` subcommand):

| Variable | Default | Notes |
|---|---|---|
| `FUNCBOX_ADDR` | `:8080` | Listen address |
| `FUNCBOX_BASE_URL` | *(none)* | Externally reachable base URL (OAuth redirects, etc.); must be an absolute URL when set |
| `FUNCBOX_DB` | `sqlite:funcbox.db` | Database connection string — see syntax below |
| `FUNCBOX_BLOB` | `fs:./data/blobs` | Blob storage connection string — see syntax below |
| `FUNCBOX_INVOKE_TIMEOUT` | `30s` | Default function execution timeout |
| `FUNCBOX_AUTH_MODE` | `google` | `google` or `dev` (see Quick start) |
| `FUNCBOX_GOOGLE_CLIENT_ID` | *(none)* | Required unless `FUNCBOX_AUTH_MODE=dev` |
| `FUNCBOX_GOOGLE_CLIENT_SECRET` | *(none)* | Required unless `FUNCBOX_AUTH_MODE=dev` |
| `FUNCBOX_SESSION_SECRET` | *(none, required)* | HKDF root secret for session/CSRF and env-var-at-rest encryption; rotating it invalidates existing sessions and encrypted env values |
| `FUNCBOX_DASHBOARD_DIST_DIR` | *(none)* | Point at `dashboard/dist` on disk instead of the embedded build, for dashboard development (`pnpm -C dashboard watch`) |
| `FUNCBOX_METRICS` | *(unset = off)* | Set to `1` to enable Prometheus metrics and mount `/metrics` |

### `FUNCBOX_DB` scheme syntax

```
sqlite:PATH                                    (or sqlite::memory:)
turso:URL?authToken=TOKEN
postgres://user:pass@host/db?sslmode=...       (any PostgreSQL, e.g. Neon)
dynamodb:table=NAME[;endpoint=URL][;region=R]
```

### `FUNCBOX_BLOB` scheme syntax

```
fs:PATH
s3:bucket=B[;endpoint=URL][;region=R][;pathstyle=1]   (AWS S3, R2, MinIO, ...)
gcs:bucket=B
```

The CLI (`funcbox`) reads its own config from `~/.config/funcbox/config.yaml`
(`$XDG_CONFIG_HOME/funcbox/config.yaml` if set), written by `funcbox login`;
`FUNCBOX_SERVER` / `FUNCBOX_API_TOKEN` env vars override it per invocation.

## CLI reference

```
funcbox login  [--server URL]                         save a server URL + API token
funcbox dev    [dir] [--addr H:P] [--env K=V]... [--env-file PATH] [--allow-all-fetch]
                                                        run a function locally with hot reload
funcbox deploy [dir] [--owner H] [--name N] [--note S] [--dry-run]
                                                        pack and upload a new version
funcbox logs   <owner>/<name> [--follow]               fetch invocation logs (polls every 2s with --follow)
funcbox rollback <owner>/<name> --to <versionID>       activate a previous version
funcbox list   [--owner H]                             list deployed functions
```

`funcbox dev` reproduces production's URL shape (`/{owner}/{name}/...`,
owner falling back to the literal `dev` when the manifest doesn't set
one) and applies the manifest's fetch policy — but only that level, since
there's no organization/workspace to intersect with locally; it prints a
reminder of this on startup. Loopback fetch targets are allowed in dev
only. Pass `--allow-all-fetch` to temporarily bypass the manifest's fetch
policy altogether (a startup note is still printed); the SSRF guard for
non-loopback addresses (link-local/metadata, multicast, unspecified) stays
in force either way.

`funcbox deploy`'s owner resolves in this order: `--owner` flag > the
manifest's own `owner` field > the caller's own handle, looked up via
`GET /api/v1/me` if neither of the first two is set.

## Permissions model

- **Fetch policy** is the intersection of three levels — organization ∩
  workspace ∩ manifest — evaluated fresh on every outbound `fetch()` call
  (not fixed at deploy time, so a policy change applies to already-deployed
  functions immediately). Each level can only narrow what's below it:
  the effective mode is the strictest of the three (`deny` <
  `allowlist` < `allow-all`), and under `allowlist` a request must match
  every level that itself declares an allowlist. Patterns are
  `host[:port]` only — no scheme or path.
- **Visibility** (`public` / `org` / `workspace`) is similarly clamped to
  the tightest of the manifest's declared value and the
  workspace/organization's configured maximum.
- **Roles**: **Org Admin** (multiple allowed) manages organization
  settings, all workspaces, and all users; the last remaining org admin
  can't be removed or demoted. **General users** can (if the organization
  allows it) deploy personal-scope functions and create workspaces.
  **Workspace Admin** manages a workspace's settings, members, and
  functions; the workspace's creator starts as its first admin.
  **Workspace Member** can deploy to the workspace unless the workspace
  restricts deploys to admins.

See `tmp/05-auth-and-permissions.md` for the full design.

## Development

### Repo layout

```
cmd/funcbox-server/  server binary entry point
cmd/funcbox/          CLI binary entry point
internal/             shared and per-role packages (see each package's doc.go)
dashboard/             dashboard frontend source (built by pnpm, embedded into
                       funcbox-server via internal/dashboard's go:embed)
testdata/hello/        end-to-end sample function used by e2e_test.go
examples/              deployable sample projects (see Examples above)
tmp/                   design docs (Japanese)
```

`internal/manifest`, `internal/bundle`, and `internal/policy` are shared
between both binaries and must never import server-only packages (store,
blob, auth, api, dashboard) — see each package's `doc.go`.

### Building and testing

```sh
make server   # build funcbox-server (builds the dashboard first)
make funcbox  # build the funcbox CLI
make test     # go test ./...
make fmt      # gofmt -l . (lists unformatted files)
make vet      # go vet ./...
```

`go test ./...` includes an end-to-end suite (`e2e_test.go`) that drives
the full server stack (store, blob, runtime, auth) in-process. Several
backend conformance suites are network-gated and skip themselves cleanly
when their environment variables aren't set:

| Package | Env vars |
|---|---|
| `internal/store/turso` | `FUNCBOX_TEST_TURSO_URL` |
| `internal/store/neon` | `FUNCBOX_TEST_POSTGRES_URL` |
| `internal/store/dynamodb` | `FUNCBOX_TEST_DYNAMODB_ENDPOINT`, `FUNCBOX_TEST_DYNAMODB_TABLE` |
| `internal/blob/s3` | `FUNCBOX_TEST_S3_ENDPOINT`, `FUNCBOX_TEST_S3_BUCKET`, `FUNCBOX_TEST_S3_ACCESS_KEY_ID`, `FUNCBOX_TEST_S3_SECRET_ACCESS_KEY` |
| `internal/blob/gcs` | `FUNCBOX_TEST_GCS_BUCKET` |

Each package's `_test.go` doc comment has the exact invocation (e.g. how
to point it at a local MinIO/LocalStack/emulator instance).

### Dashboard development

```sh
pnpm -C dashboard watch
```

Then point a running `funcbox-server` at the on-disk build with
`FUNCBOX_DASHBOARD_DIST_DIR=$(pwd)/internal/dashboard/dist` instead of
using the binary's embedded build, so edits are picked up without
restarting the server.

### Design docs

`tmp/*.md` are the project's Japanese-language design documents (product
overview, architecture, runtime, manifest, auth/permissions, data model,
HTTP API, storage, dashboard, roadmap). Code comments, doc comments, and
this README are English per the project's documentation language rule;
`tmp/` stays Japanese.

## License

MIT — see [LICENSE.md](./LICENSE.md).
