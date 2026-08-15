# funcbox

funcbox is a self-hosted serverless function platform for internal use
inside an organization. Deploy an ESM JavaScript project and it's
reachable at `https://<host>/<owner>/<function>` — no Node.js on the
hosting/runtime side, permission control at the organization / workspace /
function-manifest level, and everything (dashboard, management API,
function runtime) runs from a single Go binary per role.

> **Experimental project.** funcbox is under active development. APIs,
> the CLI, storage schemas, and behavior may change without notice, and
> it is not yet recommended for production use.

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
- **Two binaries, two Go modules.** `funcbox-server` hosts the dashboard,
  management API, auth, and function invocation behind one HTTP listener;
  it lives in its own module, `github.com/syumai/funcbox/server`, which
  carries every heavy server-only dependency (DB drivers, blob backends,
  OIDC). `funcbox` is the separate CLI (`login` / `dev` / `deploy` /
  `logs` / `rollback` / `list`) that talks to the server over HTTP only —
  it never touches the database or blob storage directly, and lives in the
  root module (`github.com/syumai/funcbox`) alongside the four packages
  the two binaries share (`bundle`, `manifest`, `policy`, `runtime`). The
  root module's only direct dependencies are go-spidermonkey, go-yaml, and
  fsnotify, so `go install`ing or importing the CLI/core library never
  pulls in the server's dependency graph. A committed `go.work` ties both
  modules together for local development; see [Repo layout](#repo-layout).
- **Pluggable backends.** Database (SQLite, Turso, any PostgreSQL,
  DynamoDB) and blob storage (local filesystem, S3-compatible, GCS) are
  selected by URI scheme at startup; local development defaults to SQLite
  + local filesystem with no external services.

## Quick start

Requires Go 1.26+ and, only for building the dashboard, pnpm + Node
(the dashboard's *build output* is embedded into the server binary —
nothing Node-related ships or runs at serve time).

### 1. Build

The CLI can be installed directly, since the root module carries none of
the server's dependencies:

```sh
go install github.com/syumai/funcbox/cmd/funcbox@latest
```

`funcbox-server` embeds the dashboard's build output via `go:embed`, so it
must be built from a checkout with `make` (a bare `go install` of it won't
have a dashboard to embed):

```sh
make server   # pnpm -C server/dashboard install/build, then go build ./cmd/funcbox-server
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
table). Because this is plain HTTP, the server automatically falls back to
differently-named, non-`__Host-`-prefixed session/CSRF/invoke cookies here
(the `__Host-` prefix used everywhere else requires `Secure`, which a
browser will never honor over `http://`). `localhost` and `127.0.0.1` are
interchangeable here — if `FUNCBOX_BASE_URL` names one and your browser
(or `funcbox login`) visits the other, the server transparently redirects
you to the configured one so login always works.

### 3. Deploy and invoke the sample function

```sh
./bin/funcbox login --server http://127.0.0.1:8080
./bin/funcbox deploy --owner <your-user-id> testdata/hello
```

`funcbox login` opens your browser to an explicit "approve this device"
page on the dashboard (you must already be signed in there, or it takes
you through `/auth/login` first) and, once approved, saves a CLI login
credential to `~/.config/funcbox/config.yaml`. See
[CLI login and access tokens](#cli-login-and-access-tokens) below for how
this works and how to use it from CI or a script.

Flags may appear before, after, or interspersed around the directory
argument for every subcommand that takes one (`dev`, `deploy`): e.g.
`funcbox deploy testdata/hello --owner x` and `funcbox deploy --owner x
testdata/hello` are equivalent.

`testdata/hello`'s manifest sets `permissions.fetch.mode: deny` and
declares no `visibility`, so it falls back to the organization's default
(`org` — any org member). Open the printed URL in the *same* browser
you're logged into the dashboard with (session-cookie auth is accepted
for same-origin `GET`/`HEAD`), or call it with `Authorization: Bearer` —
either a Google/GitHub ID token or a funcbox access token (`funcbox
print-access-token`, see [CLI login and access
tokens](#cli-login-and-access-tokens)) — for `org`/`workspace`-visibility
functions from a script.

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
owner: data                 # optional; deploy-target User ID or workspace ID, used by the
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

The authoritative source for manifest parsing and validation is the
`manifest` package.

Reserved names — rejected for both function names and public User IDs,
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
| `FUNCBOX_POOL_MAX_FUNCTIONS` | `10` | LRU cap on the number of distinct function versions kept warm at once; over the cap, the least-recently-invoked version's pool is closed gracefully. `0` = unlimited. Doesn't apply to the dashboard's own pool |
| `FUNCBOX_AUTH_MODE` | `google` | `google` or `dev` (see Quick start) |
| `FUNCBOX_AUTH_PROVIDER` | `google` | `google` or `github` — selects the active identity provider. Ignored when `FUNCBOX_AUTH_MODE=dev` (the dev stub is provider-independent). Exactly one provider is active at a time |
| `FUNCBOX_GOOGLE_CLIENT_ID` | *(none)* | Required when `FUNCBOX_AUTH_PROVIDER=google` (the default), unless `FUNCBOX_AUTH_MODE=dev` |
| `FUNCBOX_GOOGLE_CLIENT_SECRET` | *(none)* | Required when `FUNCBOX_AUTH_PROVIDER=google` (the default), unless `FUNCBOX_AUTH_MODE=dev` |
| `FUNCBOX_GITHUB_CLIENT_ID` | *(none)* | Required when `FUNCBOX_AUTH_PROVIDER=github`, unless `FUNCBOX_AUTH_MODE=dev`. The GitHub OAuth App's client ID |
| `FUNCBOX_GITHUB_CLIENT_SECRET` | *(none)* | Required when `FUNCBOX_AUTH_PROVIDER=github`, unless `FUNCBOX_AUTH_MODE=dev`. The GitHub OAuth App's client secret |
| `FUNCBOX_SESSION_SECRET` | *(none, required)* | HKDF root secret for session/CSRF and env-var-at-rest encryption; rotating it invalidates existing sessions and encrypted env values |
| `FUNCBOX_DASHBOARD_DIST_DIR` | *(none)* | Point at `server/internal/dashboard/dist` on disk instead of the embedded build, for dashboard development (`pnpm -C server/dashboard watch`) |
| `FUNCBOX_METRICS` | *(unset = off)* | Set to `1` to enable Prometheus metrics and mount `/metrics` |
| `FUNCBOX_OPEN_MODE` | *(unset = off)* | Set to `1` to seed the organization's `open_mode` setting to `true` **at first-organization bootstrap only** (see [Open mode](#open-mode)). Has no effect on an already-bootstrapped organization; from then on the organization setting itself is authoritative and this env var is never consulted again |

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

### GitHub login (`FUNCBOX_AUTH_PROVIDER=github`)

GitHub has no OIDC issuer, so this path is plain OAuth2 (`read:user
user:email` scope) against `GET /user` and `GET /user/emails`, using the
account's **verified primary email**; an account with no verified email
is refused at login. A few things behave differently from Google login as
a result:

- **The handle is fixed to the (lowercased) GitHub username** and cannot
  be changed afterward — `PATCH /api/v1/me` handle changes are rejected
  with `403` for GitHub-provider accounts, and the dashboard hides the
  change control accordingly. A GitHub username that collides with a
  funcbox-reserved name (or with a handle some other account already
  holds) is refused at login with an explicit error, since there is no
  fallback name to fall back to. Renaming your GitHub username afterward
  does **not** change your funcbox handle.
- **Switching the active provider auto-links by verified email.** If a
  login's `(provider, subject)` doesn't match an existing account but its
  verified email does, that account is linked to the new identity instead
  of a second account being created (functions, role, and connected
  devices carry over). Because linking into GitHub can change the handle
  (and therefore function URLs), the user is shown a confirmation page and
  must approve it before the link takes effect; the link is recorded in
  the audit log either way.

The CLI (`funcbox`) reads its own config from `~/.config/funcbox/config.yaml`
(`$XDG_CONFIG_HOME/funcbox/config.yaml` if set), written by `funcbox login`;
`FUNCBOX_SERVER` / `FUNCBOX_CREDENTIAL` env vars override it per invocation
(see [CLI login and access tokens](#cli-login-and-access-tokens)).

### Account approval mode and function limits

Two organization settings (editable by an admin under **Organization
settings** in the dashboard, or via `PATCH /api/v1/org`) support running
funcbox with open registration in a controlled way:

- **`require_approval`** (default off): a brand-new account — from any
  login provider, including a GitHub email-link that creates a new account
  (linking to an *existing* account keeps that account's current status
  unchanged) — is created `pending` instead of `active`. The bootstrap
  admin is always `active` regardless. **Logging in still succeeds** for a
  pending user (a session is issued), but every dashboard page shows only
  an "access request pending" screen (their identity and request date),
  and every `/api/v1/*` call — including approving a new CLI login
  device (`POST /api/v1/cli/authorize`) — responds
  `403 {"error":{"code":"pending_approval"}}`. A pending user's saved CLI
  credential can still mint access tokens (that check happens outside this
  gate; see `POST /api/v1/cli/access-token`), but every one of those
  tokens then hits the exact same 403 the moment it's used against
  `/api/v1/*`, so a pending account gets no working CLI access either way.
  An org admin
  approves (`pending` → `active`) or rejects (`pending` → `disabled`) from
  **Organization settings → Users**, which shows a dedicated "Pending
  requests" section and a nav badge with the count; both actions go
  through the same `PATCH /api/v1/org/users/{id}` endpoint the ordinary
  role/status editor uses and are recorded in the audit log with enough
  detail (`previous_status`, a derived `approval_action`) to tell an
  approval/rejection apart from an unrelated status edit.

  There is deliberately **no separate pre-login notice page** gated on
  this setting: `/auth/login` redirects straight to the identity provider
  exactly as it always has, because there's no way to know — before that
  round trip completes — whether a given login will create a new (and
  therefore pending) account or resolve an existing active one, and
  inserting a click-through for *every* login (including already-approved
  returning users) purely to cover the new-account case would be an
  unwarranted regression for the common case. The pending page itself,
  shown immediately once login completes, doubles as this notice — it's
  the first and only thing a newly-registered user sees.

- **`max_functions_per_user`** (org-level, default unlimited) and, per
  workspace, **`max_functions_per_member`** (editable under a workspace's
  own settings page): cap how many personal-scope functions a single user
  may own, and how many functions a single member may create within a
  given workspace, respectively. Both are enforced only at **new**
  function creation — redeploys, rollbacks, and env-var changes on an
  existing function are never blocked, and lowering a limit below an
  owner's current count is tolerated (existing functions are never
  force-deleted). Exceeding the limit on a real deploy responds `403
  {"error":{"code":"function_limit_exceeded"}}`; `?dry_run=true` performs
  the identical check and reports it as a warning instead of failing.
  Organization admins are **not** exempt. The dashboard's new-deployment
  page shows the selected owner's remaining quota when a limit applies.

### Open mode

`open_mode` (org setting, default off; editable under **Organization
settings**, or `PATCH /api/v1/org {"open_mode": true}`) switches an
installation from closed, invite-only registration to accepting public
sign-ups, without abandoning any of the rest of the organization's
configuration — there is still exactly one organization, and every other
org setting (login rules, fetch policy, visibility limits, ...) continues
to apply exactly as configured. The recommended public-deployment
combination is `open_mode` + `require_approval` (above) +
`max_functions_per_user`: anyone can request access, only an admin-approved
account can actually use funcbox, and each account is capped.

Turning it on changes four things:

- **Registration opens.** This only actually matters at the very first
  organization's bootstrap: normal-mode bootstrap seeds a login rule that
  allows only the very first (admin) account's exact email address and
  denies everyone else by default, so a second person has to be explicitly
  added by that admin before they can sign in at all. `FUNCBOX_OPEN_MODE=1`
  at bootstrap time seeds a `default: allow` rule instead, so registration
  is open to anyone from the start. **Enabling `open_mode` later, on an
  already-running organization, does NOT touch its existing login
  rules** — they were the admin's to configure and keep applying exactly
  as they are; the dashboard shows a one-time notice to that effect right
  after the toggle, since it would otherwise be easy to assume enabling
  "open mode" alone reopens registration.
- **Other users' information is hidden from non-admins.** A non-admin's
  own dashboard/`GET /api/v1/functions` function list narrows to only the
  functions *they* own — an org-visibility function belonging to someone
  else no longer appears there (it remains reachable by URL with the
  right credential, exactly as before; this only affects the list). The
  audit log remains admin-only, unchanged. Invoked functions also stop
  receiving the caller's identity: normal mode always injects
  `X-Funcbox-Caller-Email` for anything narrower than `visibility:
  public`, but open mode suppresses it by default (a stranger's email
  would otherwise leak to whichever unrelated user happens to own the
  function they're calling) unless the new **`expose_caller_identity`**
  org setting explicitly opts back in.
- **The workspace feature is disabled outright.** Every
  `/api/v1/workspaces*` route 404s (not 403s — the feature doesn't appear
  to exist), the dashboard hides the workspace nav item and screens,
  `visibility: workspace` is rejected as a deploy-time error (`public` and
  `org` remain available; `org` still means "every logged-in user"), and
  deploying under a workspace-scoped owner is rejected the same way.
  **Toggle guard:** `PATCH /api/v1/org` refuses (`409
  {"error":{"code":"workspaces_exist"}}`) to turn `open_mode` on while any
  workspace still exists — delete them first. Turning it back off is
  always allowed.
- **`default_visibility` is unaffected** — it still comes from the
  organization's own setting (`org` by default), open mode doesn't change
  it.

## CLI login and access tokens

> **Breaking change:** API keys (`fbx_...` tokens, `/api/v1/me/tokens`) are
> abolished. Every previously issued token stops working the moment a
> server upgrades to this version. Run `funcbox login` again on every
> machine (including CI — see below) to get a working credential.

`funcbox login [--server URL]` no longer prompts for a pasted token. It:

1. starts a temporary listener on `127.0.0.1` and generates a PKCE
   verifier/challenge pair;
2. opens your browser to the dashboard's `/dashboard/cli-auth` page
   (falling back to printing the URL if it can't open one automatically),
   carrying the loopback callback URL, the PKCE challenge, and this
   machine's hostname;
3. the dashboard shows an **explicit approval screen** — device name and
   requester, never auto-approved even if you're already signed in — and
   only proceeds once you click Approve;
4. the browser is redirected back to the loopback listener with a
   one-time authorization code, which the CLI exchanges (together with
   the PKCE verifier it alone ever held) for a long-lived **CLI login
   credential** (`fbxc_...`);
5. that credential is saved to `~/.config/funcbox/config.yaml` (mode
   `0600`).

The credential itself is **never** sent directly to the management API.
Every `funcbox` subcommand mints a short-lived **access token**
(`fbxa_...`, default 15 minutes, capped at 1 hour server-side) from it on
demand and caches it until shortly before it expires — this is invisible
day to day. Run `funcbox print-access-token [--ttl 15m]` to mint one
yourself and print it (and only it) to stdout, for scripting:

```sh
export FUNCBOX_TOKEN=$(funcbox print-access-token)
curl -H "Authorization: Bearer $FUNCBOX_TOKEN" https://fb.example.com/data/report
```

Connected devices (one row per saved credential: name, created, last used)
are listed under the dashboard's **Personal settings → Connected
devices**, where any of them can be revoked. Revoking stops that device
from minting new access tokens immediately; an access token minted before
revocation keeps working until its own short natural expiry (at most 1
hour) — it isn't invalidated instantly, which is the trade-off that keeps
access tokens short-lived enough not to need a revocation check on every
single request.

**CI / headless use**: there is no non-interactive login flow (the
approval screen is deliberately unskippable). Instead, run `funcbox login`
once interactively from a workstation, then copy the resulting credential
(`credential:` in the config file, or the CLI's own stdout during login)
into your CI system's secret store as `FUNCBOX_CREDENTIAL`. It takes
precedence over the config file:

```sh
export FUNCBOX_SERVER=https://fb.example.com
export FUNCBOX_CREDENTIAL=fbxc_...   # from a CI secret
funcbox deploy --owner ci-bot ./my-function
```

Revoke it from **Connected devices** the same way you'd revoke any other
device once it's no longer needed.

## CLI reference

```
funcbox login  [--server URL]                         browser login; saves a CLI credential
funcbox print-access-token [--ttl 15m]                 mint and print a short-lived access token
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
manifest's own `owner` field > the caller's own User ID, looked up via
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
- **Roles**: an organization-wide role is one of `admin` >
  `workspace_manager` > `member`. **Org Admin** (multiple allowed)
  manages organization settings, all workspaces, and all users; the last
  remaining org admin can't be removed or demoted. **Workspace Manager**
  has every `member` permission plus the ability to create workspaces —
  it is otherwise a member in every other respect and gains no other
  admin capability (no org settings, no user management, no audit log,
  no access to workspaces it isn't otherwise a member of). **General
  members** can (if the organization allows it) deploy personal-scope
  functions, but cannot create workspaces. Separately, within a given
  workspace, **Workspace Admin** manages that workspace's settings,
  members, and functions (the workspace's creator starts as its first
  admin), while **Workspace Member** can deploy to it unless the
  workspace restricts deploys to admins — this workspace-level
  admin/member distinction is independent of the organization-wide role
  above.

  **Migration note (breaking change)**: the organization setting
  `allow_workspace_creation` has been removed — workspace creation is now
  decided solely by the `admin`/`workspace_manager` role, with no org-wide
  toggle. Organizations that had `allow_workspace_creation: true` will see
  members lose the ability to create workspaces on upgrade; an org admin
  must grant affected users the `workspace_manager` role (via
  `PATCH /api/v1/org/users/{id}` or the dashboard's Users screen) to
  restore it. A settings JSON blob that still contains the old key is
  read without error — the key is simply ignored.

## Development

### Repo layout

Two Go modules, tied together for local development by a committed
`go.work` (`use (. ./server)`; ignored by anyone consuming either module
as a dependency):

```
go.mod                 core module: github.com/syumai/funcbox
go.work                use (. ./server); go.work.sum is committed alongside it
bundle/                 guarded tar.gz pack/unpack — shared, public API
manifest/               manifest parsing/validation — shared, public API
policy/                 fetch-policy/visibility/SSRF — shared, public API
runtime/                go-spidermonkey integration — shared, public API
internal/cli/           CLI subcommand implementations
cmd/funcbox/             CLI binary entry point
testdata/hello/         end-to-end sample function used by server/e2e_test.go
examples/               deployable sample projects (see Examples above)

server/go.mod           server module: github.com/syumai/funcbox/server
server/cmd/funcbox-server/  server binary entry point
server/internal/        server-only packages (store, blob, auth, api, invoke,
                        service, dashboard, config, settings, authz, crypto,
                        metrics — see each package's doc.go)
server/dashboard/       dashboard frontend source (built by pnpm, embedded
                        into funcbox-server via server/internal/dashboard's
                        go:embed)
server/e2e_test.go      end-to-end suite driving the full server stack
```

`bundle`, `manifest`, `policy`, and `runtime` are exported top-level
packages in the core module — they're funcbox's public library API (no
compatibility guarantee yet; funcbox is pre-v1). They're shared between
both binaries and must never import server-only packages — see each
package's `doc.go`. The server module cannot reach into the core module's
`internal/cli` (a different module's `internal/` package is not
importable), so this boundary is enforced structurally, not just by
convention.

### Building and testing

```sh
make server   # build funcbox-server (builds the dashboard first)
make funcbox  # build the funcbox CLI
make test     # go test ./... (core) + go -C server test ./... (server)
make fmt      # gofmt -l . (lists unformatted files, both modules)
make vet      # go vet ./... (core) + go -C server vet ./... (server)
```

`go -C server test ./...` includes an end-to-end suite (`server/e2e_test.go`)
that drives the full server stack (store, blob, runtime, auth) in-process.
Several backend conformance suites are network-gated and skip themselves
cleanly when their environment variables aren't set:

| Package | Env vars |
|---|---|
| `server/internal/store/turso` | `FUNCBOX_TEST_TURSO_URL` |
| `server/internal/store/neon` | `FUNCBOX_TEST_POSTGRES_URL` |
| `server/internal/store/dynamodb` | `FUNCBOX_TEST_DYNAMODB_ENDPOINT`, `FUNCBOX_TEST_DYNAMODB_TABLE` |
| `server/internal/blob/s3` | `FUNCBOX_TEST_S3_ENDPOINT`, `FUNCBOX_TEST_S3_BUCKET`, `FUNCBOX_TEST_S3_ACCESS_KEY_ID`, `FUNCBOX_TEST_S3_SECRET_ACCESS_KEY` |
| `server/internal/blob/gcs` | `FUNCBOX_TEST_GCS_BUCKET` |

Each package's `_test.go` doc comment has the exact invocation (e.g. how
to point it at a local MinIO/LocalStack/emulator instance).

### Dashboard development

```sh
pnpm -C server/dashboard watch
```

Then point a running `funcbox-server` at the on-disk build with
`FUNCBOX_DASHBOARD_DIST_DIR=$(pwd)/server/internal/dashboard/dist` instead
of using the binary's embedded build, so edits are picked up without
restarting the server.

## License

MIT — see [LICENSE.md](./LICENSE.md).
