# vinext

**Status: blocked.** This example builds successfully and the app itself
is correct and verified working (see below), but the built Cloudflare
Workers worker cannot currently boot on funcbox: it statically imports
`node:async_hooks`, which funcbox does not provide in any mode. This
README documents exactly what blocks it, what was tried, and what would
unblock it — the app and build setup are shipped anyway, in this honest
"does not run yet" state, per this repo's policy of not faking success.

## What vinext is

[`vinext`](https://github.com/cloudflare/vinext) ([docs](https://vinext.dev))
is an experimental Vite plugin from Cloudflare that reimplements the
Next.js public API surface (`pages/` and `app/` routers, SSR, RSC,
Server Actions, ISR, middleware) on top of Vite instead of webpack/
Turbopack, with Cloudflare Workers as its primary deployment target via
`@cloudflare/vite-plugin`. Its Workers build produces a plain
`export default { fetch(request, env, ctx) }` module — the same shape
funcbox expects — which is why it looked like a promising fit.

Packages used here (all beta, pinned by the lockfile):

- `vinext` `1.0.0-beta.5` — the core plugin/framework
- `@vinext/cloudflare` `1.0.0-beta.5` — Cloudflare-specific integration
  (cache adapters, `@vinext/cloudflare deploy`)
- `@vitejs/plugin-rsc` `0.5.34`, `react-server-dom-webpack` `19.2.8` — RSC
  wiring (App Router only)
- `@cloudflare/vite-plugin` `1.52.0`, `wrangler` `4.122.0` — the Workers
  build/dev tooling vinext's Cloudflare integration builds on
- `react` / `react-dom` `19.2.8`

Scaffolded with the official `pnpm create vinext-app@latest`, which is the
documented way to start a new project (`vinext init` is for *migrating* an
existing Next.js app, which doesn't apply here).

## The app

A minimal App Router app under `app/`, enough to exercise SSR, a second
route, an API route, and client-side hydration:

- `app/page.tsx` — the index page (server component, `revalidate = 300`)
- `app/about/page.tsx` — a second route, a plain server component that
  renders `new Date().toISOString()` on every request (proof it's real
  per-request SSR, not a cached static replay)
- `app/api/hello/route.ts` — a Route Handler returning JSON
- `app/components/counter.tsx` — a `"use client"` counter (`useState`),
  shipped as a separate chunk and hydrated in the browser

## Architecture on funcbox: the asset wrapper

`vinext build`'s Cloudflare target produces two things under `dist/`:

- `dist/server/` — the actual worker: `dist/server/index.js` exports
  `export default { fetch(request, env, ctx) { ... } }` and imports a
  couple dozen RSC/SSR chunk files next to it via relative specifiers.
- `dist/client/` — static assets (`_next/static/**`: JS chunks, CSS) meant
  to be served through Cloudflare's Workers **static-assets binding**
  (`wrangler.jsonc`'s `assets: { binding: "ASSETS" }`). The generated
  worker calls `env.ASSETS.fetch(...)` for asset paths and otherwise falls
  through to app rendering.

funcbox has no static-assets binding, so as directed by this example's
brief, the fix is a wrapper:

1. **`scripts/build-assets.mjs`** (Node, runs on the build machine, not in
   the worker) walks `dist/client/_next/**` after `vinext build` and
   writes `dist/assets.js` — a plain ESM module mapping every public URL
   path (e.g. `/_next/static/chunks/counter-B3POtwm5.js`) to its content
   type and base64-encoded bytes. `pnpm build` runs `vinext build && node
   scripts/build-assets.mjs`.
2. **`funcbox-entry.js`** (funcbox's `main`) imports `dist/assets.js` and
   `dist/server/index.js`. On each request it checks the map first —
   serving a matching path directly (with `Cache-Control:
   public, max-age=31536000, immutable` for the content-hashed
   `/_next/static/` paths) — and otherwise delegates to vinext's own
   `fetch()`.

This part of the wrapper is verified correct in isolation (below), but the
combined entry cannot currently be exercised end-to-end through funcbox
because of the blocker described next.

## Status: blocked by `node:async_hooks`

vinext uses `AsyncLocalStorage` extensively to keep concurrent requests'
state isolated — headers, cookies, cache tags, RSC server context, etc.
all live in a per-request ALS-backed store (see upstream's own
`packages/vinext/src/shims/ALS-ARCHITECTURE.md` for the design). This is
loaded with a static, top-level `import { AsyncLocalStorage } from
"node:async_hooks"` in the server/RSC code path — confirmed directly in
this example's own build output:

```
$ grep -o 'from"node:[a-z_]*"' dist/server/index.js
from"node:async_hooks"
```

(it's also imported by two of the RSC chunks index.js pulls in:
`unified-request-context-*.js` and
`framework~index~page~app-route-handler-dispatch-*.js`).

vinext *does* ship a browser-only stub for this
(`packages/vinext/src/plugins/async-hooks-stub.ts`, filtered to
`environment.name === "client"`) precisely because Vite can't bundle
`node:async_hooks` for the browser — but no such stub exists (or is meant
to exist) for the server/RSC environment, where a real
`AsyncLocalStorage` is required for correct per-request isolation.

funcbox does not provide `node:*` core modules in **any** mode
(see the top-level README's "Bundle limits and module resolution"
section): the default mode only resolves relative
`./`/`../` specifiers, and `compat.nodejs: true` adds `node_modules`
resolution + CJS interop but explicitly *not* `node:*` core modules
(`compat/nodejs`'s core-module installer has no hook into
`cfworkers.Pool` yet). funcbox statically scans for `node:*` imports at
both `dev` and `deploy` time (`internal/runtime/nodedetect.go`) precisely
to fail fast with an actionable message instead of a runtime crash.

**Reproduced directly** by pointing `funcbox.yaml` at the built worker and
running `go run ./cmd/funcbox dev examples/vinext`, then requesting *any*
path — including a static asset path the wrapper should have served
without ever touching vinext's code:

```
$ curl http://127.0.0.1:8787/dev/vinext/
500 cli: dev: warm pool: cfworkers: warming instance 0: worker module threw:
Error: module specifier "node:async_hooks" has no file extension: relative
imports need an explicit extension (e.g. "./lib/greet.js"), and bare
specifiers (npm-style package names) are not supported here; enable
compat.nodejs for node_modules resolution
```

Every path fails identically (confirmed for `/`, `/about`, and a
`/_next/static/chunks/*.js` asset path) because ESM module graphs are
evaluated eagerly as a whole: `funcbox-entry.js` statically imports
`dist/server/index.js`, which statically imports the chunk that imports
`node:async_hooks`, so the entire module fails to evaluate during pool
warmup, before any request — even one the wrapper would have short-circuited
before reaching vinext's code — is ever routed.

Setting `compat.nodejs: true` doesn't help (and isn't the right layer for
this class of problem anyway: `node:*` core modules are unsupported
regardless of that flag) — it was tried and instead surfaces the
[known `node_modules` collector limitation](../nodejs-compat/README.md#a-symlink-caveat-found-while-writing-this-example)
with pnpm's default symlinked layout as a bundle-collection error, which
is orthogonal noise on top of the same underlying block.

### Mitigations considered and rejected

- **Stub `node:async_hooks` with a no-op for the server build too**
  (extending vinext's own client-only `async-hooks-stub.ts` pattern to the
  `rsc`/`ssr` Vite environments). This would very likely make the build
  *load*, since vinext's own fallback path already does this — see
  `als-registry.ts`'s `NoopAsyncLocalStorage`, used when
  `typeof AsyncLocalStorage !== "function"`. It was **not** adopted here:
  funcbox reuses warm worker instances across requests, and module-level
  state persists across warm reuse, so a no-op ALS means concurrent requests on the same warm
  instance would share headers/cookies/cache state instead of being
  isolated — a real correctness bug under load, not just a missing
  feature. Shipping that as "working" would be exactly the kind of fake
  success this task was told not to produce.
- **`vinext init`'s Node platform / Nitro's `node` preset** — both target
  a long-running Node.js *process* (`node dist/standalone/server.js` or
  `node .output/server/index.mjs`), not a `fetch(request, env, ctx)`
  module. Not applicable to funcbox's function model regardless of the
  ALS question.

### What would unblock this

- **Upstream funcbox**: a hook to install `compat/nodejs`'s `node:*`
  core-module resolver into `cfworkers.Pool`'s worker initialization (a
  known gap today) — `node:async_hooks` specifically would need
  `AsyncLocalStorage` to actually work (not just
  resolve), which is a heavier lift than most `node:*` modules.
- **Upstream vinext**: an official way to disable/no-op ALS-backed
  isolation for single-request-at-a-time runtimes, or to make the
  `node:async_hooks` import in the server bundle lazy/optional rather than
  a hard top-level dependency.

## Verified behavior (on vinext's own runtime, not funcbox)

Since the funcbox path is blocked before any request is served, the app
itself was verified independently with vinext's own tooling, to confirm
the block is specific to funcbox and not a bug in this example:

```sh
pnpm install
pnpm build            # vinext build && node scripts/build-assets.mjs
PORT=3055 node_modules/.bin/vinext start
```

- `GET /` → 200, real server-rendered HTML (`<h1>Build Next.js-style
  apps...`), referencing `/_next/static/chunks/counter-B3POtwm5.js` and
  the other hashed asset paths that `dist/assets.js` also embeds
  (confirmed identical hashes between what the page references and what
  `build-assets.mjs` captured).
- `GET /about` → 200, real per-request SSR (`rendered-at` timestamp
  changes between requests).
- `GET /api/hello` → 200 `{"message":"Hello from vinext on Cloudflare
  Workers"}`.
- `GET /_next/static/chunks/counter-B3POtwm5.js` → 200,
  `content-type: application/javascript; charset=utf-8`,
  `cache-control: public, max-age=31536000, immutable`; the chunk's body
  contains the real `useState` counter implementation.

The wrapper's asset-serving logic (`dist/assets.js` + the decode step in
`funcbox-entry.js`) was verified in isolation with plain Node — the
base64-embedded bytes for the counter chunk are byte-identical to the
file on disk — since it can't be exercised through `funcbox dev` while the
combined module fails to load.

## Build / run

```sh
pnpm install
pnpm build                                   # -> dist/server, dist/assets.js
go run ./cmd/funcbox dev examples/vinext      # currently fails at pool warmup — see above
```

`node_modules` and `dist/` are gitignored; both are required and are
**not** committed (see "Commit decision" below).

vinext's own native paths still work end-to-end and are unaffected by any
of the above (kept as separate `pnpm` scripts since they're unrelated to
funcbox):

```sh
pnpm dev                    # vinext's own dev server (HMR)
pnpm run start:cloudflare   # wrangler dev against the Cloudflare build
pnpm run deploy:cloudflare  # npx @vinext/cloudflare deploy (needs Cloudflare auth)
```

## Commit decision: build output is gitignored

`dist/` is **not** committed. Two independent reasons:

1. It doesn't work when deployed to funcbox (see above), so committing it
   wouldn't make the example "deployable without building" in any
   meaningful sense.
2. Even setting that aside, what would need to deploy (`dist/server/` +
   `dist/assets.js`) is ~1.3 MiB, over this repo's informal "commit if
   small" threshold for examples.

Regenerate with `pnpm install && pnpm build`.

## Known limitations / not tested

Beyond the blocking issue above, these vinext features exist but weren't
exercised by this minimal example and are untested against funcbox:
Server Actions, middleware, ISR/`"use cache"`, streaming SSR, and
Cloudflare bindings via `cloudflare:workers` (that import itself would
hit the same `node:*`-adjacent externalization machinery and needs
workerd to resolve at runtime, which funcbox also doesn't provide).
