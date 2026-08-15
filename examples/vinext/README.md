# vinext

**Status: working**, with one caveat specific to `funcbox dev`'s local URL
scheme (see "Known limitation: `funcbox dev`'s path prefix" below) that does
not affect a real deploy. The `node:async_hooks` blocker that used to make
this "does not run yet" is resolved: funcbox now brings its own execution
pool in-house (`runtime/enginepool`) and can wire up `nodejs.Install`, which
is exactly what `AsyncLocalStorage` needs.

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
  couple dozen RSC/SSR chunk files next to it via relative specifiers. It
  also statically imports `AsyncLocalStorage` from `node:async_hooks` (see
  below) — that's the one thing it needs from funcbox's runtime beyond
  plain ESM.
- `dist/client/` — static assets (`_next/static/**`: JS chunks, CSS) meant
  to be served through Cloudflare's Workers **static-assets binding**
  (`wrangler.jsonc`'s `assets: { binding: "ASSETS" }`). The generated
  worker calls `env.ASSETS.fetch(...)` for asset paths and otherwise falls
  through to app rendering.

funcbox has no static-assets binding (and no env argument at all — see the
top-level README's breaking-changes note), so the fix is a wrapper:

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
   `/_next/static/` paths) — and otherwise calls vinext's own `fetch()`
   with `(request, undefined, undefined)`: this app reads neither `env`
   nor `ctx`, so the Workers-shaped call still works even though funcbox
   itself only ever calls `fetch(request)`.

`funcbox.yaml` sets `compat.nodejs: true` — required for the
`node:async_hooks` import — and `.funcboxignore` excludes `node_modules/`
even though `compat.nodejs` is on: `dist/server/index.js` is already
vinext's own fully self-contained esbuild bundle, so nothing here actually
needs `node_modules` resolution at runtime, only the one `node:async_hooks`
core-module import, which funcbox resolves directly.

## Verified working

Built and run directly against `runtime/enginepool.Pool` (bypassing
`funcbox dev`'s CLI wrapper — see the next section for why) with a plain,
unprefixed request path, exactly matching what a real deploy's Host-routed
invocation looks like:

- `GET /` → 200, real server-rendered HTML (`<h1>Build Next.js-style
  apps...`), referencing `/_next/static/chunks/counter-B3POtwm5.js` and
  the other hashed asset paths that `dist/assets.js` also embeds.
- `GET /about` → 200, real per-request SSR: two consecutive requests
  return DIFFERENT bodies with different embedded timestamps (confirmed:
  not a cached replay).
- `GET /api/hello` → 200 `{"message":"Hello from vinext on Cloudflare
  Workers"}`.
- `GET /_next/static/chunks/counter-B3POtwm5.js` → 200,
  `content-type: text/javascript; charset=utf-8`; the chunk's body
  contains the real `useState` counter implementation, served by
  `funcbox-entry.js`'s wrapper (not vinext's own handler).

This directly disproves the previous blocker: `AsyncLocalStorage` (from
`node:async_hooks`) works correctly inside `runtime/enginepool`'s
NodeCompat mode, including the per-request isolation vinext's RSC/SSR
machinery depends on for headers, cookies, cache tags, and server context
(see `runtime/enginepool/nodecompat_test.go`'s dedicated ALS isolation
tests, sequential AND concurrent, for the general-purpose proof; this
example is the real-application-shaped confirmation on top of that).

## Known limitation: `funcbox dev`'s path prefix

`funcbox dev` mounts a function at a path-prefixed local URL
(`/dev/<owner>/<name>/...`) for convenience, and does **not** strip that
prefix before calling the guest handler — so vinext's own client-side
router sees e.g. `/dev/vinext/about` as the request path, which doesn't
match any of its routes (`/`, `/about`, `/api/hello`), and 404s. This is
purely a `funcbox dev` presentation detail: a real deployment is
Host-routed (a function's own subdomain), so the guest always sees an
unprefixed path there — the mismatch above cannot occur outside local
`dev` testing. It affects any path-sensitive routing framework mounted
through `funcbox dev`, not something specific to this example; fixing it
in `funcbox dev` itself (stripping the mount prefix before invoking the
handler) is tracked separately from this example and intentionally not
bundled into this change.

What DOES work through `funcbox dev` as-is: the pool boots successfully
(no more crash at warmup), and a request to `/dev/vinext/...` renders a
real, correctly-styled vinext 404 page — i.e., the whole RSC/SSR pipeline
executes end-to-end and produces a coherent (if route-mismatched) response,
rather than crashing before any request is ever served. See "Verified
working" above for confirmation of the actual app routes, checked directly
against the pool with unprefixed paths.

## Build / run

```sh
pnpm install
pnpm build                                   # -> dist/server, dist/assets.js
go run ./cmd/funcbox dev examples/vinext      # boots; see the path-prefix note above for local route testing
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

`dist/` is **not** committed: `node_modules` is required to build it
(525 MiB here), and what would need to deploy (`dist/server/` +
`dist/assets.js`, ~1.3 MiB combined) is still over this repo's informal
"commit if small" threshold for examples.

Regenerate with `pnpm install && pnpm build`.

## Known limitations / not tested

Beyond the path-prefix caveat above, these vinext features exist but
weren't exercised by this minimal example and are untested against
funcbox: Server Actions, middleware, ISR/`"use cache"`, streaming SSR, and
Cloudflare bindings via `cloudflare:workers` (that import itself would hit
the same kind of externalization machinery `node:async_hooks` did, and
needs workerd-specific bindings to resolve at runtime, which funcbox does
not provide — this is a different gap than the now-resolved
`node:async_hooks` one).
