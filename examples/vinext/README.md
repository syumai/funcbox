# vinext

**Status: working**, including locally under `funcbox dev` (see "Build /
run" below). The `node:async_hooks` blocker that used to make this "does
not run yet" is resolved: funcbox now brings its own execution pool
in-house (`runtime/enginepool`) and can wire up `nodejs.Install`, which is
exactly what `AsyncLocalStorage` needs.

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

Verified both directly against `runtime/enginepool.Pool` and through
`funcbox dev` itself (which now serves every request at the dev server's
root with the request path passed through unstripped — see "Build / run"
below), with a plain, unprefixed request path, exactly matching what a
real deploy's Host-routed invocation looks like:

- `GET /` → 200, real server-rendered HTML (`<h1>Build Next.js-style
  apps...`), referencing `/_next/static/chunks/counter-B3POtwm5.js` and
  the other hashed asset paths that `dist/assets.js` also embeds.
- `GET /about` → 200, real per-request SSR: two consecutive requests
  return DIFFERENT bodies with different embedded timestamps (confirmed:
  not a cached replay).
- `GET /api/hello` → 200 `{"message":"Hello from vinext on funcbox"}`.
- `GET /_next/static/chunks/counter-B3POtwm5.js` → 200,
  `content-type: text/javascript; charset=utf-8`; the chunk's body
  contains the real `useState` counter implementation, served by
  `funcbox-entry.js`'s wrapper (not vinext's own handler).

This directly disproves the previous blocker: `AsyncLocalStorage` (from
`node:async_hooks`) is reachable and works correctly inside
`runtime/enginepool`'s NodeCompat mode for the request-scoped
`await`-everything-inside-`run()` pattern — see
`runtime/enginepool/nodecompat_test.go`'s dedicated ALS isolation tests,
sequential AND concurrent. **It does NOT, however, survive into
`next/headers`' `headers()`/`cookies()`** — see "Known limitations" below;
that's a separate, narrower gap discovered after this section was
originally written.

## Build / run

```sh
pnpm install
pnpm build                                   # -> dist/server, dist/assets.js
go run ./cmd/funcbox dev examples/vinext      # serves the app at http://127.0.0.1:8787/
```

`funcbox dev` serves the function at the dev server's root with the
request path passed through unstripped, mirroring production's
Host-routed invocation shape — so vinext's own client-side router sees
`/`, `/about`, etc. exactly as it would in production, and this app works
locally at `http://127.0.0.1:8787/` with no route mismatch. (`funcbox
dev` also still serves the same function at `/dev/vinext/...`, mirroring
production's path-based invocation shape — that request path is passed
through unstripped too, so a path-sensitive router like vinext's will not
match its own routes there; use the root URL for local route testing.)

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

These vinext features exist but weren't exercised by this minimal example
and are untested against funcbox: Server Actions, middleware,
ISR/`"use cache"`, and
Cloudflare bindings via `cloudflare:workers` (that import itself would hit
the same kind of externalization machinery `node:async_hooks` did, and
needs workerd-specific bindings to resolve at runtime, which funcbox does
not provide — this is a different gap than the now-resolved
`node:async_hooks` one).

### `next/headers`' `headers()` / `cookies()` do not work (proven, not just untested)

Any Server Component, Route Handler, or Server Action that calls
`headers()` or `cookies()` from `next/headers` throws at request time:

```
Error: headers() can only be called from a Server Component, Route
Handler, or Server Action. Make sure you're not calling it from a
Client Component.
```

This is a real per-request AsyncLocalStorage context loss, reproduced
directly against `runtime/enginepool.Pool` with the same build that runs
correctly under vinext's own `vinext start` (Node) production server —
so it is specific to funcbox's guest engine, not this app or its build.

**Root cause (confirmed upstream, not a funcbox bug):**
go-spidermonkey's `compat/nodejs` `AsyncLocalStorage` (which funcbox
depends on as a public module and does not fork) is a plain single-slot
polyfill: the store is held for the duration of `als.run(store, fn)` and
reset the instant `fn`'s own return value settles — see that package's
`js/extras.js` and, in the same module,
`docs/engine-followups.md` item 8 ("`async_hooks`: a store cannot outlive
the call that established it"), which documents this exact gap and its
effect on Next.js 15 dynamic SSR. vinext's bundled request-context module
(`unified-request-context-*.js` in the build output) does
`asyncLocalStorageInstance.run(store, renderFn)` where `renderFn` calls
React's `renderToReadableStream(...)` and returns the resulting stream
SYNCHRONOUSLY — the actual render (and any `headers()`/`cookies()` call
inside it) happens later, as the stream is pulled, by which point the slot
has already been reset. `runtime/enginepool/nodecompat_test.go`'s
`TestNodeCompatAsyncLocalStorageLostAcrossStreamedResponse` pins this
behavior with a minimal (non-vinext) repro and explains what to update if
go-spidermonkey ever gains the engine async-context hooks item 8 asks for.

**What this does and does NOT block.** The store loss only bites code that
actually reads the store after the fact — not dynamic SSR in general:

- Works: static/ISR pages (`app/page.tsx`, `revalidate`), a per-request
  dynamic Server Component that does NOT call `headers()`/`cookies()`
  (verified: a page rendering `new Date().toISOString()` on every request
  behaves identically to `app/about/page.tsx` here), and a Route Handler
  that doesn't touch `next/headers`.
- Fails: any code path — Server Component OR Route Handler — that calls
  `headers()`, `cookies()`, or (untested but almost certainly, by the same
  mechanism) `draftMode()`, per-request `connection()`, or reads the
  request context for cache-tag/revalidation bookkeeping.

So a funcbox-hosted vinext app (e.g. a future dashboard port) is not
required to give up per-request dynamic rendering to work around this —
only `next/headers` (and any other API backed by the same request-context
AsyncLocalStorage) needs to be avoided. In practice that mostly means
reading whatever `headers()`/`cookies()` would have provided some other
way — e.g. by having `funcbox-entry.js` forward the specific values a page
needs (a cookie, an auth token) through a mechanism that doesn't round-trip
through this ALS (a query param, a custom request-scoped global set before
`vinextHandler.fetch()` is called, etc.) — rather than calling into
`next/headers` from app code at all.

**Mitigation shipped here:** none is possible in funcbox's own code — the
store reset happens entirely inside vinext's bundled guest JS, before any
call ever reaches funcbox's host-side glue (`runtime/enginepool/js/glue.js`)
or Go code. This section, and the regression test above, are the
mitigation: an accurate, evidence-backed record of the gap so it isn't
rediscovered the hard way, plus a canary that will fail loudly (like
go-spidermonkey's own `TestNextJSFlagship` does for the same root cause)
if the upstream engine gap ever closes.
