// §9.3): a hono/jsx application, built entirely at development time with
// pnpm/esbuild (dashboard/, never invoked at runtime -- see the repo root
// Makefile's "server" target) into a single self-contained ESM bundle
// (dist/server.js) and a small set of hashed client assets (dist/assets/).
//
// At runtime this package serves the dashboard exactly the way
// internal/invoke serves a deployed user function: dist/server.js runs
// inside an enginepool.Pool on funcbox's OWN runtime (go-spidermonkey), not
// Node -- the dashboard is "a privileged internal function", dogfooding the
// same invoker/compat layer every user function goes through. Two things
// make it privileged rather than an ordinary function:
//
//  1. Every request is authenticated (session cookie only, checked BEFORE
//     the pool is ever invoked; an anonymous request is redirected to
//     /auth/login and never reaches the guest) rather than routed through
//     internal/invoke's visibility rules.
//  2. It alone is built with a non-nil enginepool.Config.Internal, carrying
//     exactly one capability no user function has: "funcbox:internal",
//     importable only because this pool was constructed with it (see
//     runtime/enginepool's package doc comment) -- internalAPI, an export
//     that calls internal/api's handlers in-process (no HTTP loopback) on
//     the authenticated caller's behalf. See internalapi.go and
//     caller_token.go for how the caller's identity crosses the host/guest
//     boundary safely despite an InternalExport being built once per POOL
//     INSTANCE, not per request, and then reused by every request that
//     instance ever serves.
package dashboard
