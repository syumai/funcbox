// Package dashboard hosts funcbox's own dashboard app (tmp/09-dashboard.md
// §9.3): a hono/jsx application, built entirely at development time with
// pnpm/esbuild (dashboard/, never invoked at runtime -- see the repo root
// Makefile's "server" target) into a single self-contained ESM bundle
// (dist/server.js) and a small set of hashed client assets (dist/assets/).
//
// At runtime this package serves the dashboard exactly the way
// internal/invoke serves a deployed user function: dist/server.js runs
// inside a cfworkers.Pool on funcbox's OWN runtime (go-spidermonkey), not
// Node -- the dashboard is "a privileged internal function", dogfooding the
// same invoker/compat layer every user function goes through. Two things
// make it privileged rather than an ordinary function:
//
//  1. Every request is authenticated (session cookie only, checked BEFORE
//     the pool is ever invoked; an anonymous request is redirected to
//     /auth/login and never reaches the guest) rather than routed through
//     internal/invoke's visibility rules.
//  2. Its env carries exactly one capability no user function has:
//     INTERNAL_API, a binding that calls internal/api's handlers
//     in-process (no HTTP loopback) on the authenticated caller's behalf.
//     See internalapi.go and caller_token.go for how the caller's identity
//     crosses the host/guest boundary safely despite bindings being fixed
//     per POOL INSTANCE, not per request (an env binding, once built at
//     pool warm-up, is reused by every request that instance ever serves).
package dashboard
