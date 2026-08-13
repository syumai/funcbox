// Package cli implements the funcbox CLI's subcommands (login, deploy, dev,
// rollback, list, logs — tmp/07-http-api.md §7.5). It is used only by
// cmd/funcbox, never by cmd/funcbox-server.
//
// Binary separation (tmp/02-architecture.md "バイナリ分離と依存の最小化",
// tmp/11-module-layout.md): this package may depend on the shared
// packages bundle, manifest, policy, and runtime, plus stdlib and the
// CLI's approved third-party deps (github.com/fsnotify/fsnotify for
// funcbox dev's file watcher). It must NEVER import the server-only
// packages (store, blob, auth, api, service, server, invoke, dashboard,
// config; the last is server-only configuration -- the CLI has its own
// config file handling in this package instead). Since the module split,
// this is enforced structurally rather than just by convention: those
// packages live under server/internal/... in the separate
// github.com/syumai/funcbox/server module, which cmd/funcbox (in the
// root module) cannot import at all -- another module's internal/
// packages aren't importable, and the root module's go.mod doesn't even
// require server/go.mod's dependencies (aws-sdk-go-v2, pgx, ...) to
// build them from. cmd/funcbox/dep_separation_test.go guards the
// remaining risk: a stray new direct dependency creeping into the root
// go.mod itself.
//
// The CLI talks to a funcbox-server ONLY over its HTTP management API
// (client.go) — it never touches a database or blob store directly.
package cli
