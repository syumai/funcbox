// Package cli implements the funcbox CLI's subcommands (login, deploy, dev,
// rollback, list, logs — tmp/07-http-api.md §7.5). It is used only by
// cmd/funcbox, never by cmd/funcbox-server.
//
// Binary separation (tmp/02-architecture.md "バイナリ分離と依存の最小化"):
// this package may depend on the shared packages bundle,
// manifest, policy, and runtime, plus stdlib and
// the CLI's approved third-party deps (github.com/fsnotify/fsnotify for
// funcbox dev's file watcher). It must NEVER import internal/store,
// internal/blob, internal/auth, internal/api, internal/service,
// internal/server, internal/invoke, internal/dashboard, or internal/config
// (the last is server-only configuration; the CLI has its own config file
// handling in this package instead). cmd/funcbox/dep_separation_test.go
// enforces this mechanically via `go list -deps`.
//
// The CLI talks to a funcbox-server ONLY over its HTTP management API
// (client.go) — it never touches a database or blob store directly.
package cli
