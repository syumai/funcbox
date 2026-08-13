// Package server implements funcbox-server's top-level HTTP routing
// skeleton (see tmp/02-architecture.md and tmp/07-http-api.md §7.1):
// health checks, the reserved first-path-segment dispatch to
// dashboard/api/auth/dev/assets, the function-invoke catch-all, and
// the panic-recovery and request-logging middleware every request
// passes through.
//
// This package is server-only: unlike bundle, manifest,
// and policy, it is not shared with the funcbox CLI binary,
// so it is free to depend on server-only packages as the server grows. It
// must not be imported by the shared packages.
package server
