// Package policy implements fetch host-pattern matching, the 3-level
// (organization ∩ workspace ∩ manifest) permission intersection, and
// the SSRF guard used by the runtime's Resolve/Dial hooks (see
// tmp/05-auth-and-permissions.md §5.6 and tmp/03-runtime.md §3.4).
//
// Pattern syntax validation lives here (rather than in the manifest
// package) specifically so that internal/manifest can depend on
// internal/policy without creating an import cycle.
//
// This package is shared between the funcbox CLI and funcbox-server
// binaries (see tmp/02-architecture.md). Like the other shared
// packages (bundle, manifest, and later runtime), it must never
// import server-only packages (store, blob, auth, api, dashboard).
package policy
