// Package policy implements fetch host-pattern matching, the 3-level
// (organization ∩ workspace ∩ manifest) permission intersection, and
// the SSRF guard used by the runtime's Resolve/Dial hooks (see
//
// Pattern syntax validation lives here (rather than in the manifest
// package) specifically so that manifest can depend on
// policy without creating an import cycle.
//
// This package is shared between the funcbox CLI and funcbox-server
// packages (bundle, manifest, and later runtime), it must never
// import server-only packages (store, blob, auth, api, dashboard).
package policy
