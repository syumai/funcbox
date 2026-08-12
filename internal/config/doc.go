// Package config loads funcbox-server's runtime configuration from
// environment variables (see tmp/02-architecture.md "設定（環境変数）").
//
// This package is server-only: unlike internal/bundle, internal/
// manifest, and internal/policy, it is not shared with the funcbox
// CLI binary, so it is free to depend on server-only packages as the
// server grows. It must not be imported by the shared packages.
package config
