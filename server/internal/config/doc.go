// Package config loads funcbox-server's runtime configuration from
//
// This package is server-only: unlike bundle, manifest,
// and policy, it is not shared with the funcbox CLI binary,
// so it is free to depend on server-only packages as the server grows. It
// must not be imported by the shared packages.
package config
