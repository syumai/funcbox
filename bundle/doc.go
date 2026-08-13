// Package bundle implements a guarded tar.gz unpacker and a canonical
// (deterministic) tar.gz packer for funcbox function bundles.
//
// Unpack is a security boundary: it streams gzip and tar decoding
// together and enforces size, file-count, path, and entry-type limits
// while reading, so that a malicious or oversized archive is rejected
// without ever holding more than the configured limit of decompressed
// data in memory. Pack re-serializes a validated file set into a
// byte-identical archive for any given content, which lets the server
// perform content-addressed deduplication on stored bundles.
//
// This package is shared between the funcbox CLI and funcbox-server
// packages (manifest, policy, and later runtime), it must never import
// server-only packages (store, blob, auth, api, dashboard).
package bundle
