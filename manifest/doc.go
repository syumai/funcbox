// Package manifest parses, validates, and normalizes funcbox function
// manifests (funcbox.yaml / funcbox.yml / funcbox.json — see
// tmp/04-manifest.md).
//
// Parse locates and decodes a manifest from an unpacked bundle
// (bundle), producing a Manifest. Validate re-checks a
// Manifest's structural rules independent of parsing, so callers that
// build or mutate a Manifest outside of Parse (for example, the
// deploy API filling in a name supplied as an upload parameter) can
// re-validate it. Normalized converts a Manifest into the
// JSON-serializable shape stored in the database.
//
// This package depends on policy for fetch host-pattern
// syntax validation and the Visibility type, which keeps pattern
// parsing in one place without creating an import cycle (policy does
// not depend on manifest).
//
// This package is shared between the funcbox CLI and funcbox-server
// binaries (see tmp/02-architecture.md). Like the other shared
// packages (bundle, policy, and later runtime), it must never import
// server-only packages (store, blob, auth, api, dashboard).
package manifest
