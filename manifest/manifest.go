package manifest

import (
	"time"

	"github.com/syumai/funcbox/policy"
)

// Manifest is the parsed, typed form of a funcbox function manifest
// for the field semantics.
//
// Fields that are optional in the source manifest and have no
// context-free default (Timeout, Memory, Visibility) are represented
// as pointers: nil means "not specified in this manifest", and the
// effective value is resolved later by intersecting with
// organization/workspace policy (see policy and
type Manifest struct {
	// Source is the filename the manifest was parsed from
	// ("funcbox.yaml", "funcbox.yml", or "funcbox.json"), or "" if no
	// manifest file was present in the bundle (all-defaults mode; see
	Source string

	Name        string
	Owner       string
	Main        string
	Description string

	// Timeout is nil when not specified; the effective timeout is
	// min(manifest, workspace limit, org limit).
	Timeout *time.Duration
	// Memory is the instance memory limit in bytes; nil when not
	// specified; the effective value is clamped the same way as
	// Timeout.
	Memory *int64

	Compat      Compat
	Permissions Permissions
	Env         []string

	// Visibility is nil when not specified; the caller applies the
	Visibility *policy.Visibility
}

// Compat holds the manifest's compat.* settings.
type Compat struct {
	// Nodejs enables Node.js-compatible module resolution. Defaults
	// to false.
	Nodejs bool
}

// Permissions holds the manifest's permissions.* settings.
type Permissions struct {
	Fetch FetchPermission
}

// FetchPermission is the manifest-level fetch policy declaration.
// Mode defaults to policy.FetchModeDeny when the manifest omits the
// permissions.fetch section entirely.
type FetchPermission struct {
	Mode  policy.FetchMode
	Allow []policy.Pattern
}

// FetchPolicy converts the manifest's fetch permission declaration
// into a policy.FetchPolicy, ready to be intersected with
// organization/workspace levels via policy.Effective.
func (f FetchPermission) FetchPolicy() policy.FetchPolicy {
	return policy.FetchPolicy{Mode: f.Mode, Allow: f.Allow}
}
