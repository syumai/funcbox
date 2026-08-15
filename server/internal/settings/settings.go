// Package settings defines the JSON schema stored in
//
// Settings are stored schema-less (a JSON TEXT column) because the field
// set changes often; this package is where that JSON is given a typed,
// validated Go shape. login_rules is the one exception -- it is normalized
// into its own table (store.LoginRule) since it's list/order-manipulated,
// not just read/replaced wholesale like the rest of the settings document.
//
// This package is server-only: it is not imported by policy (the
// package shared with the funcbox CLI), though it produces values that
// feed into policy.FetchPolicy/policy.Visibility at the call site.
package settings

import (
	"encoding/json"
	"fmt"

	"github.com/syumai/funcbox/bundle"
	"github.com/syumai/funcbox/policy"
)

// FetchPolicy is one level's JSON-serializable fetch permission
// declaration; see policy for the runtime mode/pattern types this
// converts into.
type FetchPolicy struct {
	Mode  string   `json:"mode"` // deny | allowlist | allow-all
	Allow []string `json:"allow,omitempty"`
}

// Policy converts f into a policy.FetchPolicy, ready to be intersected via
// policy.Effective.
func (f FetchPolicy) Policy() (policy.FetchPolicy, error) {
	mode, err := policy.ParseFetchMode(f.Mode)
	if err != nil {
		return policy.FetchPolicy{}, err
	}
	allow := make([]policy.Pattern, 0, len(f.Allow))
	for _, s := range f.Allow {
		p, err := policy.ParsePattern(s)
		if err != nil {
			return policy.FetchPolicy{}, err
		}
		allow = append(allow, p)
	}
	return policy.FetchPolicy{Mode: mode, Allow: allow}, nil
}

// §5.4's "limits:" block).
type Limits struct {
	InvokeTimeoutMax  string `json:"invoke_timeout_max,omitempty"`  // Go duration string, e.g. "60s"
	MemoryMax         int64  `json:"memory_max,omitempty"`          // bytes
	BundleUnpackedMax int64  `json:"bundle_unpacked_max,omitempty"` // bytes; clamped to <= bundle.MaxUnpackedBytes
}

// Org is the organization-wide settings document (organizations.settings;
// login_rules are stored separately -- see this package's doc comment).
//
// allow_workspace_creation was removed here (workspace creation is now
// decided solely by store.RoleAdmin/store.RoleWorkspaceManager -- see
// internal/authz.CanCreateWorkspace). json.Unmarshal silently ignores
// that key if it's still present in a persisted settings blob, so no
// migration of the stored JSON is required; ParseOrg's round trip simply
// no longer reproduces it.
type Org struct {
	// Language is the default dashboard language for the organization. It is
	// overridden by a user's individual language preference when set.
	Language           string      `json:"language"`
	AllowUserFunctions bool        `json:"allow_user_functions"`
	AllowNodejsCompat  bool        `json:"allow_nodejs_compat"`
	DefaultVisibility  string      `json:"default_visibility"`
	MaxVisibility      string      `json:"max_visibility"`
	FetchPolicy        FetchPolicy `json:"fetch_policy"`
	Limits             Limits      `json:"limits"`

	// ExtraIDTokenAudiences lists additional OIDC `aud` values accepted
	// for function-invoke ID tokens beyond the configured OIDC client ID
	// audience, letting a service-to-service caller present an ID token
	// issued for a different client.
	ExtraIDTokenAudiences []string `json:"extra_id_token_audiences,omitempty"`

	// SessionDurationSeconds overrides the default 7-day sliding session
	// duration. 0 (the zero value) means use the default.
	SessionDurationSeconds int64 `json:"session_duration_seconds,omitempty"`

	// LogRetentionDays bounds how long invocation logs (store.InvocationLog)
	// are kept before a periodic cleanup sweep (SQL backends) or a TTL
	// "use the default" (DefaultLogRetentionDays).
	LogRetentionDays int `json:"log_retention_days,omitempty"`

	// RequireApproval gates account-creation approval: when true, a
	// brand-new (non-bootstrap) user is created with
	// store.UserStatusPending instead of store.UserStatusActive, and stays
	// locked out of the dashboard/API until an Org Admin approves them
	// (PATCH /api/v1/org/users/{id} with status=active). Login rules are
	// still evaluated first -- a denied login never even reaches pending.
	RequireApproval bool `json:"require_approval"`

	// MaxFunctionsPerUser caps how many personal-scope functions
	// (owner_type=user) a single user may OWN, checked only at new-function
	// creation. 0 (the zero value) means unlimited. Lowering this never
	// deletes functions already over the new limit; it only blocks further
	// new ones.
	MaxFunctionsPerUser int `json:"max_functions_per_user,omitempty"`

	// OpenMode gates the public-registration posture: registration opens
	// (bootstrap seeds a default-allow login
	// rule instead of the normal email_exact(admin)+default-deny pair --
	// see internal/auth's seedBootstrapLoginRule), the dashboard function
	// list narrows to a non-admin caller's own functions, the invoke path
	// stops injecting X-Funcbox-Caller-* headers unless
	// ExposeCallerIdentity opts back in, and the workspace feature is
	// disabled outright (internal/api's routeWorkspaces 404s,
	// visibility: workspace is rejected at deploy time, and
	// PATCH /api/v1/org refuses to turn this on while any workspace still
	// exists). Defaults to false. FUNCBOX_OPEN_MODE=1 seeds this to true
	// ONLY at the very first organization's bootstrap; after that the
	// organization setting here is authoritative and the env var is never
	// consulted again.
	OpenMode bool `json:"open_mode"`

	// ExposeCallerIdentity re-enables X-Funcbox-Caller-Email injection on
	// the invoke path while OpenMode is on (see OpenMode's doc comment).
	// It has no effect when OpenMode is false, since normal mode always
	// injects the header regardless of this setting. Defaults to false.
	ExposeCallerIdentity bool `json:"expose_caller_identity"`
}

// DefaultLogRetentionDays is the invocation-log retention period applied
// when an organization hasn't set LogRetentionDays.
const DefaultLogRetentionDays = 7

// DefaultOrg returns the organization settings applied to a freshly
// documented defaults). Login rules are NOT part of this: an empty rule
// set is itself the documented default ("初期値は deny + 初回ユーザーの
// み例外"), handled by internal/auth rather than here.
func DefaultOrg() Org {
	return Org{
		Language:           "en",
		AllowUserFunctions: true,
		AllowNodejsCompat:  true,
		DefaultVisibility:  "org",
		MaxVisibility:      "public",
		FetchPolicy:        FetchPolicy{Mode: "deny"},
		LogRetentionDays:   DefaultLogRetentionDays,
		Limits: Limits{
			InvokeTimeoutMax:  "60s",
			MemoryMax:         256 << 20,
			BundleUnpackedMax: bundle.MaxUnpackedBytes,
		},
	}
}

// IsLanguage reports whether language is one of the dashboard languages
// currently supported by funcbox.
func IsLanguage(language string) bool {
	return language == "en" || language == "ja"
}

// EffectiveLanguage resolves the dashboard language. A user's explicit
// preference wins over the organization's default; English is the final
// fallback for older or malformed persisted settings.
func EffectiveLanguage(userLanguage, orgLanguage string) string {
	if IsLanguage(userLanguage) {
		return userLanguage
	}
	if IsLanguage(orgLanguage) {
		return orgLanguage
	}
	return "en"
}

// ParseOrg decodes raw (an organizations.settings JSON blob) on top of
// DefaultOrg, so that missing keys -- including an entirely empty "{}",
// the value BootstrapFirstUser writes -- fall back to their documented
// default rather than Go's JSON zero value. BundleUnpackedMax is clamped
// to the system-wide absolute ceiling (bundle.MaxUnpackedBytes) per
func ParseOrg(raw []byte) (Org, error) {
	o := DefaultOrg()
	if len(raw) == 0 {
		return o, nil
	}
	if err := json.Unmarshal(raw, &o); err != nil {
		return Org{}, fmt.Errorf("settings: parse org settings: %w", err)
	}
	if !IsLanguage(o.Language) {
		o.Language = "en"
	}
	if o.Limits.BundleUnpackedMax <= 0 || o.Limits.BundleUnpackedMax > bundle.MaxUnpackedBytes {
		o.Limits.BundleUnpackedMax = bundle.MaxUnpackedBytes
	}
	return o, nil
}

// JSON serializes o back to its storage form.
func (o Org) JSON() []byte {
	b, err := json.Marshal(o)
	if err != nil {
		// Org contains only marshalable field types; this cannot fail.
		panic(fmt.Sprintf("settings: marshal Org: %v", err))
	}
	return b
}

// Workspace is a workspace's settings document (workspaces.settings,
type Workspace struct {
	FetchPolicy FetchPolicy `json:"fetch_policy"`
	// DefaultVisibility/MaxVisibility are empty to mean "no workspace-level
	// override" (i.e. don't further narrow the org's default/max); a
	// non-empty MaxVisibility can only narrow, never widen, the org's
	DefaultVisibility string `json:"default_visibility,omitempty"`
	MaxVisibility     string `json:"max_visibility,omitempty"`
	// MemberCanDeploy: false restricts function deploy/env-management to
	MemberCanDeploy bool `json:"member_can_deploy"`
	// MaxFunctionsPerMember caps how many of THIS workspace's functions a
	// single member may have CREATED (functions.created_by, not ownership
	// -- the workspace's functions are shared, but the creation limit
	// applies per member), checked only at
	// new-function creation. 0 means unlimited. A function with a nil
	// CreatedBy (pre-migration, no version to backfill from) never counts
	// toward any member's total.
	MaxFunctionsPerMember int `json:"max_functions_per_member,omitempty"`
}

// DefaultWorkspace returns the settings applied to a freshly created
// workspace: unconstrained at the workspace level (an "allow-all" fetch
// mode imposes no additional restriction in policy.Effective's
// intersection, and an empty MaxVisibility likewise defers entirely to the
// organization's ceiling), with members allowed to deploy.
func DefaultWorkspace() Workspace {
	return Workspace{
		FetchPolicy:     FetchPolicy{Mode: "allow-all"},
		MemberCanDeploy: true,
	}
}

// ParseWorkspace decodes raw (a workspaces.settings JSON blob) on top of
// DefaultWorkspace, the same way ParseOrg does for organizations.
func ParseWorkspace(raw []byte) (Workspace, error) {
	w := DefaultWorkspace()
	if len(raw) == 0 {
		return w, nil
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return Workspace{}, fmt.Errorf("settings: parse workspace settings: %w", err)
	}
	return w, nil
}

// JSON serializes w back to its storage form.
func (w Workspace) JSON() []byte {
	b, err := json.Marshal(w)
	if err != nil {
		panic(fmt.Sprintf("settings: marshal Workspace: %v", err))
	}
	return b
}
