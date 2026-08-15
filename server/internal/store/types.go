// Package store defines the domain model and repository interfaces for
// funcbox's control-plane data (organizations, users, workspaces,
// functions, sessions, tokens, audit log). Interfaces are designed for
// DynamoDB-compatible access patterns (lookup by key, list by owner) so
// that a single-table DynamoDB backend can implement them alongside SQL
//
// All entity IDs are ULID strings (lexicographically sortable by creation
// time). All entities carry CreatedAt/UpdatedAt timestamps.
package store

import "time"

// OwnerType distinguishes whether a function is owned by an
// individual user or a workspace.
type OwnerType string

const (
	OwnerTypeUser      OwnerType = "user"
	OwnerTypeWorkspace OwnerType = "workspace"
)

// Role is an organization- or workspace-scoped role.
//
// At the organization level, User.Role takes one of three values, ordered
// admin > workspace_manager > member: RoleWorkspaceManager carries every
// RoleMember permission plus the ability to create workspaces, and is
// otherwise treated as a member-equivalent -- it grants no other admin
// capability (org settings,
// user management, audit logs, other-workspace management all stay
// admin-only; see internal/authz).
//
// At the workspace level, WorkspaceMember.Role only ever takes RoleAdmin
// or RoleMember (a workspace's own admin/member distinction is unrelated
// to the organization-wide workspace_manager tier).
type Role string

const (
	RoleAdmin            Role = "admin"
	RoleWorkspaceManager Role = "workspace_manager"
	RoleMember           Role = "member"
)

// LoginRuleType selects how LoginRule.Value is matched against a
// prospective user's email during first-login authorization.
type LoginRuleType string

const (
	LoginRuleTypeEmailDomain LoginRuleType = "email_domain"
	LoginRuleTypeEmailExact  LoginRuleType = "email_exact"
	LoginRuleTypeEmailGlob   LoginRuleType = "email_glob"
	LoginRuleTypeDefault     LoginRuleType = "default"
)

// LoginRuleAction is the outcome applied when a LoginRule matches.
type LoginRuleAction string

const (
	LoginRuleActionAllow LoginRuleAction = "allow"
	LoginRuleActionDeny  LoginRuleAction = "deny"
)

// Provider identifies the identity provider a User authenticated through.
// Exactly one provider is active on any given deployment
// (FUNCBOX_AUTH_PROVIDER), but a User's own Provider can
// still differ from the currently active one after an account link (see
// internal/auth's GitHub login flow) -- the org may have since switched.
type Provider string

const (
	ProviderGoogle Provider = "google"
	ProviderGitHub Provider = "github" // reserved; not yet issued
)

// UserStatus is a User's account state.
type UserStatus string

const (
	// UserStatusActive is a normally usable account.
	UserStatusActive UserStatus = "active"
	// UserStatusPending is awaiting Org Admin approval (organization
	// setting require_approval). Unlike UserStatusDisabled, a pending
	// user's session/API-token
	// authentication still succeeds (internal/auth's
	// validateAuthenticatable) so the dashboard can show the "access
	// request pending" page and the management API can respond with a
	// distinguishable 403 pending_approval (internal/api's
	// requirePendingApproved) instead of an indistinguishable 401.
	// Function-invocation caller resolution (internal/auth's
	// validateActiveUser / ResolveInvokeCaller) still treats pending the
	// same as disabled -- not-a-member -- since that path never went
	// through approval semantics to begin with.
	UserStatusPending UserStatus = "pending"
	// UserStatusDisabled is an account an Org Admin has deactivated
	// (formerly users.disabled = true). Also used for rejected approval
	// requests.
	UserStatusDisabled UserStatus = "disabled"
)

// Organization is the single, singleton tenant row (ID is always "org").
type Organization struct {
	ID          string // always "org"
	Name        string
	Settings    []byte // JSON; validated/interpreted by the caller
	SettingsGen int    // bumped on every settings update; invalidates policy caches
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// LoginRule is one ordered entry in the organization's first-login
// allow/deny list.
type LoginRule struct {
	ID        string
	Ord       int // evaluation order, ascending
	RuleType  LoginRuleType
	Value     string
	Action    LoginRuleAction
	CreatedAt time.Time
	UpdatedAt time.Time
}

// User is an individual, SSO-authenticated account.
type User struct {
	ID string
	// Provider and ProviderSubject together identify the account at its
	// identity provider (formerly a single Google-only GoogleSub field);
	// UNIQUE is (Provider, ProviderSubject).
	Provider        Provider
	ProviderSubject string
	Email           string
	Name            string
	Role            Role // organization-wide role: admin | workspace_manager | member
	Status          UserStatus
	// Language is the user's dashboard language preference ("en" or "ja").
	// An empty value means inherit the organization's language preference.
	Language  string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// PublicUserID maps a user-facing User ID to the user's immutable internal
// database ID.
type PublicUserID struct {
	UserID         string // lowercase DNS-label form
	InternalUserID string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Workspace is a shared owner of functions, with its own membership list.
type Workspace struct {
	ID          string
	Name        string // display name; it need not be unique
	Settings    []byte // JSON
	SettingsGen int
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// WorkspaceMember links a User to a Workspace with a role.
type WorkspaceMember struct {
	WorkspaceID string
	UserID      string
	Role        Role // admin | member
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Function is a named deployable unit, owned by either a user or a
// workspace. ActiveVersionID is nil until a version has been activated.
type Function struct {
	ID              string
	OwnerType       OwnerType
	OwnerID         string
	Name            string // DNS-label form, claimed installation-wide
	Description     string
	ActiveVersionID *string
	// CreatedBy is the User.ID that created this function, nil for
	// functions migrated from a schema that predates this column with no
	// function_versions to backfill from (see the 0009 migration). Distinct
	// from owner: in a workspace-owned function, CreatedBy identifies which
	// member created it, needed for per-member function-count limits (see
	// FunctionRepo.CountByWorkspaceAndCreator). A nil CreatedBy is excluded
	// from creator-scoped counts.
	CreatedBy *string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// BundleFile describes one file within a function's canonical bundle, for
// dashboard display. It is stored, JSON-encoded, in
// FunctionVersion.Files.
type BundleFile struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// FunctionVersion is an immutable deployment record. Once created it is
// never updated; rollback is performed by repointing
// Function.ActiveVersionID at a different, already-existing version.
type FunctionVersion struct {
	ID           string
	FunctionID   string
	Manifest     []byte // normalized manifest JSON; the runtime reads only this
	MainPath     string
	BundleHash   string // sha256 hex of the canonical tar.gz; the blob store key
	BundleSize   int64  // compressed size in bytes
	UnpackedSize int64  // unpacked size in bytes (<= manifest-enforced limit)
	Files        []byte // JSON-encoded []BundleFile, for dashboard display
	CreatedBy    string // User.ID
	Note         string // deploy comment
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// EnvVar is an encrypted environment variable bound to a Function (not a
// specific FunctionVersion), so secret rotation doesn't require a
// redeploy. Only keys also declared in the active version's manifest are
// exposed at runtime.
type EnvVar struct {
	FunctionID string
	Key        string
	ValueEnc   []byte // AES-GCM ciphertext
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// Session is a server-side session for browser (dashboard) auth.
type Session struct {
	ID        string // hash of a random 256-bit token; the cookie carries the raw token
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

// InvokeAuthCode is a short-lived, single-use browser handoff credential.
// ID is the SHA-256 hash of the random value carried in the callback URL;
// the raw value is never persisted.
type InvokeAuthCode struct {
	ID         string
	UserID     string
	FunctionID string
	Host       string
	ReturnTo   string
	ExpiresAt  time.Time
	CreatedAt  time.Time
}

// CLICredential is a long-lived credential minted by the CLI's
// loopback+PKCE browser login flow, persisted as "cli_credentials". It
// carries NO direct management API access itself -- its only role is
// minting short-lived access tokens via POST /api/v1/cli/access-token.
// It replaces the abolished api_tokens/fbx_ API-key mechanism.
//
// Validity is a SLIDING 90-day window measured from LastUsedAt (or, before
// its first use, CreatedAt) -- there is no separate ExpiresAt column;
// every successful access-token mint pushes LastUsedAt (and therefore the
// expiry) forward, exactly like Session's sliding expiry.
type CLICredential struct {
	ID         string
	UserID     string
	Name       string // device name (CLI hostname by default), shown on the dashboard's "connected devices" list
	SecretHash string // sha256 hex of the raw "fbxc_..." secret
	CreatedAt  time.Time
	UpdatedAt  time.Time
	LastUsedAt time.Time // zero until the first access-token mint
}

// CLIAuthCode is a short-lived, single-use PKCE authorization code minted
// by the dashboard's explicit "funcbox CLI login" approval page and
// consumed by POST /api/v1/cli/token to mint a CLICredential. ID is the
// SHA-256 hash of the random code value carried in the loopback callback
// URL; the raw value is never persisted (same pattern as InvokeAuthCode).
type CLIAuthCode struct {
	ID        string
	UserID    string
	Name      string // device name, carried through to the minted CLICredential
	Challenge string // PKCE S256 challenge: base64url(sha256(verifier)), no padding
	ExpiresAt time.Time
	CreatedAt time.Time
}

// AuditLog is an append-only record of a privileged action.
type AuditLog struct {
	ID        string
	ActorID   string
	Action    string // e.g. "function.deploy", "org.settings.update"
	Target    string // e.g. "function:01H..."
	Detail    []byte // JSON
	CreatedAt time.Time
	UpdatedAt time.Time
}

// InvocationLog is one row per function invocation, recording enough to
// render the dashboard's execution-log panel and back `funcbox logs`
// Unlike AuditLog it is not meant to be kept forever: retention is the
// organization's log_retention_days setting (internal/settings), enforced
// by a periodic cleanup sweep for SQL backends and a TTL attribute for
// DynamoDB (see InvocationLogRepo.DeleteOlderThan).
type InvocationLog struct {
	ID         string // ULID; also the sort key / pagination cursor
	FunctionID string
	VersionID  string
	Method     string
	Path       string
	Status     int
	DurationMS int64

	// Stdout/Stderr are the guest's captured console output for this
	// invocation (runtime's Config.Stdout/Stderr writers), each
	// truncated by the caller to a bounded size before Append.
	Stdout string
	Stderr string

	// FetchDecisions is a JSON-encoded []FetchDecision: every outbound
	// fetch ALLOW/DENY decision the invocation's policy hooks made.
	FetchDecisions []byte

	CreatedAt time.Time
}

// FetchDecision is one entry of InvocationLog.FetchDecisions.
type FetchDecision struct {
	Host    string `json:"host"`
	Port    int    `json:"port,omitempty"`
	Allowed bool   `json:"allowed"`
	Stage   string `json:"stage"` // "resolve" | "dial"
}
