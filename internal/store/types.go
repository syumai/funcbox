// Package store defines the domain model and repository interfaces for
// funcbox's control-plane data (organizations, users, workspaces,
// functions, sessions, tokens, audit log). Interfaces are designed for
// DynamoDB-compatible access patterns (lookup by key, list by owner) so
// that a single-table DynamoDB backend can implement them alongside SQL
// backends; see tmp/08-storage-and-db.md.
//
// All entity IDs are ULID strings (lexicographically sortable by creation
// time). All entities carry CreatedAt/UpdatedAt timestamps.
package store

import "time"

// OwnerType distinguishes whether a handle or function is owned by an
// individual user or a workspace.
type OwnerType string

const (
	OwnerTypeUser      OwnerType = "user"
	OwnerTypeWorkspace OwnerType = "workspace"
)

// Role is an organization- or workspace-scoped role.
type Role string

const (
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
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

// User is an individual, Google-SSO-authenticated account.
type User struct {
	ID        string
	GoogleSub string // stable Google subject identifier
	Email     string
	Name      string
	Role      Role // organization-wide role: admin | member
	Disabled  bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Handle is an entry in the shared URL namespace ("/{owner}/{func}") used
// by both users and workspaces. Uniqueness of Handle is enforced as the
// primary key; OwnerID is unique too, so each owner has at most one
// handle.
type Handle struct {
	Handle    string // lowercase DNS-label form
	OwnerType OwnerType
	OwnerID   string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Workspace is a shared owner of functions, with its own membership list.
type Workspace struct {
	ID          string
	Name        string // display name, distinct from its Handle
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
	Name            string // DNS-label form, unique within (OwnerType, OwnerID)
	Description     string
	ActiveVersionID *string
	CreatedAt       time.Time
	UpdatedAt       time.Time
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

// APIToken is a long-lived credential for CLI/API use.
type APIToken struct {
	ID        string
	UserID    string
	TokenHash string // sha256 hex of the raw token
	Name      string
	ExpiresAt time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
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
