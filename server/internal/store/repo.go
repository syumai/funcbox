package store

import (
	"context"
	"time"
)

// OrganizationRepo manages the singleton Organization row and its ordered
// LoginRule list.
type OrganizationRepo interface {
	// Get returns the organization. Returns ErrNotFound before
	// BootstrapFirstUser has run.
	Get(ctx context.Context) (*Organization, error)

	// Update persists o (including bumping SettingsGen, which the caller
	// is responsible for incrementing) and updates UpdatedAt.
	Update(ctx context.Context, o *Organization) error

	// ListLoginRules returns rules ordered by Ord ascending.
	ListLoginRules(ctx context.Context) ([]*LoginRule, error)

	// ReplaceLoginRules atomically replaces the entire login rule list.
	ReplaceLoginRules(ctx context.Context, rules []*LoginRule) error
}

// UserRepo manages User accounts.
type UserRepo interface {
	Create(ctx context.Context, u *User) error
	ByID(ctx context.Context, id string) (*User, error)
	ByProviderSubject(ctx context.Context, provider Provider, subject string) (*User, error)
	ByEmail(ctx context.Context, email string) (*User, error)
	Update(ctx context.Context, u *User) error
	List(ctx context.Context) ([]*User, error)
}

// PublicUserIDRepo manages public User IDs.
type PublicUserIDRepo interface {
	Create(ctx context.Context, id *PublicUserID) error
	ByUserID(ctx context.Context, userID string) (*PublicUserID, error)
	ByOwner(ctx context.Context, internalUserID string) (*PublicUserID, error)

	// Rename changes a public User ID while preserving its internal user.
	// It fails with ErrConflict if newUserID is already taken.
	Rename(ctx context.Context, oldUserID, newUserID string) error

	Delete(ctx context.Context, userID string) error
}

// WorkspaceRepo manages Workspaces and their membership.
type WorkspaceRepo interface {
	Create(ctx context.Context, w *Workspace) error
	ByID(ctx context.Context, id string) (*Workspace, error)
	Update(ctx context.Context, w *Workspace) error
	Delete(ctx context.Context, id string) error

	AddMember(ctx context.Context, m *WorkspaceMember) error
	RemoveMember(ctx context.Context, workspaceID, userID string) error
	UpdateMemberRole(ctx context.Context, workspaceID, userID string, role Role) error
	ListMembers(ctx context.Context, workspaceID string) ([]*WorkspaceMember, error)

	// ListForUser returns every workspace userID is a member of.
	ListForUser(ctx context.Context, userID string) ([]*Workspace, error)

	// ListAll returns every workspace in the organization for an
	// organization administrator's unrestricted workspace list.
	ListAll(ctx context.Context) ([]*Workspace, error)
}

// FunctionRepo manages Functions, their immutable FunctionVersions, and
// their EnvVars.
type FunctionRepo interface {
	Create(ctx context.Context, f *Function) error
	ByID(ctx context.Context, id string) (*Function, error)
	// ByName resolves an active installation-global function-name claim.
	ByName(ctx context.Context, name string) (*Function, error)
	ByOwnerAndName(ctx context.Context, ownerType OwnerType, ownerID, name string) (*Function, error)
	ListByOwner(ctx context.Context, ownerType OwnerType, ownerID string) ([]*Function, error)

	// CountByOwner returns the number of functions owned by (ownerType,
	// ownerID) -- for a user owner this is a personal-scope function count
	// (owner == creator there, so counting by ownership is equivalent to,
	// and simpler than, counting by CreatedBy). max_functions_per_user
	// checks this with ownerType=user.
	CountByOwner(ctx context.Context, ownerType OwnerType, ownerID string) (int, error)

	// CountByWorkspaceAndCreator returns the number of functions owned by
	// workspace wsID whose CreatedBy is userID -- the per-member count
	// max_functions_per_member checks, since a workspace's functions are
	// shared but the creation limit applies
	// per member. Functions with a nil CreatedBy (pre-migration, no
	// version to backfill from) never count toward any user's total.
	CountByWorkspaceAndCreator(ctx context.Context, wsID, userID string) (int, error)

	// ListVisibleTo returns every function owned by userID directly or by
	// any workspace userID is a member of (dashboard function list).
	ListVisibleTo(ctx context.Context, userID string) ([]*Function, error)

	// ListAll returns every function in the organization, regardless of
	// owner. It is used for an organization administrator's unrestricted
	// function list.
	ListAll(ctx context.Context) ([]*Function, error)

	Update(ctx context.Context, f *Function) error
	Delete(ctx context.Context, id string) error

	// CreateVersion inserts an immutable FunctionVersion. Versions are
	// never updated after creation; see FunctionVersion doc comment.
	CreateVersion(ctx context.Context, v *FunctionVersion) error
	Version(ctx context.Context, id string) (*FunctionVersion, error)

	// ListVersions returns the most recent versions of funcID, newest
	// first, capped at limit (0 = backend default).
	ListVersions(ctx context.Context, funcID string, limit int) ([]*FunctionVersion, error)

	SetEnv(ctx context.Context, funcID, key string, valueEnc []byte) error
	DeleteEnv(ctx context.Context, funcID, key string) error
	ListEnv(ctx context.Context, funcID string) (map[string][]byte, error)
}

// SessionRepo manages server-side dashboard sessions.
type SessionRepo interface {
	Create(ctx context.Context, s *Session) error

	// Refresh extends the session identified by id to newExpiresAt,
	// implementing the sliding-expiry policy. It returns ErrNotFound if id
	// doesn't exist (this deliberately does
	// NOT filter on current expiry the way Get does: a session that's
	// already expired has no row for a caller to have raced against, so
	// the only way this returns ErrNotFound is "no such id", same as
	// Delete).
	Refresh(ctx context.Context, id string, newExpiresAt time.Time) error

	// Get returns the session identified by id, as long as it has not
	// expired as of now. Returns ErrNotFound both when id is unknown and
	// when the session has expired (now >= ExpiresAt); the two are
	// indistinguishable to callers by design, matching how a DynamoDB TTL
	// attribute makes expired items transparently disappear. now is an
	// explicit parameter (rather than time.Now() internally) so callers
	// and tests can pin the clock.
	Get(ctx context.Context, id string, now time.Time) (*Session, error)

	Delete(ctx context.Context, id string) error

	// DeleteExpired removes every session with ExpiresAt <= now and
	// returns the count removed. Intended for periodic cleanup; Get
	// already filters expired sessions on read, so this is purely
	// housekeeping.
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}

// InvokeAuthCodeRepo manages atomic, one-time browser SSO handoffs.
type InvokeAuthCodeRepo interface {
	Create(ctx context.Context, code *InvokeAuthCode) error
	// Consume deletes and returns a live code only when every audience
	// binding matches. A failed match leaves the code available to its
	// intended callback, while concurrent successful calls have one winner.
	Consume(ctx context.Context, id, functionID, host string, now time.Time) (*InvokeAuthCode, error)
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}

// CLICredentialRepo manages long-lived CLI login credentials (§14.4).
type CLICredentialRepo interface {
	Create(ctx context.Context, c *CLICredential) error
	ByHash(ctx context.Context, secretHash string) (*CLICredential, error)
	// ListByUser returns userID's connected devices, for the dashboard's
	// "connected devices" list and for ownership checks on revoke.
	ListByUser(ctx context.Context, userID string) ([]*CLICredential, error)
	// Touch advances id's sliding-expiry clock by setting LastUsedAt to
	// now. Called on every successful access-token mint.
	Touch(ctx context.Context, id string, now time.Time) error
	Delete(ctx context.Context, id string) error
}

// CLIAuthCodeRepo manages the short-lived, single-use PKCE authorization
// codes the CLI's loopback login flow exchanges for a CLICredential
// (§14.4).
type CLIAuthCodeRepo interface {
	Create(ctx context.Context, code *CLIAuthCode) error
	// Consume deletes and returns a live code (id is its hash), enforcing
	// single use the same way InvokeAuthCodeRepo.Consume does. Returns
	// ErrNotFound if id is unknown, already consumed, or expired.
	Consume(ctx context.Context, id string, now time.Time) (*CLIAuthCode, error)
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}

// OAuthClientRepo manages dynamically registered OAuth 2.1 clients (RFC
// 7591 DCR, server/internal/oauth's POST /oauth/register).
type OAuthClientRepo interface {
	Create(ctx context.Context, c *OAuthClient) error
	ByID(ctx context.Context, id string) (*OAuthClient, error)
}

// OAuthAuthCodeRepo manages the short-lived, single-use PKCE authorization
// codes server/internal/oauth's GET/POST /oauth/authorize issues and
// POST /oauth/token consumes.
type OAuthAuthCodeRepo interface {
	Create(ctx context.Context, code *OAuthAuthCode) error
	// Consume deletes and returns a live code (id is its hash), enforcing
	// single use the same way CLIAuthCodeRepo.Consume does. Returns
	// ErrNotFound if id is unknown, already consumed, or expired.
	Consume(ctx context.Context, id string, now time.Time) (*OAuthAuthCode, error)
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}

// OAuthGrantRepo manages long-lived OAuth 2.1 refresh-token grants,
// mirroring CLICredentialRepo's shape exactly (see OAuthGrant's doc
// comment).
type OAuthGrantRepo interface {
	Create(ctx context.Context, g *OAuthGrant) error
	ByHash(ctx context.Context, secretHash string) (*OAuthGrant, error)
	// ListByUser returns userID's connected OAuth grants, for a future
	// "connected devices & apps" dashboard listing and for ownership
	// checks on revoke.
	ListByUser(ctx context.Context, userID string) ([]*OAuthGrant, error)
	// Touch advances id's sliding-expiry clock by setting LastUsedAt to
	// now. Called on every successful refresh_token grant.
	Touch(ctx context.Context, id string, now time.Time) error
	Delete(ctx context.Context, id string) error
}

// AuditRepo is an append-only log of privileged actions.
type AuditRepo interface {
	Append(ctx context.Context, a *AuditLog) error

	// List returns audit entries newest-first, at most limit entries,
	// starting strictly before cursor (an AuditLog.ID) if cursor is
	// non-empty. Pass an empty cursor to fetch the first page. Because IDs
	// are ULIDs (time-sortable), this keyset pagination works identically
	// against a DynamoDB backend partitioned by month (see
	List(ctx context.Context, cursor string, limit int) ([]*AuditLog, error)
}

// InvocationLogRepo stores per-invocation execution logs (see
// InvocationLog's doc comment). It is intentionally symmetric with
// AuditRepo's keyset-pagination shape.
type InvocationLogRepo interface {
	Append(ctx context.Context, l *InvocationLog) error

	// List returns functionID's invocation logs newest-first, at most limit
	// entries, starting strictly before cursor (an InvocationLog.ID) if
	// cursor is non-empty.
	List(ctx context.Context, functionID string, cursor string, limit int) ([]*InvocationLog, error)

	// DeleteOlderThan removes every log with CreatedAt strictly before
	// cutoff and returns the count removed. It is the retention mechanism
	// for SQL backends, called periodically by a cleanup goroutine
	// (cmd/funcbox-server). A DynamoDB backend enforces retention via a TTL
	// attribute set at write time instead, so its implementation is a
	// documented no-op (always returns (0, nil)) rather than an active
	// scan-and-delete.
	DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error)
}
