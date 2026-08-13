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
	ByGoogleSub(ctx context.Context, sub string) (*User, error)
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

// TokenRepo manages long-lived API tokens.
type TokenRepo interface {
	Create(ctx context.Context, t *APIToken) error
	ByHash(ctx context.Context, tokenHash string) (*APIToken, error)
	ListByUser(ctx context.Context, userID string) ([]*APIToken, error)
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
