package store

import "context"

// Store is the aggregate root every backend (sqlite, turso, neon,
// dynamodb, ...) implements. Individual repositories cover single-entity
// CRUD and lookups; the methods declared directly on Store cover
// operations that must be atomic across more than one entity. SQL backends
// implement those with a transaction; a DynamoDB backend would use
type Store interface {
	Organizations() OrganizationRepo
	Users() UserRepo
	Handles() HandleRepo
	Workspaces() WorkspaceRepo
	Functions() FunctionRepo
	Sessions() SessionRepo
	Tokens() TokenRepo
	Audit() AuditRepo
	InvocationLogs() InvocationLogRepo

	// BootstrapFirstUser atomically promotes u to admin and creates the
	// singleton Organization (named orgName), but only if no user exists
	// yet. It is safe to call concurrently from multiple requests racing
	// to complete the very first login: exactly one caller succeeds and
	// creates the admin user + organization; every other caller observes
	// either the non-empty users table (via the pre-check) or a unique
	// constraint violation on the insert itself (the backstop for the
	// race window between the check and the insert) and returns
	// ErrConflict. u.ID is filled in by the caller before calling; u.Role
	// is forced to RoleAdmin regardless of its input value.
	BootstrapFirstUser(ctx context.Context, u *User, orgName string) error

	// ActivateVersion atomically verifies that versionID is a version of
	// funcID and repoints Function.ActiveVersionID at it. Returns
	// ErrNotFound if either id doesn't exist, or if versionID belongs to a
	// different function.
	ActivateVersion(ctx context.Context, funcID, versionID string) error

	// CreateWorkspace atomically creates ws, claims handle for it, and
	// adds creatorUserID as an admin member. Returns ErrConflict if handle
	// is already taken.
	CreateWorkspace(ctx context.Context, ws *Workspace, handle string, creatorUserID string) error

	// Migrate applies any pending schema migrations. It is idempotent and
	// safe to call on every process start.
	Migrate(ctx context.Context) error

	// Close releases any resources (e.g. DB connections) held by the
	// store.
	Close() error
}
