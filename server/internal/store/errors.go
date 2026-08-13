package store

import "errors"

// Sentinel errors returned by repository and Store methods. Backend
// implementations must wrap these with errors.Is-compatible errors (e.g.
// via fmt.Errorf("...: %w", ErrNotFound)) rather than returning driver
// specific errors directly, so callers can branch on them independent of
// the backend in use.
var (
	// ErrNotFound is returned when a lookup finds no matching row/item.
	ErrNotFound = errors.New("store: not found")

	// ErrConflict is returned when an operation would violate a
	// uniqueness constraint (duplicate public User ID, duplicate function name
	// within an owner, duplicate google_sub/email, etc.) or a precondition
	// of a composite operation isn't met (e.g. BootstrapFirstUser called
	// after a user already exists).
	ErrConflict = errors.New("store: conflict")
)
