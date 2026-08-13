package manifest

import (
	"errors"
	"fmt"
	"regexp"
	"unicode/utf8"
)

// nameRE is the DNS-label-equivalent pattern required for function
// names and owner handles (tmp/04-manifest.md).
var nameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// envNameRE is the accepted shape for a declared environment variable
// key.
var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// MaxDescriptionLength is the maximum number of characters (runes)
// allowed in the description field.
const MaxDescriptionLength = 500

var (
	// ErrInvalidName is returned when name fails the DNS-label
	// pattern or length requirement.
	ErrInvalidName = errors.New("manifest: invalid name")
	// ErrReservedName is returned when name or owner collides with a
	// reserved route (see ReservedNames).
	ErrReservedName = errors.New("manifest: reserved name")
	// ErrInvalidOwner is returned when owner fails the DNS-label
	// pattern or length requirement.
	ErrInvalidOwner = errors.New("manifest: invalid owner")
	// ErrDescriptionTooLong is returned when description exceeds
	// MaxDescriptionLength characters.
	ErrDescriptionTooLong = errors.New("manifest: description too long")
	// ErrInvalidEnv is returned for a malformed or duplicate entry in
	// the env list.
	ErrInvalidEnv = errors.New("manifest: invalid env entry")
)

// Validate checks a Manifest's structural rules: name and owner
// format and reservation, description length, and env entry syntax.
//
// Validate does not have access to the bundle's file tree, so it does
// not check that Main actually exists; use ResolveMain for that once
// the bundle's files are available. It also does not know the
// deploying owner's scope defaults, so a nil Visibility is left as
// nil (Validate does not reject it).
func Validate(m *Manifest) error {
	if m == nil {
		return fmt.Errorf("manifest: nil manifest")
	}

	if err := validateName(m.Name); err != nil {
		return err
	}
	if m.Owner != "" {
		if err := validateHandle(m.Owner, ErrInvalidOwner); err != nil {
			return err
		}
	}
	if utf8.RuneCountInString(m.Description) > MaxDescriptionLength {
		return fmt.Errorf("%w: %d characters (max %d)", ErrDescriptionTooLong, utf8.RuneCountInString(m.Description), MaxDescriptionLength)
	}
	if err := validateEnv(m.Env); err != nil {
		return err
	}

	return nil
}

func validateName(name string) error {
	return validateHandle(name, ErrInvalidName)
}

// ValidateHandle validates a DNS-label-shaped handle exactly as Validate
// does for the manifest's own Name/Owner fields (format + reservation via
// IsReserved). It is exported for callers that need to validate a handle
// before it's tied to a specific manifest field — e.g. the deploy API's
// "owner" form parameter (tmp/07-http-api.md §7.3), which is supplied
// outside the manifest file itself.
func ValidateHandle(handle string) error {
	return validateHandle(handle, ErrInvalidName)
}

// validateHandle validates a DNS-label-shaped identifier (used for
// both the function name and the owner handle), wrapping format
// failures in notMatch and reservation failures in ErrReservedName.
func validateHandle(handle string, notMatch error) error {
	if !nameRE.MatchString(handle) {
		return fmt.Errorf("%w: %q", notMatch, handle)
	}
	if IsReserved(handle) {
		return fmt.Errorf("%w: %q", ErrReservedName, handle)
	}
	return nil
}

// IsValidEnvKey reports whether key is a syntactically valid environment
// variable name -- the same rule Validate applies to each entry of a
// manifest's env list. Exported so callers outside this package (the
// management API's env var endpoints, tmp/07-http-api.md §7.3's
// "PUT/DELETE /api/v1/functions/{owner}/{name}/env/{key}") can validate a
// key supplied outside a manifest file without duplicating the pattern.
func IsValidEnvKey(key string) bool {
	return envNameRE.MatchString(key)
}

func validateEnv(env []string) error {
	seen := make(map[string]struct{}, len(env))
	for _, key := range env {
		if !envNameRE.MatchString(key) {
			return fmt.Errorf("%w: %q", ErrInvalidEnv, key)
		}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%w: duplicate key %q", ErrInvalidEnv, key)
		}
		seen[key] = struct{}{}
	}
	return nil
}
