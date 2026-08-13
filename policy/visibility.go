package policy

import (
	"errors"
	"fmt"
)

// ErrInvalidVisibility is returned by ParseVisibility for unrecognized
// visibility strings.
var ErrInvalidVisibility = errors.New("policy: invalid visibility")

// Visibility is a function's public exposure level. Values are
// ordered from narrowest to widest (workspace < org < public) so
// that the effective visibility across levels can be computed with a
// plain minimum.
type Visibility int

const (
	// VisibilityWorkspace restricts invocation to workspace members.
	VisibilityWorkspace Visibility = iota
	// VisibilityOrg restricts invocation to organization members.
	VisibilityOrg
	// VisibilityPublic allows unauthenticated invocation.
	VisibilityPublic
)

// String returns the manifest/config spelling of the visibility.
func (v Visibility) String() string {
	switch v {
	case VisibilityWorkspace:
		return "workspace"
	case VisibilityOrg:
		return "org"
	case VisibilityPublic:
		return "public"
	default:
		return fmt.Sprintf("Visibility(%d)", int(v))
	}
}

// ParseVisibility parses the manifest/config spelling of a visibility
// ("public", "org", "workspace").
func ParseVisibility(s string) (Visibility, error) {
	switch s {
	case "public":
		return VisibilityPublic, nil
	case "org":
		return VisibilityOrg, nil
	case "workspace":
		return VisibilityWorkspace, nil
	default:
		return 0, fmt.Errorf("%w: %q", ErrInvalidVisibility, s)
	}
}

// MinVisibility returns the narrowest (most restrictive) of the given
// ("実効 visibility = min(manifest.visibility, ws.max_visibility,
// org.max_visibility)"). With no arguments it returns the narrowest
// possible value (VisibilityWorkspace), failing closed.
func MinVisibility(vs ...Visibility) Visibility {
	if len(vs) == 0 {
		return VisibilityWorkspace
	}
	narrowest := vs[0]
	for _, v := range vs[1:] {
		if v < narrowest {
			narrowest = v
		}
	}
	return narrowest
}
