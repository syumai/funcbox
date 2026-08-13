package policy

import (
	"errors"
	"fmt"
)

// ErrInvalidFetchMode is returned by ParseFetchMode for unrecognized
// mode strings.
var ErrInvalidFetchMode = errors.New("policy: invalid fetch mode")

// FetchMode is the permissiveness level of a fetch policy. Values are
// ordered from most to least restrictive (deny < allowlist <
// allow-all) so that the effective mode across levels can be computed
// with a plain minimum.
type FetchMode int

const (
	// FetchModeDeny blocks all outbound fetch calls.
	FetchModeDeny FetchMode = iota
	// FetchModeAllowlist permits only hosts matching an explicit list
	// of patterns.
	FetchModeAllowlist
	// FetchModeAllowAll permits any outbound fetch call (subject to
	// the SSRF guard, which is applied independently by the runtime).
	FetchModeAllowAll
)

// String returns the manifest/config spelling of the mode.
func (m FetchMode) String() string {
	switch m {
	case FetchModeDeny:
		return "deny"
	case FetchModeAllowlist:
		return "allowlist"
	case FetchModeAllowAll:
		return "allow-all"
	default:
		return fmt.Sprintf("FetchMode(%d)", int(m))
	}
}

// ParseFetchMode parses the manifest/config spelling of a fetch mode
// ("deny", "allowlist", "allow-all").
func ParseFetchMode(s string) (FetchMode, error) {
	switch s {
	case "deny":
		return FetchModeDeny, nil
	case "allowlist":
		return FetchModeAllowlist, nil
	case "allow-all":
		return FetchModeAllowAll, nil
	default:
		return 0, fmt.Errorf("%w: %q", ErrInvalidFetchMode, s)
	}
}

// FetchPolicy is one level's fetch permission declaration (org,
// workspace, or manifest).
type FetchPolicy struct {
	Mode FetchMode
	// Allow is the set of host patterns permitted when Mode is
	// FetchModeAllowlist. Ignored for other modes.
	Allow []Pattern
}

// EffectivePolicy is the result of intersecting fetch policies from
// multiple levels (organization, workspace, manifest). Construct it
// with Effective; evaluate individual requests with Decision.
type EffectivePolicy struct {
	mode FetchMode
	// levels holds only the input levels whose Mode was
	// FetchModeAllowlist. A request is allowed only if it matches
	// every one of these levels' patterns (levels with allow-all are
	// unconstrained and therefore omitted).
	levels []FetchPolicy
}

// Effective computes the effective fetch policy from an ordered set
// of levels (typically organization, workspace, manifest — see
// tmp/05-auth-and-permissions.md §5.6). The rule is:
//
//   - if any level is deny, the effective mode is deny
//   - the effective mode is allow-all only if every level is allow-all
//   - otherwise the effective mode is allowlist, and a request must
//     match EVERY level that itself declares an allowlist (levels set
//     to allow-all impose no constraint and are skipped)
//
// Effective does not precompute an intersection of patterns; matching
// against each level's pattern set happens per request in Decision.
func Effective(levels ...FetchPolicy) EffectivePolicy {
	if len(levels) == 0 {
		// No policy at any level: fail closed.
		return EffectivePolicy{mode: FetchModeDeny}
	}

	mode := FetchModeAllowAll
	for _, l := range levels {
		if l.Mode < mode {
			mode = l.Mode
		}
	}

	ep := EffectivePolicy{mode: mode}
	if mode == FetchModeAllowlist {
		for _, l := range levels {
			if l.Mode == FetchModeAllowlist {
				ep.levels = append(ep.levels, l)
			}
		}
	}
	return ep
}

// Mode returns the effective fetch mode.
func (e EffectivePolicy) Mode() FetchMode { return e.mode }

// Decision reports whether an outbound fetch to host:port is
// permitted by the effective policy. It is evaluated fresh for every
// call (patterns are matched directly; nothing is precomputed at
// Effective time).
//
// Decision only evaluates host-pattern policy; it does not apply the
// SSRF guard (see BlockedIP), which the runtime layer applies
// separately at the Dial hook.
func (e EffectivePolicy) Decision(host string, port int) bool {
	switch e.mode {
	case FetchModeAllowAll:
		return true
	case FetchModeAllowlist:
		for _, level := range e.levels {
			if !anyPatternMatches(level.Allow, host, port) {
				return false
			}
		}
		return true
	case FetchModeDeny:
		return false
	default:
		return false
	}
}

func anyPatternMatches(patterns []Pattern, host string, port int) bool {
	for _, p := range patterns {
		if p.Matches(host, port) {
			return true
		}
	}
	return false
}
