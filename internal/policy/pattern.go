package policy

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// ErrInvalidPattern is returned by ParsePattern when a host pattern is
// syntactically invalid.
var ErrInvalidPattern = errors.New("policy: invalid host pattern")

// hostLabelRE matches a single DNS label.
var hostLabelRE = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// Pattern is a parsed fetch allowlist host pattern.
//
// Supported syntax (see tmp/04-manifest.md "fetch のホストパターン仕様"):
//
//   - "api.example.com"          exact host match
//   - "*.example.com"            subdomain wildcard (one or more labels);
//     does NOT match the apex "example.com" itself
//   - "db.example.com:5432"      optional ":port" suffix; when absent,
//     only the standard ports 80 and 443 match
//   - "10.0.3.7"                 literal IP addresses are allowed
//
// Host matching is case-insensitive.
type Pattern struct {
	raw      string
	host     string // lowercased; exact host, or the domain suffix for wildcard patterns
	wildcard bool
	port     int // 0 means "no explicit port": only 80/443 match
}

// String returns the original pattern text.
func (p Pattern) String() string { return p.raw }

// ParsePattern parses and validates a single fetch allowlist host
// pattern.
func ParsePattern(s string) (Pattern, error) {
	raw := s
	if s == "" {
		return Pattern{}, fmt.Errorf("%w: empty pattern", ErrInvalidPattern)
	}

	host := s
	port := 0
	if h, portStr, err := net.SplitHostPort(s); err == nil {
		host = h
		n, convErr := strconv.Atoi(portStr)
		if convErr != nil || n < 1 || n > 65535 {
			return Pattern{}, fmt.Errorf("%w: invalid port in %q", ErrInvalidPattern, s)
		}
		port = n
	} else if !strings.Contains(err.Error(), "missing port") {
		// net.SplitHostPort failed for a reason other than "no port
		// present" (e.g. a bracketed IPv6 literal with a malformed
		// port). Surface it as an invalid pattern.
		return Pattern{}, fmt.Errorf("%w: %q: %v", ErrInvalidPattern, s, err)
	}

	host = strings.ToLower(host)
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")

	if host == "" {
		return Pattern{}, fmt.Errorf("%w: empty host in %q", ErrInvalidPattern, raw)
	}

	if strings.HasPrefix(host, "*.") {
		domain := host[2:]
		if domain == "" || !isValidHostname(domain) {
			return Pattern{}, fmt.Errorf("%w: invalid wildcard domain in %q", ErrInvalidPattern, raw)
		}
		return Pattern{raw: raw, host: domain, wildcard: true, port: port}, nil
	}

	if !isValidHostname(host) && net.ParseIP(host) == nil {
		return Pattern{}, fmt.Errorf("%w: invalid host in %q", ErrInvalidPattern, raw)
	}

	return Pattern{raw: raw, host: host, port: port}, nil
}

// isValidHostname reports whether s is a syntactically valid
// dot-separated hostname (DNS labels only; not an IP literal check).
func isValidHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !hostLabelRE.MatchString(label) {
			return false
		}
	}
	return true
}

// Matches reports whether host (a bare hostname or IP, without
// scheme/path/port) and port satisfy the pattern. Matching is
// case-insensitive.
func (p Pattern) Matches(host string, port int) bool {
	if !p.portMatches(port) {
		return false
	}

	host = strings.ToLower(strings.TrimSuffix(host, "."))

	if p.wildcard {
		return strings.HasSuffix(host, "."+p.host) && host != p.host
	}
	return host == p.host
}

func (p Pattern) portMatches(port int) bool {
	if p.port != 0 {
		return port == p.port
	}
	return port == 80 || port == 443
}
