// Package browserjar provides an http.CookieJar wrapper that enforces the
// RFC 6265bis cookie-prefix rules Go's own net/http/cookiejar deliberately
// does not. It exists ONLY for tests: production code never imports it.
//
// The bug this closes: funcbox's session/CSRF/invoke-SSO cookies (see
// server/internal/auth) are named with the "__Host-" prefix, which per RFC
// 6265bis section 4.1.3 requires the Set-Cookie response to carry the
// Secure attribute literally, have Path=/, and no Domain -- otherwise a
// real browser discards the cookie silently, with no error surfaced
// anywhere a server-side test could observe. Critically, this rejection is
// unconditional: it does NOT get waived just because the connection was to
// a "potentially trustworthy" origin like http://localhost or
// http://127.0.0.1 (that trustworthy-origin waiver only ever applies to
// the separate, plain Secure attribute -- see acceptable below). Go's
// net/http/cookiejar, used by every existing e2e test in this repository,
// implements none of this: it stores whatever Set-Cookie it's given. That
// mismatch is exactly how funcbox shipped __Host--prefixed cookies gated
// by a Secure flag that resolved false over plain-http local dev (see
// server/internal/auth/config.go's secureCookies) -- every e2e test using
// the stdlib jar stayed green while a real Chrome discarded the cookie and
// looped the user back to the login form forever.
package browserjar

import (
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

// Jar wraps a fresh net/http/cookiejar.Jar, additionally enforcing:
//
//   - "__Host-" prefix: accepted only with Secure, Path=/, and no Domain.
//   - "__Secure-" prefix: accepted only with Secure.
//   - Secure (regardless of prefix): accepted only when the response came
//     over https, OR from a loopback host (localhost/127.0.0.1/[::1]) --
//     mirroring Chrome's "potentially trustworthy origin" exemption for
//     loopback plain-http. This is a separate, narrower relaxation than
//     the "__Host-" rule above: it never substitutes for that rule's own
//     hard requirement that Secure actually be present on the cookie.
type Jar struct {
	inner http.CookieJar
}

// New returns a Jar wrapping a fresh net/http/cookiejar.Jar.
func New() *Jar {
	inner, err := cookiejar.New(nil)
	if err != nil {
		// cookiejar.New(nil) never actually returns an error in the
		// standard library's implementation.
		panic("browserjar: cookiejar.New(nil): " + err.Error())
	}
	return &Jar{inner: inner}
}

// SetCookies implements http.CookieJar, dropping any cookie a real browser
// would refuse to store for a response from u.
func (j *Jar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	var accepted []*http.Cookie
	for _, c := range cookies {
		if acceptable(u, c) {
			accepted = append(accepted, c)
		}
	}
	if len(accepted) > 0 {
		j.inner.SetCookies(u, accepted)
	}
}

// Cookies implements http.CookieJar.
func (j *Jar) Cookies(u *url.URL) []*http.Cookie {
	return j.inner.Cookies(u)
}

func acceptable(u *url.URL, c *http.Cookie) bool {
	if c.Secure && u.Scheme != "https" && !isLoopbackHost(u.Hostname()) {
		return false
	}
	switch {
	case strings.HasPrefix(c.Name, "__Host-"):
		return c.Secure && c.Path == "/" && c.Domain == ""
	case strings.HasPrefix(c.Name, "__Secure-"):
		return c.Secure
	default:
		return true
	}
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
