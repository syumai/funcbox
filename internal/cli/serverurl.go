// serverurl.go validates the funcbox server URL wherever one enters the
// CLI (the `funcbox login --server` flag and the persisted/env-supplied
// config the rest of the subcommands load via RequireConfig). It exists to
// close a specific hole: the CLI's long-lived login credential (fbxc_...)
// and the short-lived access tokens minted from it are sent as bearer
// tokens over whatever scheme the configured server URL uses, so accepting
// a plain http:// URL to a non-loopback host would let a same-network
// attacker capture the credential in transit.
package cli

import (
	"fmt"
	"net/url"
	"strings"
)

// loopbackServerHosts are the hostnames the CLI accepts a plain http://
// server URL for -- kept in sync with
// server/internal/server/middleware.go's loopbackHostAliases and
// server/internal/auth/cliauth.go's validCLILoopbackRedirect, so the CLI
// and the server agree on exactly what counts as "loopback" (and therefore
// exempt from the https requirement below). This intentionally does NOT
// cover the wider 127.0.0.0/8 range or other loopback IPs beyond
// 127.0.0.1: neither of those two server-side callers do either, and a
// third, broader definition here would just be one more thing to keep in
// sync.
var loopbackServerHosts = map[string]struct{}{
	"localhost": {},
	"127.0.0.1": {},
	"::1":       {},
}

// isLoopbackServerHost reports whether host (as returned by
// url.URL.Hostname, so already bracket-stripped for an IPv6 literal) is one
// of loopbackServerHosts.
func isLoopbackServerHost(host string) bool {
	_, ok := loopbackServerHosts[strings.ToLower(host)]
	return ok
}

// validateServerURL validates raw as a funcbox server URL and returns it
// normalized (trailing slash stripped, so callers can concatenate
// "/api/v1/..." onto the result directly without producing a double
// slash). It is the CLI's single gate against ever sending the CLI
// credential to a server address that can't defend it in transit:
//
//   - The URL must parse and use scheme http or https.
//   - Plain http is only accepted when the host is a loopback alias
//     (loopbackServerHosts) -- e.g. the local dev-server workflow
//     `http://localhost:8080`. Every other http URL is rejected in favor
//     of https, since the credential would otherwise cross the network in
//     cleartext.
//   - The URL must be a bare origin: no userinfo (user:pass@), no path
//     beyond an optional trailing slash, no query string, no fragment.
//     Any of those would silently be dropped or misinterpreted once the
//     CLI starts appending API paths to it, so they're rejected outright
//     rather than stripped.
//
// Called from both `funcbox login --server` (login.go, before any network
// request is made) and RequireConfig (config.go, so a stale or hand-edited
// config file with an insecure URL is refused too).
func validateServerURL(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("server URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid server URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("server URL %q must use http or https", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("server URL %q must include a host", raw)
	}
	if u.User != nil {
		return "", fmt.Errorf("server URL %q must not contain a username or password", raw)
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("server URL %q must not contain a path", raw)
	}
	if u.RawQuery != "" {
		return "", fmt.Errorf("server URL %q must not contain a query string", raw)
	}
	if u.Fragment != "" {
		return "", fmt.Errorf("server URL %q must not contain a fragment", raw)
	}
	if u.Scheme == "http" && !isLoopbackServerHost(u.Hostname()) {
		return "", fmt.Errorf("server URL %q uses plain http, which would send the CLI credential in cleartext over the network; use https, or http only for localhost/127.0.0.1/[::1] (e.g. a local dev server)", raw)
	}
	return u.Scheme + "://" + u.Host, nil
}
