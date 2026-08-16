package server

import (
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/syumai/funcbox/server/internal/metrics"
)

// statusWriter wraps an http.ResponseWriter to capture the status
// code that was actually written, for logging.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap exposes the wrapped ResponseWriter to http.ResponseController
// (see https://pkg.go.dev/net/http#ResponseController), which looks for
// exactly this method to see through a wrapper like statusWriter to the
// underlying http.Flusher/http.Hijacker/etc. Without it, a caller that
// needs to Flush() through New's two nested statusWriter layers (logging
// then metrics) -- as server/internal/mcpserver's Streamable HTTP /mcp
// handler does, to push its standalone SSE stream's headers out
// immediately rather than leaving them sitting in an unflushed buffer --
// would silently get http.ErrNotSupported and hang the connection open
// with nothing ever sent, since neither http.ResponseWriter nor this
// struct's own method set otherwise exposes Flush.
func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// recoverMiddleware catches panics from the wrapped handler, logs
// them with a stack trace, and responds 500 instead of crashing the
// process. It must run inside loggingMiddleware (closer to the
// handler) so that a recovered panic's 500 status still gets logged.
func recoverMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error("panic recovered",
					"panic", rec,
					"method", r.Method,
					"path", r.URL.Path,
					"stack", string(debug.Stack()),
				)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs each request's method, path, status, and
// duration once it completes.
func loggingMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		path := r.URL.Path
		// The invoke callback carries a short-lived credential in its query.
		// Keep the platform logger query-blind and use an explicit redacted
		// marker so future logging changes cannot accidentally expose it.
		if path == "/.funcbox/auth/callback" {
			path = "/.funcbox/auth/callback?[REDACTED]"
		}
		logger.Info("request",
			"method", r.Method,
			"path", path,
			"status", sw.status,
			"duration", time.Since(start),
		)
	})
}

// metricsMiddleware records every request's route class, method, status,
// (metrics disabled, or a caller that never set Deps.Metrics) -- every
// *metrics.Metrics method is nil-receiver-safe, so this middleware is
// always installed unconditionally rather than only when metrics are
// enabled, keeping New's middleware chain the same shape either way.
func metricsMiddleware(mtr *metrics.Metrics, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		mtr.ObserveHTTPRequest(routeClass(r.URL.Path), r.Method, sw.status, time.Since(start))
	})
}

// routeClass buckets a request path into a coarse, fixed-cardinality label
// for metricsMiddleware: per-path labels would blow up cardinality across
// arbitrary function owner/name/subpaths (see Metrics.ObserveHTTPRequest's
// doc comment). Mirrors router.ServeHTTP's own dispatch logic in routes.go
// (kept as a small, deliberate duplication rather than threading a
// classification result out of the router, since the two must only agree
// on classification, not on any actual handling behavior).
func routeClass(path string) string {
	segments := pathSegments(path)
	if len(segments) == 0 {
		return "root"
	}
	switch segments[0] {
	case "api", "dashboard", "auth", "dev", "metrics", "mcp", "oauth":
		return segments[0]
	case ".well-known":
		return "well-known"
	case "healthz":
		return "healthz"
	default:
		if len(segments) >= 2 {
			return "invoke"
		}
		return "other"
	}
}

// loopbackHostAliases are hostnames that all reach the same loopback
// network interface but are, individually, distinct browser cookie
// origins: a cookie set while visiting one is invisible to a request
// against another. See canonicalOriginMiddleware's doc comment for why
// that distinction matters here.
var loopbackHostAliases = map[string]struct{}{
	"localhost": {},
	"127.0.0.1": {},
	"::1":       {},
}

// isLoopbackHost reports whether host (already lowercased, no port, no
// brackets) is one of loopbackHostAliases.
func isLoopbackHost(host string) bool {
	_, ok := loopbackHostAliases[host]
	return ok
}

// splitRequestHost parses an http.Request.Host-shaped authority into a
// lowercased hostname and its port (a bracketed IPv6 literal's brackets
// are stripped either way). port is "" when the authority carried none --
// net/http always populates Request.Host from the wire's Host header
// verbatim, so unlike routes.go's normalizedRequestHost (which validates
// and rejects a much wider range of malformed input for host-based
// function routing) this only needs to handle the "IP-literal with or
// without a port" shapes loopback hostnames actually take.
func splitRequestHost(authority string) (host, port string) {
	if h, p, err := net.SplitHostPort(authority); err == nil {
		return strings.ToLower(h), p
	}
	host = strings.ToLower(authority)
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	return host, ""
}

// effectivePort resolves an explicit-or-default port for scheme: an empty
// port (no ":NNNN" in the URL or Host) means the scheme's own default
// port, so "http://127.0.0.1" and "http://127.0.0.1:80" must compare
// equal here.
func effectivePort(scheme, port string) string {
	if port != "" {
		return port
	}
	if scheme == "https" {
		return "443"
	}
	return "80"
}

// canonicalControlOrigin returns the effective control-plane origin used
// for loopback-alias normalization: deps.ControlURL when host-based
// routing is configured, falling back to deps.BaseURL for the common
// single-origin, path-routed deployment (FUNCBOX_BASE_URL set alone --
// ControlURL stays empty unless FUNCBOX_CONTROL_URL is set explicitly,
// see config.Config.FromEnv). Empty when neither is configured, in which
// case canonicalOriginMiddleware never redirects.
func canonicalControlOrigin(deps Deps) string {
	if deps.ControlURL != "" {
		return deps.ControlURL
	}
	return deps.BaseURL
}

// loopbackAliasRedirectTarget reports the same-path-and-query URL on
// canonicalOrigin that r should be redirected to: canonicalOrigin's own
// host must itself be a loopback alias, r.Host must name a DIFFERENT
// loopback alias on the SAME port, and r's path must not be under
// /api/v1 (see canonicalOriginMiddleware's doc comment for why each of
// these is required).
func loopbackAliasRedirectTarget(canonicalOrigin string, r *http.Request) (target string, ok bool) {
	if canonicalOrigin == "" {
		return "", false
	}
	segments := pathSegments(r.URL.Path)
	if len(segments) > 0 {
		switch segments[0] {
		case "api":
			return "", false
		case "mcp", ".well-known":
			// /mcp (the Streamable HTTP MCP endpoint) and the two
			// /.well-known/oauth-* metadata documents are API-facing, exactly
			// like /api/v1 above: MCP clients authenticate with a bearer
			// token, origin-independently, and the metadata documents are
			// unauthenticated, cacheable JSON with no cookie involved at all
			// -- see this function's doc comment for why /api/v1 is exempt.
			return "", false
		case "oauth":
			// /oauth/token, /oauth/register are API-facing for the same
			// reason (a bearer-token/PKCE token exchange and self-service
			// client registration, neither browser-cookie-based). But
			// /oauth/authorize is the one OAuth endpoint a BROWSER opens
			// directly (it renders the consent page, or redirects an
			// unauthenticated browser into /auth/login) -- exactly the
			// cookie-origin risk this middleware exists to fix, so it stays
			// subject to normalization like every other browser page
			// (falling through below, not returning here).
			if len(segments) < 2 || segments[1] != "authorize" {
				return "", false
			}
		}
	}
	canon, err := url.Parse(canonicalOrigin)
	if err != nil || canon.Hostname() == "" {
		return "", false
	}
	canonHost := strings.ToLower(canon.Hostname())
	if !isLoopbackHost(canonHost) {
		// Only ever rewrite loopback deployments -- a mismatched Host
		// against a non-loopback (production) canonical origin is a
		// routing/DNS problem this middleware must not paper over with a
		// redirect (and is exactly what TestHostRouting_UnknownFailsClosed
		// still expects to fail closed with 421).
		return "", false
	}
	reqHost, reqPort := splitRequestHost(r.Host)
	if reqHost == "" || !isLoopbackHost(reqHost) || reqHost == canonHost {
		return "", false
	}
	if effectivePort(canon.Scheme, canon.Port()) != effectivePort(canon.Scheme, reqPort) {
		return "", false
	}
	return strings.TrimSuffix(canonicalOrigin, "/") + r.URL.RequestURI(), true
}

// canonicalOriginMiddleware redirects browser-facing control-plane
// requests that arrive on a loopback alias of the configured canonical
// control origin (e.g. Host: localhost when FUNCBOX_BASE_URL points at
// http://127.0.0.1:8093) to that canonical origin, before the router
// picks a handler -- in particular, before any cookie is read or
// written.
//
// Why this exists: localhost, 127.0.0.1, and [::1] all reach the same
// loopback interface, but a browser treats each as a completely separate
// cookie origin. Every control-plane cookie funcbox-server sets (OAuth
// state, session, CSRF, the invoke SSO cookie) is host-only (no Domain
// attribute, by design -- see internal/auth), and the OAuth
// authorize/redirect_uri and the dev-mode stub issuer's own URL are
// always built from the configured canonical origin (BaseURL/
// ControlURL, internal/auth.Config), never from the incoming request's
// Host. A user who opens the dashboard on one loopback alias while the
// server is configured with another therefore has every cookie set on
// the "wrong" origin from the flow's second half onward -- most visibly,
// the OAuth state cookie set during /auth/login is invisible to
// /auth/callback once the identity provider redirects back to the
// configured canonical host, producing "missing OAuth state cookie (it
// may have expired -- try logging in again)" even on a perfectly timed,
// perfectly valid login attempt.
//
// Scope: every route EXCEPT /api/v1/*, /mcp, /.well-known/*, and
// /oauth/{token,register} is normalized -- dashboard, auth, the dev OIDC
// stub, /oauth/authorize, and even the legacy path-routed function-invoke
// fallback are all browser-facing enough that a cookie or session set on
// the wrong alias is a real risk. /api/v1/* is deliberately exempt:
// bearer-token API clients (the funcbox CLI's normal deployed/invoke
// traffic, and the CLI-auth token exchange itself) authenticate
// origin-independently and may legitimately talk to either loopback
// alias, so redirecting their (often POST) requests would be actively
// unfriendly -- a client that doesn't transparently replay a redirected
// POST body, or doesn't follow redirects at all, would simply break
// instead of being helped. /mcp, /.well-known/*, and /oauth/{token,
// register} are exempt for the identical reason -- see
// loopbackAliasRedirectTarget's own doc comment on that switch for exactly
// which /oauth/ sub-paths are exempt and which one (authorize) isn't.
// Managed function hosts (the FunctionDomain suffix, host-routed mode) are
// never affected by this exemption or otherwise: they aren't loopback
// aliases of the control origin, so the alias check on
// canonicalControlOrigin's own host never matches them in the first
// place.
//
// This only ever fires when the CONFIGURED canonical host is itself a
// loopback alias -- a mismatched Host against a non-loopback production
// deployment is a routing/DNS problem, not something to paper over with
// a redirect (TestHostRouting_UnknownFailsClosed's 421-on-127.0.0.1 case
// covers exactly that: canonicalControlOrigin there is a real DNS name,
// so this middleware never even looks at the request's Host).
//
// GET/HEAD get a 302 Found (temporary, safely re-followed by any browser
// or HTTP client without replaying a body); every other method gets a
// 307 Temporary Redirect, which replays the original method and body
// rather than downgrading to GET the way a 301/302/303 can on a non-GET
// client. Both codes are non-cacheable by default (unlike 301/308), so a
// client can never "remember" the redirect past a future config change.
func canonicalOriginMiddleware(deps Deps, next http.Handler) http.Handler {
	origin := canonicalControlOrigin(deps)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if target, ok := loopbackAliasRedirectTarget(origin, r); ok {
			code := http.StatusFound
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				code = http.StatusTemporaryRedirect
			}
			http.Redirect(w, r, target, code)
			return
		}
		next.ServeHTTP(w, r)
	})
}
