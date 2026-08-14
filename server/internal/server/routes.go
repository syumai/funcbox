package server

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/syumai/funcbox/server/internal/invoke"
	"github.com/syumai/funcbox/server/internal/metrics"
)

// reservedRoutes are the first-path-segment names that are dispatched to a
// dedicated subsystem rather than treated as a function owner
// top-level route rather than a subtree, since it must actually respond
// (200 "ok") instead of stubbing out. "api", "auth", and "dev" are also
// handled separately (see route): they have real handlers when the
// corresponding Deps field is set, and fall back to a 501 stub otherwise.
var reservedRoutes = map[string]struct{}{
	"assets": {},
}

// Deps are server.New's dependencies. Every handler field may be nil (the
// corresponding routes then respond 501, matching this package's original
// all-stub behavior), which keeps this constructor usable from tests that
// only care about routing behavior unrelated to a given subsystem.
type Deps struct {
	Logger *slog.Logger
	// API serves everything under /api/v1 (internal/api.Handler).
	API http.Handler
	// Invoker serves /{owner}/{func}[/...] (internal/invoke.Invoker).
	Invoker *invoke.Invoker
	// Auth serves /auth/* (internal/auth.Auth.Routes()).
	Auth http.Handler
	// DevOIDC serves /dev/oidc/* (internal/auth.Auth.DevRoutes()). Nil
	// unless FUNCBOX_AUTH_MODE=dev.
	DevOIDC http.Handler
	// Dashboard serves /dashboard/* (internal/dashboard.Server), including
	// /dashboard/assets/* (served directly, no VM) and every other
	// /dashboard/* path (session-checked, then run through the dashboard's
	// own privileged runtime pool -- see internal/dashboard's doc comment).
	// It receives the request with its full, unmodified path -- like
	// Invoker, it is responsible for its own prefix handling.
	Dashboard http.Handler
	// Metrics is funcbox-server's Prometheus instrumentation
	// metrics.New(false)) behaves as fully disabled: GET /metrics is not
	// mounted at all (falls through to the generic 501), and no per-request
	// counters/histograms are recorded -- every Metrics method is
	// nil-receiver-safe, so New always wraps every request in
	// metricsMiddleware regardless of whether metrics are enabled.
	Metrics *metrics.Metrics
	// ControlURL and FunctionDomain enable origin-separated host routing.
	// When unset, New retains the legacy path router for local compatibility.
	ControlURL     string
	FunctionDomain string
	// LandingURL, when set, redirects GET/HEAD to ControlURL. Other methods
	// fail closed rather than replaying a body or credentials.
	LandingURL string
	// BaseURL is the server's externally reachable base URL
	// (config.Config.BaseURL / FUNCBOX_BASE_URL) -- every OAuth
	// redirect_uri and, in dev mode, the stub issuer URL are built from
	// it (internal/auth), regardless of what Host a request actually
	// arrived on. canonicalOriginMiddleware uses it as the fallback
	// canonical control origin for loopback-alias normalization when
	// ControlURL is unset (the common single-origin, path-routed
	// deployment -- ControlURL is only populated when FUNCBOX_CONTROL_URL
	// is explicitly set, paired with FUNCBOX_FUNCTION_DOMAIN; see
	// config.Config.FromEnv). Not otherwise used by routing.
	BaseURL string
}

// New builds the top-level funcbox-server http.Handler: routing plus the
// panic-recovery, request-logging, and metrics middleware. deps.Logger
// must be non-nil.
func New(deps Deps) http.Handler {
	var handler http.Handler = &router{deps: deps}
	handler = canonicalOriginMiddleware(deps, handler)
	handler = recoverMiddleware(deps.Logger, handler)
	handler = metricsMiddleware(deps.Metrics, handler)
	handler = loggingMiddleware(deps.Logger, handler)
	return handler
}

type router struct {
	deps Deps
}

func (rt *router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if rt.deps.ControlURL != "" || rt.deps.FunctionDomain != "" {
		rt.serveByHost(w, r)
		return
	}
	rt.serveControl(w, r)
}

func (rt *router) serveByHost(w http.ResponseWriter, r *http.Request) {
	host, ok := normalizedRequestHost(r.Host)
	if !ok {
		misdirected(w)
		return
	}
	control, _ := url.Parse(rt.deps.ControlURL)
	if strings.EqualFold(host, control.Hostname()) {
		rt.serveControl(w, r)
		return
	}
	if rt.deps.LandingURL != "" {
		landing, _ := url.Parse(rt.deps.LandingURL)
		if strings.EqualFold(host, landing.Hostname()) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				misdirected(w)
				return
			}
			target := strings.TrimSuffix(rt.deps.ControlURL, "/") + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusPermanentRedirect)
			return
		}
	}
	name, ok := managedFunctionName(host, rt.deps.FunctionDomain)
	if !ok {
		misdirected(w)
		return
	}
	if rt.deps.Invoker == nil {
		notImplemented(w, "funcbox: function invocation is not implemented yet")
		return
	}
	// Downstream authentication binds credentials to the normalized exact
	// function host. Remove an optional listener port and trailing dot once
	// here so redirects, callback consumption, and invoke-cookie validation
	// all use the same audience string.
	r.Host = host
	if r.URL.Path == "/.funcbox/auth/callback" {
		rt.deps.Invoker.ServeBrowserAuthCallback(w, r, name, host)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/.funcbox/") {
		http.NotFound(w, r)
		return
	}
	// Every function-host path belongs to the guest, including /api,
	// /auth, and /dashboard. Platform-owned paths may later live under
	// /.funcbox/ and must be intercepted here before guest invocation.
	rt.deps.Invoker.ServeByName(w, r, name)
}

func (rt *router) serveControl(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	path := r.URL.Path

	if path == "/" {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	if path == "/healthz" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}

	segments := pathSegments(path)
	if len(segments) == 0 {
		http.NotFound(w, r)
		return
	}

	if segments[0] == "api" {
		if rt.deps.API == nil {
			notImplemented(w, "funcbox: api is not implemented yet")
			return
		}
		rt.deps.API.ServeHTTP(w, r)
		return
	}

	if segments[0] == "dashboard" {
		if rt.deps.Dashboard == nil {
			notImplemented(w, "funcbox: dashboard is not implemented yet")
			return
		}
		rt.deps.Dashboard.ServeHTTP(w, r)
		return
	}

	if segments[0] == "metrics" {
		if h := rt.deps.Metrics.Handler(); h != nil {
			h.ServeHTTP(w, r)
			return
		}
		notImplemented(w, "funcbox: metrics are not enabled (FUNCBOX_METRICS=1 required)")
		return
	}

	if segments[0] == "auth" {
		if rt.deps.Auth == nil {
			notImplemented(w, "funcbox: auth is not implemented yet")
			return
		}
		rt.deps.Auth.ServeHTTP(w, r)
		return
	}

	// /dev/oidc/* is the dev-mode stub identity provider
	// path (or /dev/oidc/* when not in dev mode) falls through to the
	// generic reserved-route 501 below.
	if len(segments) >= 2 && segments[0] == "dev" && segments[1] == "oidc" {
		if rt.deps.DevOIDC == nil {
			notImplemented(w, "funcbox: dev oidc is not enabled (FUNCBOX_AUTH_MODE=dev required)")
			return
		}
		rt.deps.DevOIDC.ServeHTTP(w, r)
		return
	}

	if segments[0] == "dev" {
		notImplemented(w, "funcbox: dev is not implemented yet")
		return
	}

	if _, reserved := reservedRoutes[segments[0]]; reserved {
		notImplemented(w, "funcbox: "+segments[0]+" is not implemented yet")
		return
	}

	// Function invocation: /{owner}/{func}[/{path...}], i.e. anything with
	// at least 2 path segments that didn't match a reserved first segment
	// invoker untouched (full original path, method, and body) — the guest
	// sees the full "/{owner}/{func}/..." URL, not a stripped subpath
	if len(segments) >= 2 {
		if rt.deps.Invoker == nil {
			notImplemented(w, "funcbox: function invocation is not implemented yet")
			return
		}
		rt.deps.Invoker.Serve(w, r, segments[0], segments[1])
		return
	}

	http.NotFound(w, r)
}

func normalizedRequestHost(authority string) (string, bool) {
	if authority == "" || strings.ContainsAny(authority, "\\/@ \t\r\n") {
		return "", false
	}
	host := authority
	if h, _, err := net.SplitHostPort(authority); err == nil {
		host = h
	} else if strings.Contains(authority, ":") {
		return "", false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || net.ParseIP(host) != nil {
		return "", false
	}
	return host, true
}

func managedFunctionName(host, domain string) (string, bool) {
	suffix := "." + strings.ToLower(strings.TrimSuffix(domain, "."))
	if !strings.HasSuffix(host, suffix) {
		return "", false
	}
	name := strings.TrimSuffix(host, suffix)
	if name == "" || strings.Contains(name, ".") || len(name) > 63 || name[0] == '-' || name[len(name)-1] == '-' {
		return "", false
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return "", false
		}
	}
	return name, true
}

func misdirected(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusMisdirectedRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{
		"code": "unknown_host", "message": "host is not configured",
	}})
}

// pathSegments splits a URL path into its non-empty segments, e.g.
// "/owner/func/sub" -> ["owner", "func", "sub"].
func pathSegments(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

// notImplemented writes a 501 response with a small JSON error body,
// matching the {"error":{...}} shape used by the management API
// machine-readable.
func notImplemented(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusNotImplemented)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{
			"code":    "not_implemented",
			"message": message,
		},
	})
}
