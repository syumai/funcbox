package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/syumai/funcbox/internal/invoke"
)

// reservedRoutes are the first-path-segment names that are dispatched to a
// dedicated subsystem rather than treated as a function owner
// (tmp/07-http-api.md §7.1). "healthz" is handled separately as an exact
// top-level route rather than a subtree, since it must actually respond
// (200 "ok") instead of stubbing out. "api", "auth", and "dev" are also
// handled separately (see route): they have real handlers when the
// corresponding Deps field is set, and fall back to a 501 stub otherwise.
var reservedRoutes = map[string]struct{}{
	"dashboard": {},
	"assets":    {},
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
}

// New builds the top-level funcbox-server http.Handler: routing plus the
// panic-recovery and request-logging middleware. deps.Logger must be
// non-nil.
func New(deps Deps) http.Handler {
	var handler http.Handler = &router{deps: deps}
	handler = recoverMiddleware(deps.Logger, handler)
	handler = loggingMiddleware(deps.Logger, handler)
	return handler
}

type router struct {
	deps Deps
}

func (rt *router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	if segments[0] == "auth" {
		if rt.deps.Auth == nil {
			notImplemented(w, "funcbox: auth is not implemented yet")
			return
		}
		rt.deps.Auth.ServeHTTP(w, r)
		return
	}

	// /dev/oidc/* is the dev-mode stub identity provider
	// (tmp/07-http-api.md §7.1: "dev モード時のみ"); any other /dev/*
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
	// above (tmp/07-http-api.md §7.1). The request is handed to the
	// invoker untouched (full original path, method, and body) — the guest
	// sees the full "/{owner}/{func}/..." URL, not a stripped subpath
	// (tmp/07-http-api.md §7.1: "プレフィックスを剥がさない").
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
// (tmp/07-http-api.md §7.3) so stubbed routes are already
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
