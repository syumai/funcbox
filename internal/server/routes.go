package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// reservedRoutes are the first-path-segment names that are dispatched
// to a dedicated subsystem rather than treated as a function owner
// (tmp/07-http-api.md §7.1). "healthz" is handled separately as an
// exact top-level route rather than a subtree, since it must actually
// respond (200 "ok") instead of stubbing out.
var reservedRoutes = map[string]struct{}{
	"dashboard": {},
	"api":       {},
	"auth":      {},
	"dev":       {},
	"assets":    {},
}

// New builds the top-level funcbox-server http.Handler: routing plus
// the panic-recovery and request-logging middleware. logger must be
// non-nil.
func New(logger *slog.Logger) http.Handler {
	var handler http.Handler = http.HandlerFunc(route)
	handler = recoverMiddleware(logger, handler)
	handler = loggingMiddleware(logger, handler)
	return handler
}

func route(w http.ResponseWriter, r *http.Request) {
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

	if _, reserved := reservedRoutes[segments[0]]; reserved {
		notImplemented(w, "funcbox: "+segments[0]+" is not implemented yet")
		return
	}

	// Function invocation: /{owner}/{func}[/{path...}], i.e. anything
	// with at least 2 path segments that didn't match a reserved
	// first segment above (tmp/07-http-api.md §7.1).
	if len(segments) >= 2 {
		notImplemented(w, "funcbox: function invocation is not implemented yet")
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
// matching the {"error":{...}} shape planned for the management API
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
