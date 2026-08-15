// Package api implements funcbox's management API HTTP handlers
// internal/auth.
//
// Every request is authenticated by internal/auth.Auth.Middleware (session
// cookie or "Authorization: Bearer fbxa_..." access token) before it
// reaches any handler in this package, with the sole exception of the two
// unauthenticated CLI
// endpoints under /api/v1/cli/ (see handler.go's New); cookie-authenticated
// mutating requests
// additionally pass internal/auth.Auth.RequireCSRF. Handlers read the
// authenticated actor via the actor() helper (handler.go) and enforce
// deferring to internal/service for checks that need extra store lookups
// (workspace membership, org settings).
package api

import (
	"encoding/json"
	"net/http"
	"strings"
)

// writeJSON writes v as a JSON response body with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// {"error":{"code":"...", "message":"..."}}.
type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	var body errorBody
	body.Error.Code = code
	body.Error.Message = message
	writeJSON(w, status, body)
}

// splitPath splits a URL path into its non-empty segments.
func splitPath(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}
