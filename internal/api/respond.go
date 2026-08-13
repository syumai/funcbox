// Package api implements funcbox's management API HTTP handlers
// (/api/v1/*, tmp/07-http-api.md §7.3) on top of internal/service and
// internal/auth.
//
// Every request is authenticated by internal/auth.Auth.Middleware (session
// cookie or "Authorization: Bearer fbx_..." token) before it reaches any
// handler in this package; cookie-authenticated mutating requests
// additionally pass internal/auth.Auth.RequireCSRF. Handlers read the
// authenticated actor via the actor() helper (handler.go) and enforce
// tmp/07-http-api.md §7.4's authorization matrix via internal/authz,
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

// errorBody is the unified error envelope from tmp/07-http-api.md §7.3:
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
