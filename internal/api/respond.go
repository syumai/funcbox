// Package api implements funcbox's management API HTTP handlers
// (/api/v1/*, tmp/07-http-api.md §7.3) on top of internal/service.
//
// Authentication is explicitly OUT OF SCOPE for this phase (Phase 2):
// tmp/07-http-api.md §7.3 describes session-cookie and Bearer-token auth,
// but no handler here checks either. Every request is trusted at face
// value for its owner/name path and form parameters — see
// internal/service.Deployer's package doc comment for the Phase 1
// owner-auto-provisioning shortcut this implies, and for what Phase 2's
// auth work needs to change here (primarily: derive owner/actor from a
// verified session/token instead of trusting the request body, and add the
// authorization checks tmp/07-http-api.md §7.4's matrix describes).
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
