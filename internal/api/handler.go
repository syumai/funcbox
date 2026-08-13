package api

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/syumai/funcbox/internal/service"
)

// Handler is the /api/v1 management API's http.Handler.
type Handler struct {
	Deployer  *service.Deployer
	Functions *service.Functions
	Logger    *slog.Logger
}

// New builds a Handler. deployer and functions must be non-nil; logger may
// be nil (errors simply aren't logged).
func New(deployer *service.Deployer, functions *service.Functions, logger *slog.Logger) *Handler {
	return &Handler{Deployer: deployer, Functions: functions, Logger: logger}
}

// ServeHTTP routes every /api/v1/* request (tmp/07-http-api.md §7.3). Only
// the "functions" resource is implemented this phase; org/workspace/me
// endpoints are Phase 2 (they need real authentication to be meaningful).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	segments := splitPath(path)

	if len(segments) >= 1 && segments[0] == "functions" {
		h.routeFunctions(w, r, segments[1:])
		return
	}
	writeError(w, http.StatusNotFound, "not_found", "unknown API route")
}

func (h *Handler) routeFunctions(w http.ResponseWriter, r *http.Request, rest []string) {
	switch {
	case len(rest) == 0:
		switch r.Method {
		case http.MethodGet:
			h.handleList(w, r)
		case http.MethodPost:
			h.handleDeploy(w, r)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		}

	case len(rest) == 2:
		owner, name := rest[0], rest[1]
		switch r.Method {
		case http.MethodGet:
			h.handleGet(w, r, owner, name)
		case http.MethodDelete:
			h.handleDelete(w, r, owner, name)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		}

	case len(rest) == 3 && rest[2] == "versions":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		h.handleListVersions(w, r, rest[0], rest[1])

	case len(rest) == 5 && rest[2] == "versions" && rest[4] == "activate":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		h.handleActivate(w, r, rest[0], rest[1], rest[3])

	default:
		writeError(w, http.StatusNotFound, "not_found", "unknown API route")
	}
}

// writeServiceError translates any error returned by internal/service into
// the unified {"error":{code,message}} envelope, logging server-side (5xx)
// failures with their underlying cause.
func (h *Handler) writeServiceError(w http.ResponseWriter, err error) {
	if svcErr, ok := service.AsError(err); ok {
		if svcErr.Status >= http.StatusInternalServerError && h.Logger != nil {
			h.Logger.Error("api: internal error", "code", svcErr.Code, "error", svcErr.Err)
		}
		writeError(w, svcErr.Status, svcErr.Code, svcErr.Message)
		return
	}
	if h.Logger != nil {
		h.Logger.Error("api: unexpected error", "error", err)
	}
	writeError(w, http.StatusInternalServerError, "internal", "internal error")
}
