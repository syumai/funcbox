package api

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/syumai/funcbox/internal/auth"
	"github.com/syumai/funcbox/internal/service"
	"github.com/syumai/funcbox/internal/store"
)

// Handler is the /api/v1 management API's http.Handler.
type Handler struct {
	Deployer  *service.Deployer
	Functions *service.Functions
	Store     store.Store
	Auth      *auth.Auth
	Logger    *slog.Logger

	mux http.Handler
}

// New builds a Handler. deployer, functions, st, and authSvc must be
// non-nil; logger may be nil (errors simply aren't logged).
func New(deployer *service.Deployer, functions *service.Functions, st store.Store, authSvc *auth.Auth, logger *slog.Logger) *Handler {
	h := &Handler{Deployer: deployer, Functions: functions, Store: st, Auth: authSvc, Logger: logger}
	h.mux = authSvc.Middleware(authSvc.RequireCSRF(http.HandlerFunc(h.route)))
	return h
}

// ServeHTTP requires authentication (Auth.Middleware) and, for
// cookie-authenticated mutating requests, a valid CSRF token
// (Auth.RequireCSRF), then dispatches to route -- every /api/v1/*
// endpoint requires a signed-in actor (tmp/07-http-api.md §7.3).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// ServeInternal dispatches r as an ALREADY-authenticated request, with act
// installed directly as the request's actor -- bypassing both Auth.Middleware
// (no cookie/bearer-token parsing) and Auth.RequireCSRF (no double-submit
// check). It exists for exactly one caller: internal/dashboard's
// env.INTERNAL_API binding (tmp/09-dashboard.md §9.3), which calls this
// package's handlers in-process on behalf of the dashboard's own SSR app --
// a privileged internal function, not a network client -- after
// independently verifying act's identity via its own HMAC-signed
// caller-token mechanism. That verification is what makes skipping
// Middleware/RequireCSRF here safe: this method must never be reachable from
// an actual HTTP request (ServeHTTP, the public entry point, does not call
// it), and callers outside internal/dashboard have no legitimate reason to
// hold an *auth.Actor to pass in.
func (h *Handler) ServeInternal(w http.ResponseWriter, r *http.Request, act *auth.Actor) {
	h.route(w, r.WithContext(auth.WithActor(r.Context(), act)))
}

// route dispatches an already-authenticated request across the
// /api/v1/{functions,org,workspaces,me} resource trees
// (tmp/07-http-api.md §7.3).
func (h *Handler) route(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	segments := splitPath(path)

	if len(segments) == 0 {
		writeError(w, http.StatusNotFound, "not_found", "unknown API route")
		return
	}

	switch segments[0] {
	case "functions":
		h.routeFunctions(w, r, segments[1:])
	case "org":
		h.routeOrg(w, r, segments[1:])
	case "workspaces":
		h.routeWorkspaces(w, r, segments[1:])
	case "me":
		h.routeMe(w, r, segments[1:])
	default:
		writeError(w, http.StatusNotFound, "not_found", "unknown API route")
	}
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

	case len(rest) == 3 && rest[2] == "logs":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		h.handleLogs(w, r, rest[0], rest[1])

	case len(rest) == 5 && rest[2] == "versions" && rest[4] == "activate":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		h.handleActivate(w, r, rest[0], rest[1], rest[3])

	case len(rest) == 4 && rest[2] == "env":
		owner, name, key := rest[0], rest[1], rest[3]
		switch r.Method {
		case http.MethodPut:
			h.handleSetEnv(w, r, owner, name, key)
		case http.MethodDelete:
			h.handleDeleteEnv(w, r, owner, name, key)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		}

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

// actor returns the authenticated caller. Every route reachable through
// ServeHTTP has already passed Auth.Middleware, which guarantees a non-nil
// Actor is present in the request context (Middleware itself responds 401
// otherwise, well before route/actor is ever reached).
func actor(r *http.Request) *store.User {
	return auth.ActorFromContext(r.Context()).User
}
