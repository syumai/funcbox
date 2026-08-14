package api

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/syumai/funcbox/server/internal/auth"
	"github.com/syumai/funcbox/server/internal/service"
	"github.com/syumai/funcbox/server/internal/store"
)

// Handler is the /api/v1 management API's http.Handler.
type Handler struct {
	Deployer           *service.Deployer
	Functions          *service.Functions
	Store              store.Store
	Auth               *auth.Auth
	Logger             *slog.Logger
	managedFunctionURL func(name, requestPath string) (string, error)
	baseURL            string

	mux http.Handler
}

// Option customizes management API response generation.
type Option func(*Handler)

// WithManagedFunctionURL adds canonical managed-function URLs to function
// DTOs. The server passes config.Config.ManagedFunctionURL here -- but only
// when FUNCBOX_FUNCTION_DOMAIN is actually configured; see functionDTO's
// doc comment for why this option being unset (rather than set to a
// function that always errors) is what lets the path-based-mode URL
// fallback below run silently, with no per-request ERROR log line.
func WithManagedFunctionURL(build func(name, requestPath string) (string, error)) Option {
	return func(h *Handler) { h.managedFunctionURL = build }
}

// WithBaseURL sets the control-plane's own externally reachable base URL
// (config.Config.BaseURL), consulted by functionDTO as the path-based
// "<BaseURL>/<owner>/<name>" URL fallback whenever WithManagedFunctionURL
// wasn't configured (FUNCBOX_FUNCTION_DOMAIN unset).
func WithBaseURL(base string) Option {
	return func(h *Handler) { h.baseURL = strings.TrimSuffix(base, "/") }
}

// New builds a Handler. deployer, functions, st, and authSvc must be
// non-nil; logger may be nil (errors simply aren't logged).
func New(deployer *service.Deployer, functions *service.Functions, st store.Store, authSvc *auth.Auth, logger *slog.Logger, opts ...Option) *Handler {
	h := &Handler{Deployer: deployer, Functions: functions, Store: st, Auth: authSvc, Logger: logger}
	for _, opt := range opts {
		opt(h)
	}
	authenticated := authSvc.Middleware(requirePendingApproved(authSvc.RequireCSRF(http.HandlerFunc(h.route))))
	h.mux = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// POST /api/v1/cli/token and POST /api/v1/cli/access-token
		// (cli.go) authenticate themselves -- by PKCE code+verifier and by
		// CLI credential respectively, neither of which Auth.Middleware
		// recognizes as a bearer credential -- so they must never pass
		// through it (a session cookie or access token is not, and must
		// not be required to, call either). Every other /api/v1/* route,
		// including POST /api/v1/cli/authorize, goes through the normal
		// chain.
		if isUnauthenticatedCLIPath(r.URL.Path) {
			h.routeUnauthenticatedCLI(w, r)
			return
		}
		authenticated.ServeHTTP(w, r)
	})
	return h
}

// isUnauthenticatedCLIPath reports whether path is one of the two CLI
// endpoints that bypass Auth.Middleware entirely (see New's doc comment).
func isUnauthenticatedCLIPath(path string) bool {
	return path == "/api/v1/cli/token" || path == "/api/v1/cli/access-token"
}

// routeUnauthenticatedCLI dispatches the two paths isUnauthenticatedCLIPath
// recognizes. It is reached directly from h.mux, never through h.route (no
// Actor is available here -- there is deliberately none for either
// handler to read).
func (h *Handler) routeUnauthenticatedCLI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if r.URL.Path == "/api/v1/cli/token" {
		h.handleCLIToken(w, r)
		return
	}
	h.handleCLIAccessToken(w, r)
}

// requirePendingApproved rejects every /api/v1/* request from a
// store.UserStatusPending actor with a distinguishable 403 (tmp/13-public-mode.md
// §13.3: "API は authz レイヤーで一律拒否"), running right after
// Auth.Middleware installs the actor and before RequireCSRF/route see the
// request. This is a blanket rule -- it applies uniformly to every route
// under this prefix, including POST /api/v1/cli/authorize (in practice a
// pending user's dashboard session never even reaches that call --
// internal/dashboard's own pending gate shows the "access request
// pending" page before the pool, and therefore INTERNAL_API, ever runs --
// but the block is still enforced here too, uniformly, with no special
// case needed). The two CLI endpoints that bypass Auth.Middleware
// entirely (POST /api/v1/cli/token, POST /api/v1/cli/access-token; see
// New's doc comment) never reach this middleware -- a pending user CAN
// still mint an access token there (MintAccessTokenFromCredential uses
// validateAuthenticatable, the same lenient check Authenticate itself
// uses, deliberately allowing pending through) but gets the same 403
// here on every actual /api/v1/* call made with it, exactly as a pending
// user's session cookie always has.
func requirePendingApproved(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := auth.ActorFromContext(r.Context()); a != nil && a.User.Status == store.UserStatusPending {
			writeError(w, http.StatusForbidden, "pending_approval", "this account is awaiting organization administrator approval")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ServeHTTP requires authentication (Auth.Middleware) and, for
// cookie-authenticated mutating requests, a valid CSRF token
// (Auth.RequireCSRF), then dispatches to route -- every /api/v1/*
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// ServeInternal dispatches r as an ALREADY-authenticated request, with act
// installed directly as the request's actor -- bypassing both Auth.Middleware
// (no cookie/bearer-token parsing), Auth.RequireCSRF (no double-submit
// check), AND requirePendingApproved (h.mux's chain, not h.route itself).
// The last of those is safe only because internal/dashboard's own
// ServeHTTP never invokes the dashboard's pool -- and therefore never
// reaches this method -- for a store.UserStatusPending actor in the first
// place (it renders the "access request pending" page itself instead); if
// that invariant ever changed, ServeInternal would need its own pending
// check. It exists for exactly one caller: internal/dashboard's
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
	case "cli":
		h.routeCLI(w, r, segments[1:])
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

// actor returns the authenticated caller. Every route that calls this --
// everything reachable through h.route, i.e. every /api/v1/* route except
// the two unauthenticated CLI endpoints handled directly by
// routeUnauthenticatedCLI (POST /api/v1/cli/token, POST
// /api/v1/cli/access-token; see New's doc comment) -- has already passed
// Auth.Middleware, which guarantees a non-nil Actor is present in the
// request context (Middleware itself responds 401 otherwise, well before
// route/actor is ever reached). Neither of those two CLI handlers calls
// actor(): they authenticate themselves, by PKCE code+verifier and by CLI
// credential respectively, and have no Actor to read.
func actor(r *http.Request) *store.User {
	return auth.ActorFromContext(r.Context()).User
}
