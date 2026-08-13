// cli.go implements the /api/v1/cli/* endpoints backing §14.4/§14.5 of
// tmp/14-auth-and-pool-improvements.md's browser-based `funcbox login`
// flow:
//
//   - POST /api/v1/cli/authorize: session + CSRF-protected (the normal
//     /api/v1/* auth chain), called ONLY from the dashboard's explicit
//     "funcbox CLI login" approval page after the user clicks Approve. It
//     mints the one-time code the browser then hands off to the CLI's
//     loopback listener.
//   - POST /api/v1/cli/token: UNAUTHENTICATED (see handler.go's mux --
//     it's dispatched before Auth.Middleware ever runs). The code+PKCE
//     verifier pair presented here IS the proof of identity; there is no
//     session or bearer credential. Exchanges the code for a long-lived
//     CLICredential.
//   - POST /api/v1/cli/access-token: also UNAUTHENTICATED at the
//     Auth.Middleware level -- it authenticates itself, by the CLI
//     credential presented in its own Authorization header (never a
//     session or access token), and mints a short-lived access token.
package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/syumai/funcbox/server/internal/auth"
	"github.com/syumai/funcbox/server/internal/service"
)

// routeCLI dispatches the session-authenticated CLI route
// (POST /api/v1/cli/authorize). Its unauthenticated siblings
// (/cli/token, /cli/access-token) never reach here -- see
// isUnauthenticatedCLIPath and handleUnauthenticatedCLI in handler.go.
func (h *Handler) routeCLI(w http.ResponseWriter, r *http.Request, rest []string) {
	switch {
	case len(rest) == 1 && rest[0] == "authorize":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		h.handleCLIAuthorize(w, r)
	default:
		writeError(w, http.StatusNotFound, "not_found", "unknown API route")
	}
}

// handleCLIAuthorize implements POST /api/v1/cli/authorize: the dashboard
// approval page's "Approve" action. The caller is already authenticated
// (session cookie, CSRF-checked by the normal chain) -- this endpoint's
// entire job is to bind a fresh one-time code to that identity.
func (h *Handler) handleCLIAuthorize(w http.ResponseWriter, r *http.Request) {
	a := actor(r)
	var body struct {
		Redirect  string `json:"redirect"`
		Challenge string `json:"challenge"`
		Name      string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", `request body must be JSON: {"redirect","challenge","name"}`)
		return
	}
	code, err := h.Auth.IssueCLIAuthCode(r.Context(), a.ID, body.Name, body.Redirect, body.Challenge)
	if err != nil {
		if errors.Is(err, auth.ErrCLIAuthInvalidRequest) {
			writeError(w, http.StatusBadRequest, "invalid_cli_auth_request", "the CLI login request is malformed or its redirect/challenge is not acceptable")
			return
		}
		h.writeServiceError(w, service.Internal("failed to issue CLI authorization code", err))
		return
	}
	_ = auth.Audit(r.Context(), h.Store, a.ID, "cli_login.approve", "user:"+a.ID, map[string]any{"name": body.Name})
	writeJSON(w, http.StatusOK, map[string]any{"code": code})
}

// handleCLIToken implements the UNAUTHENTICATED POST /api/v1/cli/token:
// the loopback callback's code+verifier exchange for a CLICredential.
func (h *Handler) handleCLIToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code     string `json:"code"`
		Verifier string `json:"verifier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", `request body must be JSON: {"code","verifier"}`)
		return
	}
	plaintext, cred, err := h.Auth.ExchangeCLICode(r.Context(), body.Code, body.Verifier)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrPKCEMismatch):
			writeError(w, http.StatusBadRequest, "pkce_mismatch", "the PKCE verifier does not match the authorization's challenge")
		case errors.Is(err, auth.ErrCLIAuthCodeInvalid):
			writeError(w, http.StatusBadRequest, "invalid_grant", "the authorization code is invalid, expired, or already used")
		default:
			h.writeServiceError(w, service.Internal("failed to exchange CLI authorization code", err))
		}
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"credential": plaintext,
		"name":       cred.Name,
		"created_at": cred.CreatedAt.Format(time.RFC3339),
	})
}

// handleCLIAccessToken implements the UNAUTHENTICATED (at the
// Auth.Middleware level) POST /api/v1/cli/access-token: authenticated
// instead by the "fbxc_..." CLI credential in its own Authorization
// header, it mints a short-lived access token (§14.5).
func (h *Handler) handleCLIAccessToken(w http.ResponseWriter, r *http.Request) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || raw == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing CLI credential")
		return
	}
	var body struct {
		TTL string `json:"ttl"` // Go duration string, e.g. "15m"; empty = server default
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_body", `request body must be JSON: {"ttl": "15m"} or empty`)
		return
	}
	var ttl time.Duration
	if body.TTL != "" {
		d, err := time.ParseDuration(body.TTL)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_ttl", `ttl must be a Go duration string, e.g. "15m"`)
			return
		}
		ttl = d
	}
	token, expiresAt, err := h.Auth.MintAccessTokenFromCredential(r.Context(), raw, ttl)
	if err != nil {
		if errors.Is(err, auth.ErrCLICredentialInvalid) {
			writeError(w, http.StatusUnauthorized, "unauthorized", "CLI credential is invalid, revoked, or expired -- run `funcbox login` again")
			return
		}
		h.writeServiceError(w, service.Internal("failed to mint access token", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"expires_at":   expiresAt.Format(time.RFC3339),
	})
}
