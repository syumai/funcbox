package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/syumai/funcbox/internal/auth"
	"github.com/syumai/funcbox/internal/service"
	"github.com/syumai/funcbox/internal/store"
	"github.com/syumai/funcbox/manifest"
)

// routeMe dispatches /api/v1/me/... (tmp/07-http-api.md §7.3).
func (h *Handler) routeMe(w http.ResponseWriter, r *http.Request, rest []string) {
	switch {
	case len(rest) == 0:
		switch r.Method {
		case http.MethodGet:
			h.handleMeGet(w, r)
		case http.MethodPatch:
			h.handleMePatch(w, r)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		}

	case len(rest) == 1 && rest[0] == "tokens":
		switch r.Method {
		case http.MethodGet:
			h.handleTokensList(w, r)
		case http.MethodPost:
			h.handleTokenCreate(w, r)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		}

	case len(rest) == 2 && rest[0] == "tokens":
		if r.Method != http.MethodDelete {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		h.handleTokenDelete(w, r, rest[1])

	default:
		writeError(w, http.StatusNotFound, "not_found", "unknown API route")
	}
}

// handleMeGet implements GET /api/v1/me: profile, org role, and workspace
// memberships.
func (h *Handler) handleMeGet(w http.ResponseWriter, r *http.Request) {
	a := actor(r)
	handle := ""
	if hnd, err := h.Store.Handles().ByOwner(r.Context(), store.OwnerTypeUser, a.ID); err == nil {
		handle = hnd.Handle
	}
	wss, err := h.Store.Workspaces().ListForUser(r.Context(), a.ID)
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to list workspaces", err))
		return
	}
	wsDTOs := make([]map[string]any, 0, len(wss))
	for _, ws := range wss {
		hnd, err := h.Store.Handles().ByOwner(r.Context(), store.OwnerTypeWorkspace, ws.ID)
		if err != nil {
			continue
		}
		wsDTOs = append(wsDTOs, map[string]any{"id": ws.ID, "handle": hnd.Handle, "name": ws.Name})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":         a.ID,
		"email":      a.Email,
		"name":       a.Name,
		"handle":     handle,
		"role":       string(a.Role),
		"workspaces": wsDTOs,
	})
}

// handleMePatch implements PATCH /api/v1/me: handle change
// (tmp/06-data-model.md: "後から変更可能（変更は audit 対象）").
func (h *Handler) handleMePatch(w http.ResponseWriter, r *http.Request) {
	a := actor(r)
	var body struct {
		Handle string `json:"handle"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be JSON: {\"handle\": \"...\"}")
		return
	}
	if body.Handle == "" {
		writeJSON(w, http.StatusOK, map[string]any{"id": a.ID})
		return
	}
	if err := manifest.ValidateHandle(body.Handle); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_handle", err.Error())
		return
	}

	old, err := h.Store.Handles().ByOwner(r.Context(), store.OwnerTypeUser, a.ID)
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to look up current handle", err))
		return
	}
	if old.Handle == body.Handle {
		writeJSON(w, http.StatusOK, map[string]any{"handle": old.Handle})
		return
	}
	if err := h.Store.Handles().Rename(r.Context(), old.Handle, body.Handle); err != nil {
		if errors.Is(err, store.ErrConflict) {
			h.writeServiceError(w, service.ConflictErr("handle is already taken", err))
			return
		}
		h.writeServiceError(w, service.Internal("failed to rename handle", err))
		return
	}
	_ = auth.Audit(r.Context(), h.Store, a.ID, "user.handle.update", "user:"+a.ID,
		map[string]any{"old_handle": old.Handle, "new_handle": body.Handle})
	writeJSON(w, http.StatusOK, map[string]any{"handle": body.Handle})
}

func tokenDTO(t *store.APIToken) map[string]any {
	return map[string]any{
		"id":         t.ID,
		"name":       t.Name,
		"expires_at": t.ExpiresAt.Format(time.RFC3339),
		"created_at": t.CreatedAt.Format(time.RFC3339),
	}
}

// handleTokensList implements GET /api/v1/me/tokens.
func (h *Handler) handleTokensList(w http.ResponseWriter, r *http.Request) {
	a := actor(r)
	tokens, err := h.Store.Tokens().ListByUser(r.Context(), a.ID)
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to list tokens", err))
		return
	}
	dtos := make([]map[string]any, 0, len(tokens))
	for _, t := range tokens {
		dtos = append(dtos, tokenDTO(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": dtos})
}

// handleTokenCreate implements POST /api/v1/me/tokens: the plaintext
// token is returned ONLY in this response (tmp/07-http-api.md §7.3).
func (h *Handler) handleTokenCreate(w http.ResponseWriter, r *http.Request) {
	a := actor(r)
	var body struct {
		Name      string `json:"name"`
		ExpiresAt string `json:"expires_at"` // RFC3339
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be JSON: {\"name\", \"expires_at\"}")
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "missing_name", "name is required")
		return
	}
	expiresAt, err := time.Parse(time.RFC3339, body.ExpiresAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_expires_at", "expires_at must be an RFC3339 timestamp")
		return
	}
	if err := auth.ValidateTokenTTL(time.Now(), expiresAt); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_expires_at", err.Error())
		return
	}

	plaintext, hash, err := auth.GenerateToken()
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to generate token", err))
		return
	}
	tok := &store.APIToken{UserID: a.ID, TokenHash: hash, Name: body.Name, ExpiresAt: expiresAt}
	if err := h.Store.Tokens().Create(r.Context(), tok); err != nil {
		h.writeServiceError(w, service.Internal("failed to create token", err))
		return
	}
	_ = auth.Audit(r.Context(), h.Store, a.ID, "token.create", "token:"+tok.ID, map[string]any{"name": tok.Name})

	body2 := tokenDTO(tok)
	body2["token"] = plaintext
	writeJSON(w, http.StatusCreated, body2)
}

// handleTokenDelete implements DELETE /api/v1/me/tokens/{id}: only the
// issuing user (or an org admin) may revoke a token.
func (h *Handler) handleTokenDelete(w http.ResponseWriter, r *http.Request, id string) {
	a := actor(r)
	tokens, err := h.Store.Tokens().ListByUser(r.Context(), a.ID)
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to list tokens", err))
		return
	}
	owned := false
	for _, t := range tokens {
		if t.ID == id {
			owned = true
			break
		}
	}
	if !owned && a.Role != store.RoleAdmin {
		h.writeServiceError(w, service.NotFoundErr("token not found", nil))
		return
	}
	if err := h.Store.Tokens().Delete(r.Context(), id); err != nil {
		h.writeServiceError(w, service.Internal("failed to delete token", err))
		return
	}
	_ = auth.Audit(r.Context(), h.Store, a.ID, "token.delete", "token:"+id, nil)
	w.WriteHeader(http.StatusNoContent)
}
