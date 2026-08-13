package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/syumai/funcbox/manifest"
	"github.com/syumai/funcbox/server/internal/auth"
	"github.com/syumai/funcbox/server/internal/service"
	"github.com/syumai/funcbox/server/internal/settings"
	"github.com/syumai/funcbox/server/internal/store"
)

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
	u, err := h.Store.Users().ByID(r.Context(), a.ID)
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to load current user", err))
		return
	}
	org, err := h.loadOrg(r)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	orgSettings, err := settings.ParseOrg(org.Settings)
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to parse organization settings", err))
		return
	}
	publicUserID := ""
	if id, err := h.Store.PublicUserIDs().ByOwner(r.Context(), a.ID); err == nil {
		publicUserID = id.UserID
	}
	wss, err := h.Store.Workspaces().ListForUser(r.Context(), a.ID)
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to list workspaces", err))
		return
	}
	wsDTOs := make([]map[string]any, 0, len(wss))
	for _, ws := range wss {
		wsDTOs = append(wsDTOs, map[string]any{"id": ws.ID, "name": ws.Name})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":                 a.ID,
		"email":              u.Email,
		"name":               u.Name,
		"user_id":            publicUserID,
		"role":               string(u.Role),
		"language":           nullableLanguage(u.Language),
		"effective_language": settings.EffectiveLanguage(u.Language, orgSettings.Language),
		"workspaces":         wsDTOs,
	})
}

func nullableLanguage(language string) any {
	if language == "" {
		return nil
	}
	return language
}

// handleMePatch implements PATCH /api/v1/me: public User ID and language
// changes. The response's `id` remains the immutable internal database ID;
// `user_id` is the user-chosen public owner selector.
func (h *Handler) handleMePatch(w http.ResponseWriter, r *http.Request) {
	a := actor(r)
	u, err := h.Store.Users().ByID(r.Context(), a.ID)
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to load current user", err))
		return
	}
	var body struct {
		UserID   string          `json:"user_id"`
		Language json.RawMessage `json:"language"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be JSON")
		return
	}

	languageChanged := body.Language != nil
	newLanguage := u.Language
	if languageChanged {
		if bytes.Equal(bytes.TrimSpace(body.Language), []byte("null")) {
			newLanguage = ""
		} else if err := json.Unmarshal(body.Language, &newLanguage); err != nil || !settings.IsLanguage(newLanguage) {
			writeError(w, http.StatusBadRequest, "invalid_language", "language must be \"en\", \"ja\", or null to inherit the organization setting")
			return
		}
	}
	if body.UserID != "" {
		// GitHub-provider handles are fixed to the (lowercased) GitHub
		// username at registration/link time (tmp/13-public-mode.md
		// §13.2); the dashboard hides the change UI for that provider, and
		// this is the server-side enforcement of the same rule.
		if u.Provider == store.ProviderGitHub {
			writeError(w, http.StatusForbidden, "handle_locked", "the handle is fixed to the GitHub username for GitHub-linked accounts and cannot be changed")
			return
		}
		if err := manifest.ValidateUserID(body.UserID); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_user_id", err.Error())
			return
		}
	}

	if languageChanged {
		u.Language = newLanguage
		if err := h.Store.Users().Update(r.Context(), u); err != nil {
			h.writeServiceError(w, service.Internal("failed to update user language", err))
			return
		}
		_ = auth.Audit(r.Context(), h.Store, a.ID, "user.language.update", "user:"+a.ID,
			map[string]any{"language": nullableLanguage(u.Language)})
	}

	if body.UserID != "" {
		old, err := h.Store.PublicUserIDs().ByOwner(r.Context(), u.ID)
		if err != nil {
			h.writeServiceError(w, service.Internal("failed to look up current User ID", err))
			return
		}
		if old.UserID != body.UserID {
			if err := h.Store.PublicUserIDs().Rename(r.Context(), old.UserID, body.UserID); err != nil {
				if errors.Is(err, store.ErrConflict) {
					h.writeServiceError(w, service.ConflictErr("User ID is already taken", err))
					return
				}
				h.writeServiceError(w, service.Internal("failed to rename User ID", err))
				return
			}
			_ = auth.Audit(r.Context(), h.Store, a.ID, "user.id.update", "user:"+a.ID,
				map[string]any{"old_user_id": old.UserID, "new_user_id": body.UserID})
		}
	} else if current, err := h.Store.PublicUserIDs().ByOwner(r.Context(), u.ID); err == nil {
		body.UserID = current.UserID
	}

	org, err := h.loadOrg(r)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	orgSettings, err := settings.ParseOrg(org.Settings)
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to parse organization settings", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":                 a.ID,
		"user_id":            body.UserID,
		"language":           nullableLanguage(u.Language),
		"effective_language": settings.EffectiveLanguage(u.Language, orgSettings.Language),
	})
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
