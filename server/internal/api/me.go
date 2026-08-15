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

	case len(rest) == 1 && rest[0] == "devices":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		h.handleDevicesList(w, r)

	case len(rest) == 2 && rest[0] == "devices":
		if r.Method != http.MethodDelete {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		h.handleDeviceDelete(w, r, rest[1])

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
	// Each workspace entry additionally carries its max_functions_per_member
	// quota and the caller's current per-creator count, when a limit
	// applies -- the dashboard's new-deploy
	// page (already calling GET /me for its owner list) uses this to show
	// remaining quota per owner without a separate round trip.
	wsDTOs := make([]map[string]any, 0, len(wss))
	for _, ws := range wss {
		entry := map[string]any{"id": ws.ID, "name": ws.Name}
		if wsSet, wsErr := settings.ParseWorkspace(ws.Settings); wsErr == nil && wsSet.MaxFunctionsPerMember > 0 {
			if n, cErr := h.Store.Functions().CountByWorkspaceAndCreator(r.Context(), ws.ID, a.ID); cErr == nil {
				entry["function_count"] = n
				entry["function_limit"] = wsSet.MaxFunctionsPerMember
			}
		}
		wsDTOs = append(wsDTOs, entry)
	}

	body := map[string]any{
		"id":                 a.ID,
		"email":              u.Email,
		"name":               u.Name,
		"user_id":            publicUserID,
		"role":               string(u.Role),
		"language":           nullableLanguage(u.Language),
		"effective_language": settings.EffectiveLanguage(u.Language, orgSettings.Language),
		"workspaces":         wsDTOs,
	}
	// Personal-scope (max_functions_per_user) quota, same shape as each
	// workspace entry above.
	if orgSettings.MaxFunctionsPerUser > 0 {
		if n, cErr := h.Store.Functions().CountByOwner(r.Context(), store.OwnerTypeUser, a.ID); cErr == nil {
			body["personal_function_count"] = n
			body["personal_function_limit"] = orgSettings.MaxFunctionsPerUser
		}
	}
	// pending_approval_count feeds the dashboard nav's pending-requests
	// badge, admin-only, computed here since
	// baseProps (dashboard/src/render.ts) already fetches /me on every page
	// -- reusing that round trip instead of adding a second one.
	if a.Role == store.RoleAdmin {
		if users, uErr := h.Store.Users().List(r.Context()); uErr == nil {
			n := 0
			for _, other := range users {
				if other.Status == store.UserStatusPending {
					n++
				}
			}
			body["pending_approval_count"] = n
		}
	}
	writeJSON(w, http.StatusOK, body)
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
		// username at registration/link time; the dashboard hides the
		// change UI for that provider, and
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

// deviceDTO renders a store.CLICredential for the dashboard's "connected
// devices" list (§14.4) -- name/created/last-used, never the secret itself
// (that's shown exactly once, by the CLI, at `funcbox login` time, never
// by the management API).
func deviceDTO(c *store.CLICredential) map[string]any {
	dto := map[string]any{
		"id":         c.ID,
		"name":       c.Name,
		"created_at": c.CreatedAt.Format(time.RFC3339),
	}
	if !c.LastUsedAt.IsZero() {
		dto["last_used_at"] = c.LastUsedAt.Format(time.RFC3339)
	} else {
		dto["last_used_at"] = nil
	}
	return dto
}

// handleDevicesList implements GET /api/v1/me/devices: the caller's own
// connected CLI-login devices (§14.4).
func (h *Handler) handleDevicesList(w http.ResponseWriter, r *http.Request) {
	a := actor(r)
	creds, err := h.Store.CLICredentials().ListByUser(r.Context(), a.ID)
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to list devices", err))
		return
	}
	dtos := make([]map[string]any, 0, len(creds))
	for _, c := range creds {
		dtos = append(dtos, deviceDTO(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": dtos})
}

// handleDeviceDelete implements DELETE /api/v1/me/devices/{id}: revokes a
// CLI-login credential, only the issuing user (or an org admin) may revoke
// one. Revoking stops future access-token minting immediately
// (POST /api/v1/cli/access-token looks the credential up by hash on every
// call); any access token already minted from it stays valid until its
// own short (<= 1 hour) natural expiry, per §14.5's documented design.
func (h *Handler) handleDeviceDelete(w http.ResponseWriter, r *http.Request, id string) {
	a := actor(r)
	creds, err := h.Store.CLICredentials().ListByUser(r.Context(), a.ID)
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to list devices", err))
		return
	}
	owned := false
	for _, c := range creds {
		if c.ID == id {
			owned = true
			break
		}
	}
	if !owned && a.Role != store.RoleAdmin {
		h.writeServiceError(w, service.NotFoundErr("device not found", nil))
		return
	}
	if err := h.Store.CLICredentials().Delete(r.Context(), id); err != nil {
		h.writeServiceError(w, service.Internal("failed to delete device", err))
		return
	}
	_ = auth.Audit(r.Context(), h.Store, a.ID, "cli_credential.delete", "cli_credential:"+id, nil)
	w.WriteHeader(http.StatusNoContent)
}
