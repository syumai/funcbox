package api

import (
	"bytes"
	"context"
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

// DeviceInfo unifies a store.CLICredential ("device", minted by `funcbox
// login`) and a store.OAuthGrant ("app", minted by the MCP/OAuth
// authorization-code flow -- server/internal/oauth) into one "connected
// device or app" entry, labeled by Kind ("cli" or "oauth") -- the shape
// ListDevices returns. Both are self-scoped, sliding-expiry credentials
// with the same fields (see their own doc comments in internal/store), so
// they render identically once unified; only their revocation path
// (RevokeDevice) differs by kind.
type DeviceInfo struct {
	Kind       string // "cli" or "oauth"
	ID         string
	Name       string // CLI: the credential's device name; OAuth: the client's registered name, or its client_id if unnamed
	CreatedAt  time.Time
	LastUsedAt time.Time // zero if never used
}

func deviceInfoDTO(d DeviceInfo) map[string]any {
	dto := map[string]any{
		"id":         d.ID,
		"kind":       d.Kind,
		"name":       d.Name,
		"created_at": d.CreatedAt.Format(time.RFC3339),
	}
	if !d.LastUsedAt.IsZero() {
		dto["last_used_at"] = d.LastUsedAt.Format(time.RFC3339)
	} else {
		dto["last_used_at"] = nil
	}
	return dto
}

// ListDevices returns act's own connected CLI-login devices AND OAuth app
// grants (e.g. an MCP client's connection, minted by server/internal/
// oauth's /oauth/token), combined and labeled by Kind -- the shared use
// case behind GET /api/v1/me/devices (handleDevicesList below) and the MCP
// devices tool group's list_connected_devices tool. Always self-scoped
// (act's own credentials only; there is no cross-user listing, admin or
// otherwise -- see RevokeDevice's doc comment for why revocation is
// stricter for MCP than for the pre-existing REST admin-override case).
func (h *Handler) ListDevices(ctx context.Context, act *store.User) ([]DeviceInfo, error) {
	creds, err := h.Store.CLICredentials().ListByUser(ctx, act.ID)
	if err != nil {
		return nil, service.Internal("failed to list devices", err)
	}
	grants, err := h.Store.OAuthGrants().ListByUser(ctx, act.ID)
	if err != nil {
		return nil, service.Internal("failed to list connected apps", err)
	}
	out := make([]DeviceInfo, 0, len(creds)+len(grants))
	for _, c := range creds {
		out = append(out, DeviceInfo{Kind: "cli", ID: c.ID, Name: c.Name, CreatedAt: c.CreatedAt, LastUsedAt: c.LastUsedAt})
	}
	for _, g := range grants {
		name := g.ClientID
		if client, err := h.Store.OAuthClients().ByID(ctx, g.ClientID); err == nil && client.Name != "" {
			name = client.Name
		}
		out = append(out, DeviceInfo{Kind: "oauth", ID: g.ID, Name: name, CreatedAt: g.CreatedAt, LastUsedAt: g.LastUsedAt})
	}
	return out, nil
}

// handleDevicesList implements GET /api/v1/me/devices: the caller's own
// connected CLI-login devices AND OAuth app grants (§14.4), each entry
// labeled "kind": "cli"|"oauth".
func (h *Handler) handleDevicesList(w http.ResponseWriter, r *http.Request) {
	devices, err := h.ListDevices(r.Context(), actor(r))
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	dtos := make([]map[string]any, 0, len(devices))
	for _, d := range devices {
		dtos = append(dtos, deviceInfoDTO(d))
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": dtos})
}

// RevokeDevice revokes act's own CLI-login device or OAuth app grant,
// identified by kind ("cli" or "oauth") + id -- the shared use case behind
// DELETE /api/v1/me/devices/{id} (handleDeviceDelete below, which tries
// "cli" then "oauth") and the MCP devices tool group's revoke_device tool.
//
// allowAdminOverride, when true, additionally permits an org admin to
// revoke ANY user's "cli" device (RESTs pre-existing behavior, since
// handleDeviceDelete predates this method and already allowed it). The MCP
// revoke_device tool always passes false: the design's devices group is
// deliberately self-scoped ("own only") regardless of the caller's role,
// so an admin's MCP session gets no more reach here than a plain member's.
// There is no admin override for "oauth" grants in either caller --
// OAuthGrantRepo has no cross-user lookup-by-id, only ListByUser, so an
// admin override would need a new store method this step doesn't add.
func (h *Handler) RevokeDevice(ctx context.Context, act *store.User, kind, id string, allowAdminOverride bool) error {
	switch kind {
	case "cli":
		creds, err := h.Store.CLICredentials().ListByUser(ctx, act.ID)
		if err != nil {
			return service.Internal("failed to list devices", err)
		}
		owned := false
		for _, c := range creds {
			if c.ID == id {
				owned = true
				break
			}
		}
		if !owned && !(allowAdminOverride && act.Role == store.RoleAdmin) {
			return service.NotFoundErr("device not found", nil)
		}
		if err := h.Store.CLICredentials().Delete(ctx, id); err != nil {
			return service.Internal("failed to delete device", err)
		}
		_ = auth.Audit(ctx, h.Store, act.ID, "cli_credential.delete", "cli_credential:"+id, nil)
		return nil

	case "oauth":
		grants, err := h.Store.OAuthGrants().ListByUser(ctx, act.ID)
		if err != nil {
			return service.Internal("failed to list connected apps", err)
		}
		owned := false
		for _, g := range grants {
			if g.ID == id {
				owned = true
				break
			}
		}
		if !owned {
			return service.NotFoundErr("connected app not found", nil)
		}
		if err := h.Store.OAuthGrants().Delete(ctx, id); err != nil {
			return service.Internal("failed to delete connected app", err)
		}
		_ = auth.Audit(ctx, h.Store, act.ID, "oauth_grant.delete", "oauth_grant:"+id, nil)
		return nil

	default:
		return service.BadRequest("invalid_kind", `device kind must be "cli" or "oauth"`, nil)
	}
}

// handleDeviceDelete implements DELETE /api/v1/me/devices/{id}: revokes a
// CLI-login credential or OAuth app grant identified by id alone (trying
// "cli" first, then "oauth", since the REST route carries no kind), only
// the issuing user (or, for a CLI device, an org admin) may revoke one.
// Revoking a CLI credential stops future access-token minting immediately
// (POST /api/v1/cli/access-token looks the credential up by hash on every
// call); any access token already minted from it stays valid until its
// own short (<= 1 hour) natural expiry, per §14.5's documented design.
// Revoking an OAuth grant is the equivalent stop for its refresh token
// (server/internal/oauth's POST /oauth/token refresh grant).
func (h *Handler) handleDeviceDelete(w http.ResponseWriter, r *http.Request, id string) {
	a := actor(r)
	err := h.RevokeDevice(r.Context(), a, "cli", id, true)
	if err != nil {
		if svcErr, ok := service.AsError(err); ok && svcErr.Status == http.StatusNotFound {
			err = h.RevokeDevice(r.Context(), a, "oauth", id, false)
		}
	}
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
