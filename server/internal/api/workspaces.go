package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/syumai/funcbox/server/internal/auth"
	"github.com/syumai/funcbox/server/internal/authz"
	"github.com/syumai/funcbox/server/internal/service"
	"github.com/syumai/funcbox/server/internal/settings"
	"github.com/syumai/funcbox/server/internal/store"
)

// routeWorkspaces dispatches every /api/v1/workspaces* request. When the
// organization has open mode enabled, the whole workspace feature is
// disabled: every route under this prefix 404s, exactly as if it didn't
// exist, rather than 403ing (which
// would still confirm the feature exists and just isn't permitted).
func (h *Handler) routeWorkspaces(w http.ResponseWriter, r *http.Request, rest []string) {
	openMode, err := h.openModeEnabled(r.Context())
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to load organization settings", err))
		return
	}
	if openMode {
		writeError(w, http.StatusNotFound, "not_found", "unknown API route")
		return
	}

	switch {
	case len(rest) == 0:
		switch r.Method {
		case http.MethodGet:
			h.handleWorkspacesList(w, r)
		case http.MethodPost:
			h.handleWorkspaceCreate(w, r)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		}

	case len(rest) == 1:
		switch r.Method {
		case http.MethodGet:
			h.handleWorkspaceGet(w, r, rest[0])
		case http.MethodPatch:
			h.handleWorkspacePatch(w, r, rest[0])
		case http.MethodDelete:
			h.handleWorkspaceDelete(w, r, rest[0])
		default:
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		}

	case len(rest) == 3 && rest[1] == "members":
		workspaceID, userID := rest[0], rest[2]
		switch r.Method {
		case http.MethodGet:
			h.handleWorkspaceMemberGet(w, r, workspaceID, userID)
		case http.MethodPut:
			h.handleWorkspaceMemberPut(w, r, workspaceID, userID)
		case http.MethodDelete:
			h.handleWorkspaceMemberDelete(w, r, workspaceID, userID)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		}

	default:
		writeError(w, http.StatusNotFound, "not_found", "unknown API route")
	}
}

func workspaceDTO(ws *store.Workspace, wsSet settings.Workspace) map[string]any {
	return map[string]any{
		"id":           ws.ID,
		"name":         ws.Name,
		"settings":     wsSet,
		"settings_gen": ws.SettingsGen,
		"created_at":   ws.CreatedAt,
	}
}

// resolveWorkspace looks up an immutable workspace ID and returns it with
// its parsed settings. Workspace names are display-only and not selectors.
func (h *Handler) resolveWorkspace(r *http.Request, workspaceID string) (*store.Workspace, settings.Workspace, error) {
	ws, err := h.Store.Workspaces().ByID(r.Context(), workspaceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, settings.Workspace{}, service.NotFoundErr("workspace not found", err)
		}
		return nil, settings.Workspace{}, service.Internal("failed to load workspace", err)
	}
	wsSet, err := settings.ParseWorkspace(ws.Settings)
	if err != nil {
		return nil, settings.Workspace{}, service.Internal("failed to parse workspace settings", err)
	}
	return ws, wsSet, nil
}

func (h *Handler) workspaceRole(r *http.Request, wsID string) (*store.Role, error) {
	members, err := h.Store.Workspaces().ListMembers(r.Context(), wsID)
	if err != nil {
		return nil, err
	}
	a := actor(r)
	for _, m := range members {
		if m.UserID == a.ID {
			role := m.Role
			return &role, nil
		}
	}
	return nil, nil
}

// handleWorkspacesList implements GET /api/v1/workspaces: an org admin
// sees every workspace; anyone else sees only the ones they're a member
// of.
func (h *Handler) handleWorkspacesList(w http.ResponseWriter, r *http.Request) {
	a := actor(r)
	var wss []*store.Workspace
	var err error
	if a.Role == store.RoleAdmin {
		wss, err = h.Store.Workspaces().ListAll(r.Context())
	} else {
		wss, err = h.Store.Workspaces().ListForUser(r.Context(), a.ID)
	}
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to list workspaces", err))
		return
	}
	dtos := make([]map[string]any, 0, len(wss))
	for _, ws := range wss {
		wsSet, err := settings.ParseWorkspace(ws.Settings)
		if err != nil {
			continue
		}
		dtos = append(dtos, workspaceDTO(ws, wsSet))
	}
	writeJSON(w, http.StatusOK, map[string]any{"workspaces": dtos})
}

// handleWorkspaceCreate implements POST /api/v1/workspaces
// the workspace's initial admin via Store.CreateWorkspace.
func (h *Handler) handleWorkspaceCreate(w http.ResponseWriter, r *http.Request) {
	a := actor(r)

	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be JSON: {\"name\"}")
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "invalid_name", "workspace name is required")
		return
	}

	if !authz.CanCreateWorkspace(authz.Actor{UserID: a.ID, Role: a.Role}) {
		writeError(w, http.StatusForbidden, "forbidden", "workspace creation is not permitted")
		return
	}

	ws := &store.Workspace{Name: body.Name, Settings: settings.DefaultWorkspace().JSON(), SettingsGen: 1}
	if err := h.Store.CreateWorkspace(r.Context(), ws, a.ID); err != nil {
		h.writeServiceError(w, service.Internal("failed to create workspace", err))
		return
	}
	_ = auth.Audit(r.Context(), h.Store, a.ID, "workspace.create", "workspace:"+ws.ID, map[string]any{"name": body.Name})
	writeJSON(w, http.StatusCreated, workspaceDTO(ws, settings.DefaultWorkspace()))
}

// handleWorkspaceGet implements GET /api/v1/workspaces/{workspaceID}: visible
// to an org admin or any member; 404 otherwise (to avoid leaking
// existence to a non-member).
func (h *Handler) handleWorkspaceGet(w http.ResponseWriter, r *http.Request, workspaceID string) {
	ws, wsSet, err := h.resolveWorkspace(r, workspaceID)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	role, err := h.workspaceRole(r, ws.ID)
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to load membership", err))
		return
	}
	a := actor(r)
	if a.Role != store.RoleAdmin && role == nil {
		h.writeServiceError(w, service.NotFoundErr("workspace not found", nil))
		return
	}

	members, err := h.Store.Workspaces().ListMembers(r.Context(), ws.ID)
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to list members", err))
		return
	}
	memberDTOs := make([]map[string]any, 0, len(members))
	for _, m := range members {
		memberDTOs = append(memberDTOs, map[string]any{"user_id": m.UserID, "role": string(m.Role)})
	}

	body := workspaceDTO(ws, wsSet)
	body["members"] = memberDTOs
	writeJSON(w, http.StatusOK, body)
}

// handleWorkspacePatch implements PATCH /api/v1/workspaces/{workspaceID}:
// settings update, gated by CanManageWorkspace (org admin or this
// workspace's own admin).
func (h *Handler) handleWorkspacePatch(w http.ResponseWriter, r *http.Request, workspaceID string) {
	ws, wsSet, err := h.resolveWorkspace(r, workspaceID)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	if err := h.requireManageWorkspace(w, r, ws.ID); err != nil {
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&wsSet); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be a JSON object matching the workspace settings schema")
		return
	}
	ws.Settings = wsSet.JSON()
	ws.SettingsGen++
	if err := h.Store.Workspaces().Update(r.Context(), ws); err != nil {
		h.writeServiceError(w, service.Internal("failed to update workspace", err))
		return
	}
	_ = auth.Audit(r.Context(), h.Store, actor(r).ID, "workspace.settings.update", "workspace:"+ws.ID, wsSet)
	writeJSON(w, http.StatusOK, workspaceDTO(ws, wsSet))
}

// handleWorkspaceDelete implements DELETE /api/v1/workspaces/{workspaceID}.
// Refuses (409) to delete a workspace that still owns functions, so a
// function's owner reference is never left dangling.
func (h *Handler) handleWorkspaceDelete(w http.ResponseWriter, r *http.Request, workspaceID string) {
	ws, _, err := h.resolveWorkspace(r, workspaceID)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	if err := h.requireManageWorkspace(w, r, ws.ID); err != nil {
		return
	}

	fns, err := h.Store.Functions().ListByOwner(r.Context(), store.OwnerTypeWorkspace, ws.ID)
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to check workspace functions", err))
		return
	}
	if len(fns) > 0 {
		writeError(w, http.StatusConflict, "workspace_not_empty", "delete or move every function owned by this workspace first")
		return
	}

	if err := h.Store.Workspaces().Delete(r.Context(), ws.ID); err != nil {
		h.writeServiceError(w, service.Internal("failed to delete workspace", err))
		return
	}
	_ = auth.Audit(r.Context(), h.Store, actor(r).ID, "workspace.delete", "workspace:"+ws.ID, map[string]any{"name": ws.Name})
	w.WriteHeader(http.StatusNoContent)
}

// requireManageWorkspace writes the appropriate error response and
// returns non-nil if the actor may not manage wsID.
func (h *Handler) requireManageWorkspace(w http.ResponseWriter, r *http.Request, wsID string) error {
	role, err := h.workspaceRole(r, wsID)
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to load membership", err))
		return err
	}
	a := actor(r)
	if !authz.CanManageWorkspace(authz.Actor{UserID: a.ID, Role: a.Role}, role) {
		e := service.Forbidden("not permitted to manage this workspace")
		h.writeServiceError(w, e)
		return e
	}
	return nil
}

func (h *Handler) handleWorkspaceMemberGet(w http.ResponseWriter, r *http.Request, workspaceID, userID string) {
	ws, _, err := h.resolveWorkspace(r, workspaceID)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	role, err := h.workspaceRole(r, ws.ID)
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to load membership", err))
		return
	}
	a := actor(r)
	if a.Role != store.RoleAdmin && role == nil {
		h.writeServiceError(w, service.NotFoundErr("workspace not found", nil))
		return
	}
	members, err := h.Store.Workspaces().ListMembers(r.Context(), ws.ID)
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to list members", err))
		return
	}
	for _, m := range members {
		if m.UserID == userID {
			writeJSON(w, http.StatusOK, map[string]any{"user_id": m.UserID, "role": string(m.Role)})
			return
		}
	}
	h.writeServiceError(w, service.NotFoundErr("member not found", nil))
}

// handleWorkspaceMemberPut implements PUT
// /api/v1/workspaces/{workspaceID}/members/{userID}: add-or-update a member's
// role, gated by CanManageWorkspace, with the same last-admin guard as
// org users (a workspace with zero admins is just as much a lockout).
func (h *Handler) handleWorkspaceMemberPut(w http.ResponseWriter, r *http.Request, workspaceID, userID string) {
	ws, _, err := h.resolveWorkspace(r, workspaceID)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	if err := h.requireManageWorkspace(w, r, ws.ID); err != nil {
		return
	}

	var body struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be JSON: {\"role\": \"admin\"|\"member\"}")
		return
	}
	role := store.Role(body.Role)
	if role != store.RoleAdmin && role != store.RoleMember {
		writeError(w, http.StatusBadRequest, "invalid_role", "role must be \"admin\" or \"member\"")
		return
	}

	if _, err := h.Store.Users().ByID(r.Context(), userID); err != nil {
		h.writeServiceError(w, service.NotFoundErr("user not found", err))
		return
	}

	members, err := h.Store.Workspaces().ListMembers(r.Context(), ws.ID)
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to list members", err))
		return
	}
	var existing *store.WorkspaceMember
	for _, m := range members {
		if m.UserID == userID {
			existing = m
			break
		}
	}

	if existing != nil && existing.Role == store.RoleAdmin && role != store.RoleAdmin {
		if countOtherWSAdmins(members, userID) == 0 {
			writeError(w, http.StatusConflict, "last_admin", "cannot demote the workspace's last admin")
			return
		}
	}

	if existing == nil {
		if err := h.Store.Workspaces().AddMember(r.Context(), &store.WorkspaceMember{WorkspaceID: ws.ID, UserID: userID, Role: role}); err != nil {
			h.writeServiceError(w, service.Internal("failed to add member", err))
			return
		}
	} else {
		if err := h.Store.Workspaces().UpdateMemberRole(r.Context(), ws.ID, userID, role); err != nil {
			h.writeServiceError(w, service.Internal("failed to update member role", err))
			return
		}
	}
	_ = auth.Audit(r.Context(), h.Store, actor(r).ID, "workspace.member.update", "workspace:"+ws.ID,
		map[string]any{"user_id": userID, "role": string(role)})
	writeJSON(w, http.StatusOK, map[string]any{"user_id": userID, "role": string(role)})
}

// handleWorkspaceMemberDelete implements DELETE
// /api/v1/workspaces/{workspaceID}/members/{userID}.
func (h *Handler) handleWorkspaceMemberDelete(w http.ResponseWriter, r *http.Request, workspaceID, userID string) {
	ws, _, err := h.resolveWorkspace(r, workspaceID)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	if err := h.requireManageWorkspace(w, r, ws.ID); err != nil {
		return
	}

	members, err := h.Store.Workspaces().ListMembers(r.Context(), ws.ID)
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to list members", err))
		return
	}
	for _, m := range members {
		if m.UserID == userID && m.Role == store.RoleAdmin && countOtherWSAdmins(members, userID) == 0 {
			writeError(w, http.StatusConflict, "last_admin", "cannot remove the workspace's last admin")
			return
		}
	}

	if err := h.Store.Workspaces().RemoveMember(r.Context(), ws.ID, userID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.writeServiceError(w, service.NotFoundErr("member not found", err))
			return
		}
		h.writeServiceError(w, service.Internal("failed to remove member", err))
		return
	}
	_ = auth.Audit(r.Context(), h.Store, actor(r).ID, "workspace.member.remove", "workspace:"+ws.ID, map[string]any{"user_id": userID})
	w.WriteHeader(http.StatusNoContent)
}

func countOtherWSAdmins(members []*store.WorkspaceMember, excludeUserID string) int {
	n := 0
	for _, m := range members {
		if m.UserID != excludeUserID && m.Role == store.RoleAdmin {
			n++
		}
	}
	return n
}
