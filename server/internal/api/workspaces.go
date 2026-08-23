package api

import (
	"context"
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
func (h *Handler) resolveWorkspace(ctx context.Context, workspaceID string) (*store.Workspace, settings.Workspace, error) {
	ws, err := h.Store.Workspaces().ByID(ctx, workspaceID)
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

// workspaceRoleFor returns userID's role within wsID, or nil if userID is
// not a member.
func (h *Handler) workspaceRoleFor(ctx context.Context, wsID, userID string) (*store.Role, error) {
	members, err := h.Store.Workspaces().ListMembers(ctx, wsID)
	if err != nil {
		return nil, err
	}
	for _, m := range members {
		if m.UserID == userID {
			role := m.Role
			return &role, nil
		}
	}
	return nil, nil
}

func (h *Handler) workspaceRole(r *http.Request, wsID string) (*store.Role, error) {
	return h.workspaceRoleFor(r.Context(), wsID, actor(r).ID)
}

// ListWorkspaces returns every workspace act may see: an org admin sees
// every workspace; anyone else sees only the ones they're a member of --
// the shared use case behind GET /api/v1/workspaces (handleWorkspacesList
// below) and the MCP workspaces tool group's list_workspaces tool.
func (h *Handler) ListWorkspaces(ctx context.Context, act *store.User) ([]*store.Workspace, error) {
	if act.Role == store.RoleAdmin {
		wss, err := h.Store.Workspaces().ListAll(ctx)
		if err != nil {
			return nil, service.Internal("failed to list workspaces", err)
		}
		return wss, nil
	}
	wss, err := h.Store.Workspaces().ListForUser(ctx, act.ID)
	if err != nil {
		return nil, service.Internal("failed to list workspaces", err)
	}
	return wss, nil
}

// handleWorkspacesList implements GET /api/v1/workspaces: an org admin
// sees every workspace; anyone else sees only the ones they're a member
// of.
func (h *Handler) handleWorkspacesList(w http.ResponseWriter, r *http.Request) {
	wss, err := h.ListWorkspaces(r.Context(), actor(r))
	if err != nil {
		h.writeServiceError(w, err)
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

// CreateWorkspace creates a new workspace named name and adds act as its
// initial admin member (via Store.CreateWorkspace's atomic creator-becomes-
// admin behavior), gated by authz.CanCreateWorkspace -- the shared use case
// behind POST /api/v1/workspaces (handleWorkspaceCreate below) and the MCP
// workspaces tool group's create_workspace tool.
//
// Unlike this file's other shared use cases (ListWorkspaces, GetWorkspace,
// SetWorkspaceMember, RemoveWorkspaceMember), which rely on the invariant
// that zero workspaces exist while open mode is on (enabling open mode is
// refused while any workspace still exists, and once on, routeWorkspaces
// 404s the whole REST surface so none can be created through it -- see
// settings.Org.OpenMode's doc comment) to naturally resolve to an empty or
// not-found result without a dedicated check, THIS method actively creates
// state and so must check open mode itself: it is reachable from MCP,
// which has no equivalent route-dispatch gate, and a workspace created
// through it while open mode is on would violate that invariant.
func (h *Handler) CreateWorkspace(ctx context.Context, act *store.User, name string) (*store.Workspace, error) {
	openMode, err := h.openModeEnabled(ctx)
	if err != nil {
		return nil, service.Internal("failed to load organization settings", err)
	}
	if openMode {
		return nil, service.NotFoundErr("workspace creation is not available while the organization is in open mode", nil)
	}
	if name == "" {
		return nil, service.BadRequest("invalid_name", "workspace name is required", nil)
	}
	if !authz.CanCreateWorkspace(authz.Actor{UserID: act.ID, Role: act.Role}) {
		return nil, service.Forbidden("workspace creation is not permitted")
	}

	ws := &store.Workspace{Name: name, Settings: settings.DefaultWorkspace().JSON(), SettingsGen: 1}
	if err := h.Store.CreateWorkspace(ctx, ws, act.ID); err != nil {
		return nil, service.Internal("failed to create workspace", err)
	}
	_ = auth.Audit(ctx, h.Store, act.ID, "workspace.create", "workspace:"+ws.ID, map[string]any{"name": name})
	return ws, nil
}

// handleWorkspaceCreate implements POST /api/v1/workspaces: creates the
// workspace and adds the caller as its initial admin via CreateWorkspace.
func (h *Handler) handleWorkspaceCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be JSON: {\"name\"}")
		return
	}
	ws, err := h.CreateWorkspace(r.Context(), actor(r), body.Name)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, workspaceDTO(ws, settings.DefaultWorkspace()))
}

// GetWorkspace looks up workspaceID and returns it, its parsed settings,
// and its member list, gated to an org admin or any member (a
// service.NotFoundErr otherwise, to avoid leaking existence to a
// non-member) -- the shared use case behind GET
// /api/v1/workspaces/{workspaceID} (handleWorkspaceGet below) and the MCP
// workspaces tool group's get_workspace tool.
func (h *Handler) GetWorkspace(ctx context.Context, act *store.User, workspaceID string) (*store.Workspace, settings.Workspace, []*store.WorkspaceMember, error) {
	ws, wsSet, err := h.resolveWorkspace(ctx, workspaceID)
	if err != nil {
		return nil, settings.Workspace{}, nil, err
	}
	role, err := h.workspaceRoleFor(ctx, ws.ID, act.ID)
	if err != nil {
		return nil, settings.Workspace{}, nil, service.Internal("failed to load membership", err)
	}
	if act.Role != store.RoleAdmin && role == nil {
		return nil, settings.Workspace{}, nil, service.NotFoundErr("workspace not found", nil)
	}
	members, err := h.Store.Workspaces().ListMembers(ctx, ws.ID)
	if err != nil {
		return nil, settings.Workspace{}, nil, service.Internal("failed to list members", err)
	}
	return ws, wsSet, members, nil
}

// handleWorkspaceGet implements GET /api/v1/workspaces/{workspaceID}: visible
// to an org admin or any member; 404 otherwise (to avoid leaking
// existence to a non-member).
func (h *Handler) handleWorkspaceGet(w http.ResponseWriter, r *http.Request, workspaceID string) {
	ws, wsSet, members, err := h.GetWorkspace(r.Context(), actor(r), workspaceID)
	if err != nil {
		h.writeServiceError(w, err)
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
	ws, wsSet, err := h.resolveWorkspace(r.Context(), workspaceID)
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
	ws, _, err := h.resolveWorkspace(r.Context(), workspaceID)
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

// requireManageWorkspaceActor returns a service.Error if act may not
// manage wsID (CanManageWorkspace), shared by requireManageWorkspace (the
// HTTP-facing wrapper) and SetWorkspaceMember/RemoveWorkspaceMember below,
// mirroring requireOrgAdminActor's split in org.go.
func (h *Handler) requireManageWorkspaceActor(ctx context.Context, act *store.User, wsID string) error {
	role, err := h.workspaceRoleFor(ctx, wsID, act.ID)
	if err != nil {
		return service.Internal("failed to load membership", err)
	}
	if !authz.CanManageWorkspace(authz.Actor{UserID: act.ID, Role: act.Role}, role) {
		return service.Forbidden("not permitted to manage this workspace")
	}
	return nil
}

// requireManageWorkspace writes the appropriate error response and
// returns non-nil if the actor may not manage wsID.
func (h *Handler) requireManageWorkspace(w http.ResponseWriter, r *http.Request, wsID string) error {
	if err := h.requireManageWorkspaceActor(r.Context(), actor(r), wsID); err != nil {
		h.writeServiceError(w, err)
		return err
	}
	return nil
}

func (h *Handler) handleWorkspaceMemberGet(w http.ResponseWriter, r *http.Request, workspaceID, userID string) {
	_, _, members, err := h.GetWorkspace(r.Context(), actor(r), workspaceID)
	if err != nil {
		h.writeServiceError(w, err)
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

// SetWorkspaceMember adds userID to workspaceID with the given role
// (creating the membership if it didn't already exist) or updates their
// existing role, gated by requireManageWorkspaceActor, with the same
// last-admin guard as org users (a workspace with zero admins is just as
// much a lockout) -- the shared use case behind PUT
// /api/v1/workspaces/{workspaceID}/members/{userID} (handleWorkspaceMemberPut
// below) and the MCP workspaces tool group's add_workspace_member and
// set_workspace_member_role tools.
func (h *Handler) SetWorkspaceMember(ctx context.Context, act *store.User, workspaceID, userID string, role store.Role) error {
	ws, _, err := h.resolveWorkspace(ctx, workspaceID)
	if err != nil {
		return err
	}
	if err := h.requireManageWorkspaceActor(ctx, act, ws.ID); err != nil {
		return err
	}
	if role != store.RoleAdmin && role != store.RoleMember {
		return service.BadRequest("invalid_role", "role must be \"admin\" or \"member\"", nil)
	}
	if _, err := h.Store.Users().ByID(ctx, userID); err != nil {
		return service.NotFoundErr("user not found", err)
	}

	members, err := h.Store.Workspaces().ListMembers(ctx, ws.ID)
	if err != nil {
		return service.Internal("failed to list members", err)
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
			return &service.Error{Status: http.StatusConflict, Code: "last_admin", Message: "cannot demote the workspace's last admin"}
		}
	}

	if existing == nil {
		if err := h.Store.Workspaces().AddMember(ctx, &store.WorkspaceMember{WorkspaceID: ws.ID, UserID: userID, Role: role}); err != nil {
			return service.Internal("failed to add member", err)
		}
	} else {
		if err := h.Store.Workspaces().UpdateMemberRole(ctx, ws.ID, userID, role); err != nil {
			return service.Internal("failed to update member role", err)
		}
	}
	_ = auth.Audit(ctx, h.Store, act.ID, "workspace.member.update", "workspace:"+ws.ID,
		map[string]any{"user_id": userID, "role": string(role)})
	return nil
}

// handleWorkspaceMemberPut implements PUT
// /api/v1/workspaces/{workspaceID}/members/{userID}: add-or-update a member's
// role, gated by CanManageWorkspace, with the same last-admin guard as
// org users (a workspace with zero admins is just as much a lockout).
func (h *Handler) handleWorkspaceMemberPut(w http.ResponseWriter, r *http.Request, workspaceID, userID string) {
	var body struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be JSON: {\"role\": \"admin\"|\"member\"}")
		return
	}
	if err := h.SetWorkspaceMember(r.Context(), actor(r), workspaceID, userID, store.Role(body.Role)); err != nil {
		h.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user_id": userID, "role": body.Role})
}

// RemoveWorkspaceMember removes userID from workspaceID, gated by
// requireManageWorkspaceActor, refusing (409) to remove the workspace's
// last admin -- the shared use case behind DELETE
// /api/v1/workspaces/{workspaceID}/members/{userID}
// (handleWorkspaceMemberDelete below) and the MCP workspaces tool group's
// remove_workspace_member tool.
func (h *Handler) RemoveWorkspaceMember(ctx context.Context, act *store.User, workspaceID, userID string) error {
	ws, _, err := h.resolveWorkspace(ctx, workspaceID)
	if err != nil {
		return err
	}
	if err := h.requireManageWorkspaceActor(ctx, act, ws.ID); err != nil {
		return err
	}

	members, err := h.Store.Workspaces().ListMembers(ctx, ws.ID)
	if err != nil {
		return service.Internal("failed to list members", err)
	}
	for _, m := range members {
		if m.UserID == userID && m.Role == store.RoleAdmin && countOtherWSAdmins(members, userID) == 0 {
			return &service.Error{Status: http.StatusConflict, Code: "last_admin", Message: "cannot remove the workspace's last admin"}
		}
	}

	if err := h.Store.Workspaces().RemoveMember(ctx, ws.ID, userID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return service.NotFoundErr("member not found", err)
		}
		return service.Internal("failed to remove member", err)
	}
	_ = auth.Audit(ctx, h.Store, act.ID, "workspace.member.remove", "workspace:"+ws.ID, map[string]any{"user_id": userID})
	return nil
}

// handleWorkspaceMemberDelete implements DELETE
// /api/v1/workspaces/{workspaceID}/members/{userID}.
func (h *Handler) handleWorkspaceMemberDelete(w http.ResponseWriter, r *http.Request, workspaceID, userID string) {
	if err := h.RemoveWorkspaceMember(r.Context(), actor(r), workspaceID, userID); err != nil {
		h.writeServiceError(w, err)
		return
	}
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
