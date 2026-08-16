// tools_workspaces.go implements the MCP workspaces tool group:
// list_workspaces, get_workspace (membership-gated), and
// add_workspace_member/remove_workspace_member/set_workspace_member_role
// (workspace-admin-gated). Like the functions group (see
// tools_functions.go's doc comment), authorization here is per-RESOURCE
// (a specific workspace's membership/admin role), not per organization-wide
// role, so every tool is registered for every authenticated actor and
// re-derives its own authorization per call via the exact same
// internal/api.Handler methods (ListWorkspaces/GetWorkspace/
// SetWorkspaceMember/RemoveWorkspaceMember) the REST API under
// /api/v1/workspaces uses.
package mcpserver

import (
	"context"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/syumai/funcbox/server/internal/store"
)

// registerWorkspacesTools adds the workspaces tool group for every
// authenticated, non-pending actor. When the organization has open mode
// enabled, the workspace feature is disabled outright (routeWorkspaces
// 404s the REST surface the same way) -- every method these tools call
// resolves to an empty list or a not-found/forbidden error in that case,
// so no separate open-mode gate is needed here.
func (h *Handler) registerWorkspacesTools(server *mcp.Server, u *store.User) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_workspaces",
		Description: "List workspaces you belong to (or, for an org admin, every workspace).",
	}, h.listWorkspacesHandler())

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_workspace",
		Description: "Get a workspace's settings and member list. Visible to an org admin or any member.",
	}, h.getWorkspaceHandler())

	mcp.AddTool(server, &mcp.Tool{
		Name:        "add_workspace_member",
		Description: "Add a user to a workspace with the given role. Requires being that workspace's admin (or an org admin).",
	}, h.setWorkspaceMemberHandler())

	mcp.AddTool(server, &mcp.Tool{
		Name:        "set_workspace_member_role",
		Description: `Change an existing workspace member's role ("admin" or "member"). Rejected if it would leave the workspace with no admin.`,
	}, h.setWorkspaceMemberHandler())

	mcp.AddTool(server, &mcp.Tool{
		Name:        "remove_workspace_member",
		Description: "Remove a member from a workspace. Rejected if it would leave the workspace with no admin.",
	}, h.removeWorkspaceMemberHandler())
}

func workspaceDTO(ws *store.Workspace, members []*store.WorkspaceMember) map[string]any {
	memberDTOs := make([]map[string]any, 0, len(members))
	for _, m := range members {
		memberDTOs = append(memberDTOs, map[string]any{"user_id": m.UserID, "role": string(m.Role)})
	}
	return map[string]any{
		"id":           ws.ID,
		"name":         ws.Name,
		"settings_gen": ws.SettingsGen,
		"created_at":   ws.CreatedAt,
		"members":      memberDTOs,
	}
}

// listWorkspacesOut is list_workspaces' output.
type listWorkspacesOut struct {
	Workspaces []map[string]any `json:"workspaces"`
}

func (h *Handler) listWorkspacesHandler() mcp.ToolHandlerFor[struct{}, listWorkspacesOut] {
	return func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, listWorkspacesOut, error) {
		u, err := h.requireActor(ctx, req)
		if err != nil {
			return nil, listWorkspacesOut{}, err
		}
		wss, err := h.api.ListWorkspaces(ctx, u)
		if err != nil {
			return nil, listWorkspacesOut{}, toolError(err)
		}
		dtos := make([]map[string]any, 0, len(wss))
		for _, ws := range wss {
			dtos = append(dtos, map[string]any{
				"id": ws.ID, "name": ws.Name, "settings_gen": ws.SettingsGen, "created_at": ws.CreatedAt,
			})
		}
		return nil, listWorkspacesOut{Workspaces: dtos}, nil
	}
}

// workspaceIDIn is the input shape shared by every tool below that
// addresses one specific workspace.
type workspaceIDIn struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"the workspace's immutable ID, as returned by list_workspaces"`
}

func (h *Handler) getWorkspaceHandler() mcp.ToolHandlerFor[workspaceIDIn, map[string]any] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in workspaceIDIn) (*mcp.CallToolResult, map[string]any, error) {
		u, err := h.requireActor(ctx, req)
		if err != nil {
			return nil, nil, err
		}
		if in.WorkspaceID == "" {
			return nil, nil, errors.New("workspace_id is required")
		}
		ws, _, members, err := h.api.GetWorkspace(ctx, u, in.WorkspaceID)
		if err != nil {
			return nil, nil, toolError(err)
		}
		return nil, workspaceDTO(ws, members), nil
	}
}

// setWorkspaceMemberIn is the input shared by add_workspace_member and
// set_workspace_member_role -- both are the same upsert-by-role use case
// (internal/api.Handler.SetWorkspaceMember), just under two different
// tool names/descriptions for discoverability (an agent adding a NEW
// member and one changing an EXISTING member's role are different intents
// even though the underlying REST call is identical).
type setWorkspaceMemberIn struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"the workspace's immutable ID, as returned by list_workspaces"`
	UserID      string `json:"user_id" jsonschema:"the target user's internal ID"`
	Role        string `json:"role" jsonschema:"admin or member"`
}

func (h *Handler) setWorkspaceMemberHandler() mcp.ToolHandlerFor[setWorkspaceMemberIn, map[string]any] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in setWorkspaceMemberIn) (*mcp.CallToolResult, map[string]any, error) {
		u, err := h.requireActor(ctx, req)
		if err != nil {
			return nil, nil, err
		}
		if in.WorkspaceID == "" || in.UserID == "" || in.Role == "" {
			return nil, nil, errors.New("workspace_id, user_id, and role are all required")
		}
		if err := h.api.SetWorkspaceMember(ctx, u, in.WorkspaceID, in.UserID, store.Role(in.Role)); err != nil {
			return nil, nil, toolError(err)
		}
		return nil, map[string]any{"user_id": in.UserID, "role": in.Role}, nil
	}
}

// removeWorkspaceMemberIn is remove_workspace_member's input.
type removeWorkspaceMemberIn struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"the workspace's immutable ID, as returned by list_workspaces"`
	UserID      string `json:"user_id" jsonschema:"the target user's internal ID"`
}

// removeWorkspaceMemberOut is remove_workspace_member's output.
type removeWorkspaceMemberOut struct {
	Removed bool `json:"removed"`
}

func (h *Handler) removeWorkspaceMemberHandler() mcp.ToolHandlerFor[removeWorkspaceMemberIn, removeWorkspaceMemberOut] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in removeWorkspaceMemberIn) (*mcp.CallToolResult, removeWorkspaceMemberOut, error) {
		u, err := h.requireActor(ctx, req)
		if err != nil {
			return nil, removeWorkspaceMemberOut{}, err
		}
		if in.WorkspaceID == "" || in.UserID == "" {
			return nil, removeWorkspaceMemberOut{}, errors.New("workspace_id and user_id are both required")
		}
		if err := h.api.RemoveWorkspaceMember(ctx, u, in.WorkspaceID, in.UserID); err != nil {
			return nil, removeWorkspaceMemberOut{}, toolError(err)
		}
		return nil, removeWorkspaceMemberOut{Removed: true}, nil
	}
}
