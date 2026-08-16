// tools_users.go implements the MCP users tool group: list_users,
// approve_user, reject_user, set_user_role, and set_user_status. Every
// tool is admin-only, and every handler is a thin wrapper around
// api.Handler's ListUsers/PatchUser -- the exact same use-case methods
// internal/api's REST handlers under /api/v1/org/users call -- so
// authorization, the last-admin guard, and audit logging (internal/auth's
// Audit, "org.user.update") all happen exactly once, shared with the REST
// surface.
package mcpserver

import (
	"context"
	"errors"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/syumai/funcbox/server/internal/authz"
	"github.com/syumai/funcbox/server/internal/service"
	"github.com/syumai/funcbox/server/internal/store"
)

// registerUsersTools adds the users tool group to server, but ONLY when u
// holds the organization-wide admin role (authz.CanUpdateOrgSettings):
// every one of these tools is admin-only, identically to their REST
// counterparts under /api/v1/org/users (see internal/api/org.go). A
// non-admin's session therefore never sees any of them in tools/list --
// and even if a client calls one by name anyway (bypassing tools/list),
// every handler below independently re-checks u's authorization via the
// api.Handler method it calls (ListUsers/PatchUser, both of which call
// internal/api's own requireOrgAdminActor), so the call is refused with no
// state change rather than silently trusting this registration gate alone.
func (h *Handler) registerUsersTools(server *mcp.Server, u *store.User) {
	if !authz.CanUpdateOrgSettings(authz.Actor{UserID: u.ID, Role: u.Role}) {
		return
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_users",
		Description: "List every user in the organization, optionally filtered by status.",
	}, h.listUsersHandler(u))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "approve_user",
		Description: "Approve a pending user, setting their status to active.",
	}, h.approveUserHandler(u))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "reject_user",
		Description: "Reject a pending user, setting their status to disabled.",
	}, h.rejectUserHandler(u))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "set_user_role",
		Description: `Change a user's organization-wide role. Rejected with a "last admin" error if it would leave the organization with no active admin.`,
	}, h.setUserRoleHandler(u))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "set_user_status",
		Description: `Change a user's status. Rejected with a "last admin" error if disabling the organization's last active admin.`,
	}, h.setUserStatusHandler(u))
}

// userResult is the users tool group's common output shape for a single
// user, mirroring internal/api's userDTO (id/email/name/role/status/
// created_at) so an MCP client sees the same fields the REST API's
// GET/PATCH /api/v1/org/users responses do.
type userResult struct {
	ID        string `json:"id" jsonschema:"the user's internal ID (not the public User ID used in function URLs)"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Role      string `json:"role" jsonschema:"admin, workspace_manager, or member"`
	Status    string `json:"status" jsonschema:"active, pending, or disabled"`
	CreatedAt string `json:"created_at" jsonschema:"RFC 3339 timestamp"`
}

func toUserResult(u *store.User) userResult {
	return userResult{
		ID:        u.ID,
		Email:     u.Email,
		Name:      u.Name,
		Role:      string(u.Role),
		Status:    string(u.Status),
		CreatedAt: u.CreatedAt.UTC().Format(time.RFC3339),
	}
}

// listUsersIn is list_users' input.
type listUsersIn struct {
	Status string `json:"status,omitempty" jsonschema:"optional filter: active, pending, or disabled; omit to list every user"`
}

// listUsersOut is list_users' output.
type listUsersOut struct {
	Users []userResult `json:"users"`
}

func (h *Handler) listUsersHandler(u *store.User) mcp.ToolHandlerFor[listUsersIn, listUsersOut] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in listUsersIn) (*mcp.CallToolResult, listUsersOut, error) {
		if in.Status != "" && !validUserStatus(in.Status) {
			return nil, listUsersOut{}, errors.New(`status must be "active", "pending", or "disabled"`)
		}
		users, err := h.api.ListUsers(ctx, u)
		if err != nil {
			return nil, listUsersOut{}, toolError(err)
		}
		out := listUsersOut{Users: make([]userResult, 0, len(users))}
		for _, usr := range users {
			if in.Status != "" && string(usr.Status) != in.Status {
				continue
			}
			out.Users = append(out.Users, toUserResult(usr))
		}
		return nil, out, nil
	}
}

// userIDIn is the input shape shared by approve_user and reject_user,
// which each pin one specific status transition and take no other
// argument.
type userIDIn struct {
	UserID string `json:"user_id" jsonschema:"the target user's internal ID, as returned by list_users"`
}

func (h *Handler) approveUserHandler(u *store.User) mcp.ToolHandlerFor[userIDIn, userResult] {
	status := string(store.UserStatusActive)
	return func(ctx context.Context, _ *mcp.CallToolRequest, in userIDIn) (*mcp.CallToolResult, userResult, error) {
		if in.UserID == "" {
			return nil, userResult{}, errors.New("user_id is required")
		}
		updated, _, err := h.api.PatchUser(ctx, u, in.UserID, nil, &status)
		if err != nil {
			return nil, userResult{}, toolError(err)
		}
		return nil, toUserResult(updated), nil
	}
}

func (h *Handler) rejectUserHandler(u *store.User) mcp.ToolHandlerFor[userIDIn, userResult] {
	status := string(store.UserStatusDisabled)
	return func(ctx context.Context, _ *mcp.CallToolRequest, in userIDIn) (*mcp.CallToolResult, userResult, error) {
		if in.UserID == "" {
			return nil, userResult{}, errors.New("user_id is required")
		}
		updated, _, err := h.api.PatchUser(ctx, u, in.UserID, nil, &status)
		if err != nil {
			return nil, userResult{}, toolError(err)
		}
		return nil, toUserResult(updated), nil
	}
}

// setUserRoleIn is set_user_role's input.
type setUserRoleIn struct {
	UserID string `json:"user_id" jsonschema:"the target user's internal ID, as returned by list_users"`
	Role   string `json:"role" jsonschema:"admin, workspace_manager, or member"`
}

func (h *Handler) setUserRoleHandler(u *store.User) mcp.ToolHandlerFor[setUserRoleIn, userResult] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in setUserRoleIn) (*mcp.CallToolResult, userResult, error) {
		if in.UserID == "" || in.Role == "" {
			return nil, userResult{}, errors.New("user_id and role are both required")
		}
		updated, _, err := h.api.PatchUser(ctx, u, in.UserID, &in.Role, nil)
		if err != nil {
			return nil, userResult{}, toolError(err)
		}
		return nil, toUserResult(updated), nil
	}
}

// setUserStatusIn is set_user_status's input.
type setUserStatusIn struct {
	UserID string `json:"user_id" jsonschema:"the target user's internal ID, as returned by list_users"`
	Status string `json:"status" jsonschema:"active, pending, or disabled"`
}

func (h *Handler) setUserStatusHandler(u *store.User) mcp.ToolHandlerFor[setUserStatusIn, userResult] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in setUserStatusIn) (*mcp.CallToolResult, userResult, error) {
		if in.UserID == "" || in.Status == "" {
			return nil, userResult{}, errors.New("user_id and status are both required")
		}
		updated, _, err := h.api.PatchUser(ctx, u, in.UserID, nil, &in.Status)
		if err != nil {
			return nil, userResult{}, toolError(err)
		}
		return nil, toUserResult(updated), nil
	}
}

func validUserStatus(s string) bool {
	switch store.UserStatus(s) {
	case store.UserStatusActive, store.UserStatusPending, store.UserStatusDisabled:
		return true
	default:
		return false
	}
}

// toolError converts an error from internal/api's shared use-case methods
// into a client-safe error for an MCP tool result: only the service.Error's
// public Message is exposed (never its wrapped Err, which may carry
// backend-internal detail) -- mirrors internal/api's own writeServiceError,
// which likewise never puts Err in a response body. Returning a plain error
// from a ToolHandlerFor is automatically packed into the CallToolResult as
// an IsError result (not a protocol-level error), per the go-sdk's own
// ToolHandlerFor doc comment -- exactly the "clean MCP error, no state
// change" a non-admin's direct tools/call attempt must get.
func toolError(err error) error {
	if svcErr, ok := service.AsError(err); ok {
		return errors.New(svcErr.Message)
	}
	return errors.New("internal error")
}
