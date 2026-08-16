// tools_audit.go implements the MCP audit tool group: list_audit_logs.
// Admin-only, registered ONLY for an actor holding the organization-wide
// admin role -- identical gating to tools_org.go's org group.
package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/syumai/funcbox/server/internal/api"
	"github.com/syumai/funcbox/server/internal/authz"
	"github.com/syumai/funcbox/server/internal/store"
)

// registerAuditTools adds the audit tool group to server, but ONLY when u
// holds the organization-wide admin role -- see registerOrgTools' doc
// comment for the shared rationale (this file's own handler still
// re-checks independently, via h.api.ListAuditLogs -> requireOrgAdminActor).
func (h *Handler) registerAuditTools(server *mcp.Server, u *store.User) {
	if !authz.CanUpdateOrgSettings(authz.Actor{UserID: u.ID, Role: u.Role}) {
		return
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_audit_logs",
		Description: "List the organization's audit log, newest first, paged via next_cursor.",
	}, h.listAuditLogsHandler())
}

// listAuditLogsIn is list_audit_logs' input.
type listAuditLogsIn struct {
	Cursor string `json:"cursor,omitempty" jsonschema:"pagination cursor from a previous call's next_cursor; omit for the first (newest) page"`
	Limit  int    `json:"limit,omitempty" jsonschema:"max entries to return; server default applies if omitted or <= 0"`
	Action string `json:"action,omitempty" jsonschema:"optional client-side filter: only return entries whose action equals this exactly, e.g. \"function.deploy\""`
	UserID string `json:"user_id,omitempty" jsonschema:"optional client-side filter: only return entries whose actor_id equals this"`
}

// listAuditLogsOut is list_audit_logs' output.
type listAuditLogsOut struct {
	AuditLogs  []map[string]any `json:"audit_logs"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

// listAuditLogsHandler applies action/user_id as an in-memory filter over
// one page of AuditRepo.List results: the store's own List has no such
// filter parameter (it supports only keyset pagination by cursor), so
// filtering here is necessarily post-hoc, page-local -- a caller
// requesting a specific action/user should expect to page through
// next_cursor themselves until satisfied, exactly like grep-ing paged
// output, rather than expecting the FIRST page to be pre-filtered
// server-side.
func (h *Handler) listAuditLogsHandler() mcp.ToolHandlerFor[listAuditLogsIn, listAuditLogsOut] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in listAuditLogsIn) (*mcp.CallToolResult, listAuditLogsOut, error) {
		u, err := h.requireActor(ctx, req)
		if err != nil {
			return nil, listAuditLogsOut{}, err
		}
		logs, next, err := h.api.ListAuditLogs(ctx, u, in.Cursor, in.Limit)
		if err != nil {
			return nil, listAuditLogsOut{}, toolError(err)
		}
		dtos := make([]map[string]any, 0, len(logs))
		for _, l := range logs {
			if in.Action != "" && l.Action != in.Action {
				continue
			}
			if in.UserID != "" && l.ActorID != in.UserID {
				continue
			}
			dtos = append(dtos, api.AuditLogDTO(l))
		}
		if dtos == nil {
			dtos = []map[string]any{}
		}
		return nil, listAuditLogsOut{AuditLogs: dtos, NextCursor: next}, nil
	}
}
