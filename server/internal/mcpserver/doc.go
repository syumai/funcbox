// Package mcpserver implements funcbox's Model Context Protocol (MCP)
// server: the Streamable HTTP endpoint at /mcp (see mcpserver.go), backed
// by the official github.com/modelcontextprotocol/go-sdk. It authenticates
// every request with funcbox's own "Authorization: Bearer fbxa_..." access
// token -- never a session cookie -- before handing the request to the
// SDK's own handler, and builds one mcp.Server per MCP session with only
// the tools the authenticated actor may call already registered (see
// (*Handler).getServer). Two authorization shapes exist across the tool
// groups: role-gated groups (users, org, audit -- tools_users.go,
// tools_org.go, tools_audit.go) are registered ONLY for an org admin, so
// tools/list itself is role-filtered for those; resource-scoped groups
// (functions, workspaces, devices -- tools_functions.go,
// tools_workspaces.go, tools_devices.go) are registered for EVERY
// authenticated actor, since their authorization depends on which
// specific function/workspace/device is addressed, not the actor's
// organization-wide role, and is re-derived per call instead. Either way,
// every handler independently re-checks its own authorization rather than
// trusting the registration gate alone -- a client that calls an unlisted
// (or resource-denied) tool by name anyway still gets a clean refusal, not
// a state change.
//
// Tool handlers are thin wrappers around the exact same use-case methods
// internal/api's REST handlers call (e.g. api.Handler.PatchUser for the
// users tool group in tools_users.go), so authorization double-checks,
// the last-admin guard, and audit logging all happen exactly once, shared
// between the two surfaces.
//
// Mounting /mcp, and gating it (together with server/internal/oauth's
// endpoints) behind the organization's mcp_enabled setting, is
// server/internal/server's job -- this package exposes Enabled as the
// shared settings-resolution helper for that gate; Handler itself only
// implements http.Handler and does not mount itself onto any router.
package mcpserver
