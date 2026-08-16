// tools_org.go implements the MCP org tool group: get_org_settings,
// update_org_settings, list_login_rules, and replace_login_rules. Every
// tool is admin-only (like tools_users.go's users group), registered ONLY
// for an actor holding the organization-wide admin role -- see
// registerOrgTools.
package mcpserver

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/syumai/funcbox/server/internal/api"
	"github.com/syumai/funcbox/server/internal/authz"
	"github.com/syumai/funcbox/server/internal/store"
)

// registerOrgTools adds the org tool group to server, but ONLY when u
// holds the organization-wide admin role -- identical to
// registerUsersTools' own gate (see its doc comment for why every handler
// below ALSO independently re-checks authorization via the api.Handler
// method it calls, rather than trusting this registration gate alone).
func (h *Handler) registerOrgTools(server *mcp.Server, u *store.User) {
	if !authz.CanUpdateOrgSettings(authz.Actor{UserID: u.ID, Role: u.Role}) {
		return
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_org_settings",
		Description: "Get the organization's name and settings.",
	}, h.getOrgSettingsHandler())

	mcp.AddTool(server, &mcp.Tool{
		Name: "update_org_settings",
		Description: "Partially update the organization's settings: only the fields you include are changed, everything else keeps its current value. " +
			"Disabling mcp_enabled through this tool IS allowed, including self-disabling the very connection you're using -- " +
			"this call's own response still reaches you, but every /mcp request after it (including your own next one) gets a 404, " +
			"with no grace period for the current session.",
	}, h.updateOrgSettingsHandler())

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_login_rules",
		Description: "List the organization's login rules, in evaluation order.",
	}, h.listLoginRulesHandler())

	mcp.AddTool(server, &mcp.Tool{
		Name: "replace_login_rules",
		Description: "Replace the organization's ENTIRE login-rule set (order = input order). " +
			"Rejected if the new rule set would deny your own account's email, to prevent a self-lockout.",
	}, h.replaceLoginRulesHandler())
}

// getOrgSettingsOut is get_org_settings' output.
type getOrgSettingsOut struct {
	Name        string `json:"name"`
	Settings    any    `json:"settings"`
	SettingsGen int    `json:"settings_gen"`
}

func (h *Handler) getOrgSettingsHandler() mcp.ToolHandlerFor[struct{}, getOrgSettingsOut] {
	return func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, getOrgSettingsOut, error) {
		u, err := h.requireActor(ctx, req)
		if err != nil {
			return nil, getOrgSettingsOut{}, err
		}
		if !authz.CanUpdateOrgSettings(authz.Actor{UserID: u.ID, Role: u.Role}) {
			return nil, getOrgSettingsOut{}, errors.New("organization admin required")
		}
		name, orgSet, gen, err := h.api.GetOrgSettings(ctx)
		if err != nil {
			return nil, getOrgSettingsOut{}, toolError(err)
		}
		return nil, getOrgSettingsOut{Name: name, Settings: orgSet, SettingsGen: gen}, nil
	}
}

// updateOrgSettingsIn is update_org_settings' input: an arbitrary JSON
// object, merged over the current settings server-side
// (internal/api.Handler.UpdateOrgSettings) -- deliberately not a typed
// struct, so a caller can send only the fields it wants to change (e.g.
// {"mcp_enabled": false}) without needing to know or round-trip every
// other settings field.
type updateOrgSettingsIn struct {
	Settings map[string]any `json:"settings" jsonschema:"a JSON object with only the settings fields you want to change, e.g. {\"mcp_enabled\": false}"`
}

// updateOrgSettingsOut is update_org_settings' output.
type updateOrgSettingsOut struct {
	Name                string `json:"name"`
	Settings            any    `json:"settings"`
	SettingsGen         int    `json:"settings_gen"`
	OpenModeJustEnabled bool   `json:"open_mode_just_enabled,omitempty"`
}

func (h *Handler) updateOrgSettingsHandler() mcp.ToolHandlerFor[updateOrgSettingsIn, updateOrgSettingsOut] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in updateOrgSettingsIn) (*mcp.CallToolResult, updateOrgSettingsOut, error) {
		u, err := h.requireActor(ctx, req)
		if err != nil {
			return nil, updateOrgSettingsOut{}, err
		}
		if len(in.Settings) == 0 {
			return nil, updateOrgSettingsOut{}, errors.New("settings is required (a JSON object with the fields to change)")
		}
		patch, err := json.Marshal(in.Settings)
		if err != nil {
			return nil, updateOrgSettingsOut{}, errors.New("failed to encode settings")
		}
		name, orgSet, gen, openModeJustEnabled, err := h.api.UpdateOrgSettings(ctx, u, patch)
		if err != nil {
			return nil, updateOrgSettingsOut{}, toolError(err)
		}
		return nil, updateOrgSettingsOut{Name: name, Settings: orgSet, SettingsGen: gen, OpenModeJustEnabled: openModeJustEnabled}, nil
	}
}

// listLoginRulesOut is list_login_rules' output.
type listLoginRulesOut struct {
	LoginRules []map[string]any `json:"login_rules"`
}

func (h *Handler) listLoginRulesHandler() mcp.ToolHandlerFor[struct{}, listLoginRulesOut] {
	return func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, listLoginRulesOut, error) {
		u, err := h.requireActor(ctx, req)
		if err != nil {
			return nil, listLoginRulesOut{}, err
		}
		if !authz.CanUpdateOrgSettings(authz.Actor{UserID: u.ID, Role: u.Role}) {
			return nil, listLoginRulesOut{}, errors.New("organization admin required")
		}
		rules, err := h.api.ListLoginRules(ctx)
		if err != nil {
			return nil, listLoginRulesOut{}, toolError(err)
		}
		dtos := make([]map[string]any, 0, len(rules))
		for _, r := range rules {
			dtos = append(dtos, api.LoginRuleDTO(r))
		}
		return nil, listLoginRulesOut{LoginRules: dtos}, nil
	}
}

// replaceLoginRulesIn is replace_login_rules' input.
type replaceLoginRulesIn struct {
	LoginRules []api.LoginRuleInput `json:"login_rules" jsonschema:"the complete new rule set, in evaluation order"`
}

func (h *Handler) replaceLoginRulesHandler() mcp.ToolHandlerFor[replaceLoginRulesIn, listLoginRulesOut] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in replaceLoginRulesIn) (*mcp.CallToolResult, listLoginRulesOut, error) {
		u, err := h.requireActor(ctx, req)
		if err != nil {
			return nil, listLoginRulesOut{}, err
		}
		rules, err := h.api.ReplaceLoginRules(ctx, u, in.LoginRules)
		if err != nil {
			return nil, listLoginRulesOut{}, toolError(err)
		}
		dtos := make([]map[string]any, 0, len(rules))
		for _, r := range rules {
			dtos = append(dtos, api.LoginRuleDTO(r))
		}
		return nil, listLoginRulesOut{LoginRules: dtos}, nil
	}
}
