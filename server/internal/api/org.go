package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/syumai/funcbox/server/internal/auth"
	"github.com/syumai/funcbox/server/internal/authz"
	"github.com/syumai/funcbox/server/internal/service"
	"github.com/syumai/funcbox/server/internal/settings"
	"github.com/syumai/funcbox/server/internal/store"
)

func (h *Handler) routeOrg(w http.ResponseWriter, r *http.Request, rest []string) {
	switch {
	case len(rest) == 0:
		switch r.Method {
		case http.MethodGet:
			h.handleOrgGet(w, r)
		case http.MethodPatch:
			h.handleOrgPatch(w, r)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		}

	case len(rest) == 1 && rest[0] == "login-rules":
		switch r.Method {
		case http.MethodGet:
			h.handleLoginRulesGet(w, r)
		case http.MethodPut:
			h.handleLoginRulesPut(w, r)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		}

	case len(rest) == 1 && rest[0] == "users":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		h.handleOrgUsersList(w, r)

	case len(rest) == 2 && rest[0] == "users":
		if r.Method != http.MethodPatch {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		h.handleOrgUserPatch(w, r, rest[1])

	case len(rest) == 1 && rest[0] == "audit-logs":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		h.handleAuditLogs(w, r)

	default:
		writeError(w, http.StatusNotFound, "not_found", "unknown API route")
	}
}

// requireOrgAdminActor returns a 403 service.Error if act does not hold the
// organization-wide admin role (authz.CanUpdateOrgSettings). Shared by
// requireOrgAdmin (the HTTP-facing 403-writing wrapper used by every route
// in this file) and every exported use-case method below (ListUsers,
// PatchUser) that server/internal/mcpserver's users tool group also calls
// directly -- those callers have no *http.ResponseWriter to write to, and
// must still enforce this check themselves rather than trusting that only
// an admin's session ever reaches them (an MCP tool not listed for a
// non-admin actor must still refuse a direct tools/call attempt).
func requireOrgAdminActor(act *store.User) error {
	if !authz.CanUpdateOrgSettings(authz.Actor{UserID: act.ID, Role: act.Role}) {
		return service.Forbidden("organization admin required")
	}
	return nil
}

// requireOrgAdmin writes 403 and returns false if the request's actor is
// not an org admin.
func (h *Handler) requireOrgAdmin(w http.ResponseWriter, r *http.Request) bool {
	if err := requireOrgAdminActor(actor(r)); err != nil {
		h.writeServiceError(w, err)
		return false
	}
	return true
}

func (h *Handler) loadOrgCtx(ctx context.Context) (*store.Organization, error) {
	org, err := h.Store.Organizations().Get(ctx)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, service.Internal("organization is not initialized", err)
		}
		return nil, service.Internal("failed to load organization", err)
	}
	return org, nil
}

func (h *Handler) loadOrg(r *http.Request) (*store.Organization, error) {
	return h.loadOrgCtx(r.Context())
}

// handleOrgGet implements GET /api/v1/org: any authenticated actor may
// restricts the PATCH).
func (h *Handler) handleOrgGet(w http.ResponseWriter, r *http.Request) {
	name, orgSet, gen, err := h.GetOrgSettings(r.Context())
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":         name,
		"settings":     orgSet,
		"settings_gen": gen,
	})
}

// GetOrgSettings returns the organization's name, parsed settings, and
// settings_gen -- the shared use case behind GET /api/v1/org
// (handleOrgGet above) and the MCP org tool group's get_org_settings tool
// (server/internal/mcpserver). Any authenticated actor may call this (read
// access is unrestricted; only PATCH/UpdateOrgSettings is admin-only).
func (h *Handler) GetOrgSettings(ctx context.Context) (name string, orgSet settings.Org, settingsGen int, err error) {
	org, err := h.Store.Organizations().Get(ctx)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", settings.Org{}, 0, service.Internal("organization is not initialized", err)
		}
		return "", settings.Org{}, 0, service.Internal("failed to load organization", err)
	}
	orgSet, err = settings.ParseOrg(org.Settings)
	if err != nil {
		return "", settings.Org{}, 0, service.Internal("failed to parse organization settings", err)
	}
	return org.Name, orgSet, org.SettingsGen, nil
}

// UpdateOrgSettings JSON-merges patch over the organization's current
// settings (any field patch omits keeps its current value) and bumps
// settings_gen so the effective-policy cache (internal/invoke) invalidates
// -- the shared use case behind PATCH /api/v1/org (handleOrgPatch below)
// and the MCP org tool group's update_org_settings tool. Admin-only
// (requireOrgAdminActor); the open-mode toggle guard (refusing to enable
// open mode while any workspace still exists) applies identically to both
// callers. Disabling mcp_enabled through THIS method (including via MCP,
// self-disabling the very connection that called it) is deliberately
// allowed -- server/internal/server's router re-checks mcp_enabled fresh
// on EVERY request to /mcp (mcpserver.Enabled), not just at session
// creation, so the disabling call's own response still reaches the client
// (mcp_enabled was still true when that request arrived), but the very
// next request to /mcp -- even one from the same already-open MCP
// session -- 404s exactly like any other caller's would. There is no
// session-scoped grace period.
func (h *Handler) UpdateOrgSettings(ctx context.Context, act *store.User, patch []byte) (name string, orgSet settings.Org, settingsGen int, openModeJustEnabled bool, err error) {
	if err := requireOrgAdminActor(act); err != nil {
		return "", settings.Org{}, 0, false, err
	}
	org, err := h.Store.Organizations().Get(ctx)
	if err != nil {
		return "", settings.Org{}, 0, false, service.Internal("failed to load organization", err)
	}
	cur, err := settings.ParseOrg(org.Settings)
	if err != nil {
		return "", settings.Org{}, 0, false, service.Internal("failed to parse organization settings", err)
	}
	// Captured before patch is decoded over cur, purely to detect an
	// open_mode false->true TRANSITION below -- see the
	// workspace-existence guard's comment.
	wasOpenMode := cur.OpenMode

	if err := json.Unmarshal(patch, &cur); err != nil {
		return "", settings.Org{}, 0, false, service.BadRequest("invalid_body", "request body must be a JSON object matching the organization settings schema", err)
	}
	if !settings.IsLanguage(cur.Language) {
		return "", settings.Org{}, 0, false, service.BadRequest("invalid_language", "language must be \"en\" or \"ja\"", nil)
	}

	// The toggle guard: open mode disables the workspace feature outright
	// (routeWorkspaces 404s, deploy rejects
	// visibility: workspace and workspace-scoped owners -- see
	// internal/service.Deployer.Deploy), so turning it ON while a
	// workspace still exists would strand that workspace in a state
	// nothing can manage anymore. Only checked on the false->true
	// transition -- disabling open mode is always allowed, and once
	// enabled no workspace can be CREATED to violate the invariant again
	// (routeWorkspaces already 404s), so re-checking on every subsequent
	// PATCH would be redundant.
	openModeJustEnabled = cur.OpenMode && !wasOpenMode
	if openModeJustEnabled {
		wss, err := h.Store.Workspaces().ListAll(ctx)
		if err != nil {
			return "", settings.Org{}, 0, false, service.Internal("failed to check existing workspaces", err)
		}
		if len(wss) > 0 {
			return "", settings.Org{}, 0, false, &service.Error{
				Status: http.StatusConflict, Code: "workspaces_exist",
				Message: "cannot enable open mode while workspaces still exist; delete every workspace first",
			}
		}
	}

	org.Settings = cur.JSON()
	org.SettingsGen++
	if err := h.Store.Organizations().Update(ctx, org); err != nil {
		return "", settings.Org{}, 0, false, service.Internal("failed to update organization settings", err)
	}
	_ = auth.Audit(ctx, h.Store, act.ID, "org.settings.update", "org", cur)
	return org.Name, cur, org.SettingsGen, openModeJustEnabled, nil
}

// handleOrgPatch implements PATCH /api/v1/org: admin-only, JSON-merges the
// request body over the current settings (any field the body omits keeps
// its current value), and bumps settings_gen so the effective-policy cache
// (internal/invoke) invalidates.
func (h *Handler) handleOrgPatch(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "failed to read request body")
		return
	}
	name, orgSet, gen, openModeJustEnabled, err := h.UpdateOrgSettings(r.Context(), actor(r), body)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	resp := map[string]any{
		"name":         name,
		"settings":     orgSet,
		"settings_gen": gen,
	}
	if openModeJustEnabled {
		// Enabling open_mode on a normal, already-configured organization
		// must NOT silently rewrite its
		// existing login rules -- they remain exactly what this admin
		// already set up (e.g. a domain allowlist) and keep applying
		// unchanged. This flag lets the dashboard surface that as an
		// explicit notice rather than the caller having to guess it from
		// settings alone.
		resp["open_mode_just_enabled"] = true
	}
	writeJSON(w, http.StatusOK, resp)
}

// openModeEnabled reports the organization's current open_mode setting,
// failing closed (false) if the organization or its settings can't be
// loaded.
func (h *Handler) openModeEnabled(ctx context.Context) (bool, error) {
	org, err := h.Store.Organizations().Get(ctx)
	if err != nil {
		return false, err
	}
	orgSet, err := settings.ParseOrg(org.Settings)
	if err != nil {
		return false, err
	}
	return orgSet.OpenMode, nil
}

// loginRuleDTO is the JSON shape of a store.LoginRule, both for responses
// and (via loginRuleInput) for the PUT request body.
// LoginRuleInput is the JSON shape ReplaceLoginRules accepts for one rule,
// exported so server/internal/mcpserver's org tool group can build its
// input from an MCP tool call's arguments without reimplementing this
// shape.
type LoginRuleInput struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Action string `json:"action"`
}

// LoginRuleDTO is exported for the same reason as UserDTO: so
// server/internal/mcpserver's org tools shape their output identically to
// the REST API's, without reimplementing this mapping.
func LoginRuleDTO(r *store.LoginRule) map[string]any { return loginRuleDTO(r) }

func loginRuleDTO(r *store.LoginRule) map[string]any {
	return map[string]any{
		"id":     r.ID,
		"ord":    r.Ord,
		"type":   string(r.RuleType),
		"value":  r.Value,
		"action": string(r.Action),
	}
}

// ListLoginRules returns the organization's login rules in evaluation
// order -- the shared use case behind GET /api/v1/org/login-rules
// (handleLoginRulesGet below) and the MCP org tool group's
// list_login_rules tool. Like its REST counterpart, this performs no
// authorization check of its own (login rules are not secret); callers
// that need one (the MCP org tool group only registers for org admins in
// the first place, but re-checks anyway per this package's convention)
// are responsible for it.
func (h *Handler) ListLoginRules(ctx context.Context) ([]*store.LoginRule, error) {
	rules, err := h.Store.Organizations().ListLoginRules(ctx)
	if err != nil {
		return nil, service.Internal("failed to list login rules", err)
	}
	return rules, nil
}

func (h *Handler) handleLoginRulesGet(w http.ResponseWriter, r *http.Request) {
	rules, err := h.ListLoginRules(r.Context())
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	dtos := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		dtos = append(dtos, loginRuleDTO(rule))
	}
	writeJSON(w, http.StatusOK, map[string]any{"login_rules": dtos})
}

// ReplaceLoginRules validates and atomically replaces the organization's
// entire login-rule set (order = slice order), admin-only
// (requireOrgAdminActor) -- the shared use case behind PUT
// /api/v1/org/login-rules (handleLoginRulesPut below) and the MCP org tool
// group's replace_login_rules tool. As a safety net beyond the literal
// spec (see internal/auth's bootstrap login-rule seeding for the matching
// concern at signup time), the new rule set is rejected if it would deny
// the requesting admin's own email -- login rules are re-evaluated on
// every session validation (internal/auth §5.4), so an admin could
// otherwise lock themselves out with no way back in short of direct DB
// surgery. Returns the new rule set (ListLoginRules) on success.
func (h *Handler) ReplaceLoginRules(ctx context.Context, act *store.User, in []LoginRuleInput) ([]*store.LoginRule, error) {
	if err := requireOrgAdminActor(act); err != nil {
		return nil, err
	}

	rules := make([]*store.LoginRule, 0, len(in))
	for i, item := range in {
		ruleType := store.LoginRuleType(item.Type)
		action := store.LoginRuleAction(item.Action)
		switch ruleType {
		case store.LoginRuleTypeEmailDomain, store.LoginRuleTypeEmailExact, store.LoginRuleTypeEmailGlob, store.LoginRuleTypeDefault:
		default:
			return nil, service.BadRequest("invalid_rule_type", "login rule type must be one of email_domain, email_exact, email_glob, default", nil)
		}
		if action != store.LoginRuleActionAllow && action != store.LoginRuleActionDeny {
			return nil, service.BadRequest("invalid_rule_action", "login rule action must be \"allow\" or \"deny\"", nil)
		}
		rules = append(rules, &store.LoginRule{Ord: i, RuleType: ruleType, Value: item.Value, Action: action})
	}

	if !auth.EvaluateLoginRules(rules, act.Email) {
		return nil, service.BadRequest("self_lockout",
			"this rule set would deny your own account's email; adjust it so you remain permitted to sign in", nil)
	}

	if err := h.Store.Organizations().ReplaceLoginRules(ctx, rules); err != nil {
		return nil, service.Internal("failed to replace login rules", err)
	}
	_ = auth.Audit(ctx, h.Store, act.ID, "org.login_rules.update", "org", in)
	return h.ListLoginRules(ctx)
}

// handleLoginRulesPut implements PUT /api/v1/org/login-rules: admin-only,
// "一覧・一括置換（順序ごと）").
func (h *Handler) handleLoginRulesPut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		LoginRules []LoginRuleInput `json:"login_rules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be {\"login_rules\": [...]}")
		return
	}
	rules, err := h.ReplaceLoginRules(r.Context(), actor(r), body.LoginRules)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	dtos := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		dtos = append(dtos, loginRuleDTO(rule))
	}
	writeJSON(w, http.StatusOK, map[string]any{"login_rules": dtos})
}

// ListUsers returns every user in the organization, admin-only -- the
// shared use case behind GET /api/v1/org/users (handleOrgUsersList below)
// and the MCP users tool group's list_users tool
// (server/internal/mcpserver), so both surfaces enforce the exact same
// authorization check with no duplicated logic.
func (h *Handler) ListUsers(ctx context.Context, act *store.User) ([]*store.User, error) {
	if err := requireOrgAdminActor(act); err != nil {
		return nil, err
	}
	users, err := h.Store.Users().List(ctx)
	if err != nil {
		return nil, service.Internal("failed to list users", err)
	}
	return users, nil
}

// handleOrgUsersList implements GET /api/v1/org/users (admin-only).
func (h *Handler) handleOrgUsersList(w http.ResponseWriter, r *http.Request) {
	users, err := h.ListUsers(r.Context(), actor(r))
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	dtos := make([]map[string]any, 0, len(users))
	for _, u := range users {
		dtos = append(dtos, userDTO(u))
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": dtos})
}

// UserDTO is exported so server/internal/mcpserver's users tools can shape
// their own JSON output identically to the REST API's, without
// reimplementing this mapping.
func UserDTO(u *store.User) map[string]any { return userDTO(u) }

func userDTO(u *store.User) map[string]any {
	return map[string]any{
		"id":         u.ID,
		"email":      u.Email,
		"name":       u.Name,
		"role":       string(u.Role),
		"status":     string(u.Status),
		"created_at": u.CreatedAt,
	}
}

// PatchUser applies a role and/or status change to the user identified by
// id, admin-only, with the last-admin guard (409) below: a change that
// would leave the organization with zero active admins is rejected. role
// and/or status may be nil to mean "leave this field unchanged". It writes
// the same org.user.update audit entry (with the derived approval_action
// label) either way -- the shared use case behind PATCH
// /api/v1/org/users/{id} (handleOrgUserPatch below) and every MCP users
// tool that mutates a user (approve_user/reject_user/set_user_role/
// set_user_status in server/internal/mcpserver), so the authorization
// check, the last-admin guard, and the audit trail are never duplicated
// across those call sites.
func (h *Handler) PatchUser(ctx context.Context, act *store.User, id string, role, status *string) (updated *store.User, approvalAction string, err error) {
	if err := requireOrgAdminActor(act); err != nil {
		return nil, "", err
	}

	target, err := h.Store.Users().ByID(ctx, id)
	if err != nil {
		return nil, "", service.NotFoundErr("user not found", err)
	}
	// Captured before any mutation below, purely so the audit entry can
	// record what changed -- e.g. previous_status=pending, status=active is
	// how an approval is distinguished from an ordinary status edit (an
	// admin toggling an already-active user to disabled and back wouldn't
	// otherwise look any different in the log).
	prevRole, prevStatus := target.Role, target.Status

	newRole := target.Role
	if role != nil {
		newRole = store.Role(*role)
		if newRole != store.RoleAdmin && newRole != store.RoleWorkspaceManager && newRole != store.RoleMember {
			return nil, "", service.BadRequest("invalid_role", "role must be \"admin\", \"workspace_manager\", or \"member\"", nil)
		}
	}
	newStatus := target.Status
	if status != nil {
		newStatus = store.UserStatus(*status)
		switch newStatus {
		case store.UserStatusActive, store.UserStatusPending, store.UserStatusDisabled:
		default:
			return nil, "", service.BadRequest("invalid_status", "status must be \"active\", \"pending\", or \"disabled\"", nil)
		}
	}

	// Last-admin guard: if this change would leave the org with zero
	// active admins, reject with 409.
	demoting := target.Role == store.RoleAdmin && (newRole != store.RoleAdmin || (newStatus != store.UserStatusActive && target.Status == store.UserStatusActive))
	if demoting {
		remaining, err := countOtherActiveAdmins(ctx, h.Store, target.ID)
		if err != nil {
			return nil, "", service.Internal("failed to check remaining admins", err)
		}
		if remaining == 0 {
			return nil, "", service.ConflictErr("cannot remove the organization's last active admin", nil)
		}
	}

	target.Role = newRole
	target.Status = newStatus
	if err := h.Store.Users().Update(ctx, target); err != nil {
		return nil, "", service.Internal("failed to update user", err)
	}
	// approval_action is a convenience label so an approval/rejection
	// stands out in the audit log without the reader having to compare
	// previous_status themselves; it's derived, not a separate code path.
	if prevStatus == store.UserStatusPending && target.Status != prevStatus {
		if target.Status == store.UserStatusActive {
			approvalAction = "approved"
		} else if target.Status == store.UserStatusDisabled {
			approvalAction = "rejected"
		}
	}
	_ = auth.Audit(ctx, h.Store, act.ID, "org.user.update", "user:"+target.ID,
		map[string]any{
			"role": string(target.Role), "status": string(target.Status),
			"previous_role": string(prevRole), "previous_status": string(prevStatus),
			"approval_action": approvalAction,
		})
	return target, approvalAction, nil
}

// handleOrgUserPatch implements PATCH /api/v1/org/users/{id}: role and/or
// status change, admin-only, with a last-admin guard (409) per
func (h *Handler) handleOrgUserPatch(w http.ResponseWriter, r *http.Request, id string) {
	if !h.requireOrgAdmin(w, r) {
		return
	}
	var body struct {
		Role   *string `json:"role"`
		Status *string `json:"status"`
		// Disabled is deprecated compatibility for the pre-generalization
		// {"disabled": bool} shape (the users.disabled -> users.status
		// migration): consulted only when
		// Status is absent, true maps to "disabled" and false to "active".
		Disabled *bool `json:"disabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be JSON")
		return
	}

	status := body.Status
	if status == nil && body.Disabled != nil {
		s := string(store.UserStatusActive)
		if *body.Disabled {
			s = string(store.UserStatusDisabled)
		}
		status = &s
	}

	target, _, err := h.PatchUser(r.Context(), actor(r), id, body.Role, status)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, userDTO(target))
}

// countOtherActiveAdmins returns the number of active admin users other
// than excludeID.
func countOtherActiveAdmins(ctx context.Context, st store.Store, excludeID string) (int, error) {
	users, err := st.Users().List(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, u := range users {
		if u.ID != excludeID && u.Role == store.RoleAdmin && u.Status == store.UserStatusActive {
			n++
		}
	}
	return n, nil
}

// parsePositiveInt parses s as a positive base-10 integer.
func parsePositiveInt(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid positive int %q", s)
	}
	return n, nil
}

// ListAuditLogs returns at most limit audit entries newest-first, starting
// strictly before cursor if non-empty (the same keyset pagination
// AuditRepo.List documents), admin-only (requireOrgAdminActor) -- the
// shared use case behind GET /api/v1/org/audit-logs (handleAuditLogs
// below) and the MCP audit tool group's list_audit_logs tool. The second
// return value is the next page's cursor ("" once exhausted).
func (h *Handler) ListAuditLogs(ctx context.Context, act *store.User, cursor string, limit int) ([]*store.AuditLog, string, error) {
	if err := requireOrgAdminActor(act); err != nil {
		return nil, "", err
	}
	logs, err := h.Store.Audit().List(ctx, cursor, limit)
	if err != nil {
		return nil, "", service.Internal("failed to list audit logs", err)
	}
	next := ""
	if len(logs) > 0 {
		next = logs[len(logs)-1].ID
	}
	return logs, next, nil
}

// AuditLogDTO is exported for the same reason as UserDTO: so
// server/internal/mcpserver's audit tools shape their output identically
// to the REST API's, without reimplementing this mapping.
func AuditLogDTO(l *store.AuditLog) map[string]any {
	var detail any
	_ = json.Unmarshal(l.Detail, &detail)
	return map[string]any{
		"id":         l.ID,
		"actor_id":   l.ActorID,
		"action":     l.Action,
		"target":     l.Target,
		"detail":     detail,
		"created_at": l.CreatedAt,
	}
}

// handleAuditLogs implements GET /api/v1/org/audit-logs
// (?cursor=&limit=), admin-only.
func (h *Handler) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	cursor := r.URL.Query().Get("cursor")
	limit := 0
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := parsePositiveInt(s); err == nil {
			limit = n
		}
	}
	logs, next, err := h.ListAuditLogs(r.Context(), actor(r), cursor, limit)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	dtos := make([]map[string]any, 0, len(logs))
	for _, l := range logs {
		dtos = append(dtos, AuditLogDTO(l))
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit_logs": dtos, "next_cursor": next})
}
