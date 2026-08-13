package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// requireOrgAdmin writes 403 and returns false if the request's actor is
// not an org admin.
func (h *Handler) requireOrgAdmin(w http.ResponseWriter, r *http.Request) bool {
	a := actor(r)
	if !authz.CanUpdateOrgSettings(authz.Actor{UserID: a.ID, Role: a.Role}) {
		writeError(w, http.StatusForbidden, "forbidden", "organization admin required")
		return false
	}
	return true
}

func (h *Handler) loadOrg(r *http.Request) (*store.Organization, error) {
	org, err := h.Store.Organizations().Get(r.Context())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, service.Internal("organization is not initialized", err)
		}
		return nil, service.Internal("failed to load organization", err)
	}
	return org, nil
}

// handleOrgGet implements GET /api/v1/org: any authenticated actor may
// restricts the PATCH).
func (h *Handler) handleOrgGet(w http.ResponseWriter, r *http.Request) {
	org, err := h.loadOrg(r)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	orgSet, err := settings.ParseOrg(org.Settings)
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to parse organization settings", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":         org.Name,
		"settings":     orgSet,
		"settings_gen": org.SettingsGen,
	})
}

// handleOrgPatch implements PATCH /api/v1/org: admin-only, JSON-merges the
// request body over the current settings (any field the body omits keeps
// its current value), and bumps settings_gen so the effective-policy cache
// (internal/invoke) invalidates.
func (h *Handler) handleOrgPatch(w http.ResponseWriter, r *http.Request) {
	if !h.requireOrgAdmin(w, r) {
		return
	}
	org, err := h.loadOrg(r)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	cur, err := settings.ParseOrg(org.Settings)
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to parse organization settings", err))
		return
	}
	// Captured before the request body is decoded over cur, purely to
	// detect an open_mode false->true TRANSITION below -- see the
	// workspace-existence guard's comment.
	wasOpenMode := cur.OpenMode

	if err := json.NewDecoder(r.Body).Decode(&cur); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be a JSON object matching the organization settings schema")
		return
	}
	if !settings.IsLanguage(cur.Language) {
		writeError(w, http.StatusBadRequest, "invalid_language", "language must be \"en\" or \"ja\"")
		return
	}

	// tmp/13-public-mode.md §13.1's toggle guard: open mode disables the
	// workspace feature outright (routeWorkspaces 404s, deploy rejects
	// visibility: workspace and workspace-scoped owners -- see
	// internal/service.Deployer.Deploy), so turning it ON while a
	// workspace still exists would strand that workspace in a state
	// nothing can manage anymore. Only checked on the false->true
	// transition -- disabling open mode is always allowed, and once
	// enabled no workspace can be CREATED to violate the invariant again
	// (routeWorkspaces already 404s), so re-checking on every subsequent
	// PATCH would be redundant.
	openModeJustEnabled := cur.OpenMode && !wasOpenMode
	if openModeJustEnabled {
		wss, err := h.Store.Workspaces().ListAll(r.Context())
		if err != nil {
			h.writeServiceError(w, service.Internal("failed to check existing workspaces", err))
			return
		}
		if len(wss) > 0 {
			writeError(w, http.StatusConflict, "workspaces_exist",
				"cannot enable open mode while workspaces still exist; delete every workspace first")
			return
		}
	}

	org.Settings = cur.JSON()
	org.SettingsGen++
	if err := h.Store.Organizations().Update(r.Context(), org); err != nil {
		h.writeServiceError(w, service.Internal("failed to update organization settings", err))
		return
	}
	_ = auth.Audit(r.Context(), h.Store, actor(r).ID, "org.settings.update", "org", cur)
	resp := map[string]any{
		"name":         org.Name,
		"settings":     cur,
		"settings_gen": org.SettingsGen,
	}
	if openModeJustEnabled {
		// tmp/13-public-mode.md §13.1: enabling open_mode on a normal,
		// already-configured organization must NOT silently rewrite its
		// existing login rules -- they remain exactly what this admin
		// already set up (e.g. a domain allowlist) and keep applying
		// unchanged. This flag lets the dashboard surface that as an
		// explicit notice rather than the caller having to guess it from
		// settings alone.
		resp["open_mode_just_enabled"] = true
	}
	writeJSON(w, http.StatusOK, resp)
}

// openModeEnabled reports the organization's current open_mode setting
// (tmp/13-public-mode.md §13.1), failing closed (false) if the
// organization or its settings can't be loaded.
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
type loginRuleInput struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Action string `json:"action"`
}

func loginRuleDTO(r *store.LoginRule) map[string]any {
	return map[string]any{
		"id":     r.ID,
		"ord":    r.Ord,
		"type":   string(r.RuleType),
		"value":  r.Value,
		"action": string(r.Action),
	}
}

func (h *Handler) handleLoginRulesGet(w http.ResponseWriter, r *http.Request) {
	rules, err := h.Store.Organizations().ListLoginRules(r.Context())
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to list login rules", err))
		return
	}
	dtos := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		dtos = append(dtos, loginRuleDTO(rule))
	}
	writeJSON(w, http.StatusOK, map[string]any{"login_rules": dtos})
}

// handleLoginRulesPut implements PUT /api/v1/org/login-rules: admin-only,
// "一覧・一括置換（順序ごと）"). As a safety net beyond the literal spec
// (see internal/auth's bootstrap login-rule seeding for the matching
// concern at signup time), the new rule set is rejected if it would deny
// the requesting admin's own email -- login rules are re-evaluated on
// every session validation (internal/auth §5.4), so an admin could
// otherwise lock themselves out with no way back in short of direct DB
// surgery.
func (h *Handler) handleLoginRulesPut(w http.ResponseWriter, r *http.Request) {
	if !h.requireOrgAdmin(w, r) {
		return
	}
	var body struct {
		LoginRules []loginRuleInput `json:"login_rules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be {\"login_rules\": [...]}")
		return
	}

	rules := make([]*store.LoginRule, 0, len(body.LoginRules))
	for i, in := range body.LoginRules {
		ruleType := store.LoginRuleType(in.Type)
		action := store.LoginRuleAction(in.Action)
		switch ruleType {
		case store.LoginRuleTypeEmailDomain, store.LoginRuleTypeEmailExact, store.LoginRuleTypeEmailGlob, store.LoginRuleTypeDefault:
		default:
			writeError(w, http.StatusBadRequest, "invalid_rule_type", "login rule type must be one of email_domain, email_exact, email_glob, default")
			return
		}
		if action != store.LoginRuleActionAllow && action != store.LoginRuleActionDeny {
			writeError(w, http.StatusBadRequest, "invalid_rule_action", "login rule action must be \"allow\" or \"deny\"")
			return
		}
		rules = append(rules, &store.LoginRule{Ord: i, RuleType: ruleType, Value: in.Value, Action: action})
	}

	a := actor(r)
	if !auth.EvaluateLoginRules(rules, a.Email) {
		writeError(w, http.StatusBadRequest, "self_lockout",
			"this rule set would deny your own account's email; adjust it so you remain permitted to sign in")
		return
	}

	if err := h.Store.Organizations().ReplaceLoginRules(r.Context(), rules); err != nil {
		h.writeServiceError(w, service.Internal("failed to replace login rules", err))
		return
	}
	_ = auth.Audit(r.Context(), h.Store, a.ID, "org.login_rules.update", "org", body.LoginRules)
	h.handleLoginRulesGet(w, r)
}

// handleOrgUsersList implements GET /api/v1/org/users (admin-only).
func (h *Handler) handleOrgUsersList(w http.ResponseWriter, r *http.Request) {
	if !h.requireOrgAdmin(w, r) {
		return
	}
	users, err := h.Store.Users().List(r.Context())
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to list users", err))
		return
	}
	dtos := make([]map[string]any, 0, len(users))
	for _, u := range users {
		dtos = append(dtos, userDTO(u))
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": dtos})
}

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
		// {"disabled": bool} shape (tmp/13-public-mode.md §13.3's
		// users.disabled -> users.status migration): consulted only when
		// Status is absent, true maps to "disabled" and false to "active".
		Disabled *bool `json:"disabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be JSON")
		return
	}

	target, err := h.Store.Users().ByID(r.Context(), id)
	if err != nil {
		h.writeServiceError(w, service.NotFoundErr("user not found", err))
		return
	}
	// Captured before any mutation below, purely so the audit entry can
	// record what changed -- e.g. previous_status=pending, status=active is
	// how an approval is distinguished from an ordinary status edit (an
	// admin toggling an already-active user to disabled and back wouldn't
	// otherwise look any different in the log).
	prevRole, prevStatus := target.Role, target.Status

	newRole := target.Role
	if body.Role != nil {
		newRole = store.Role(*body.Role)
		if newRole != store.RoleAdmin && newRole != store.RoleWorkspaceManager && newRole != store.RoleMember {
			writeError(w, http.StatusBadRequest, "invalid_role", "role must be \"admin\", \"workspace_manager\", or \"member\"")
			return
		}
	}
	newStatus := target.Status
	switch {
	case body.Status != nil:
		newStatus = store.UserStatus(*body.Status)
		switch newStatus {
		case store.UserStatusActive, store.UserStatusPending, store.UserStatusDisabled:
		default:
			writeError(w, http.StatusBadRequest, "invalid_status", "status must be \"active\", \"pending\", or \"disabled\"")
			return
		}
	case body.Disabled != nil:
		if *body.Disabled {
			newStatus = store.UserStatusDisabled
		} else {
			newStatus = store.UserStatusActive
		}
	}

	// Last-admin guard: if this change would leave the org with zero
	// active admins, reject with 409.
	demoting := target.Role == store.RoleAdmin && (newRole != store.RoleAdmin || (newStatus != store.UserStatusActive && target.Status == store.UserStatusActive))
	if demoting {
		remaining, err := countOtherActiveAdmins(r.Context(), h.Store, target.ID)
		if err != nil {
			h.writeServiceError(w, service.Internal("failed to check remaining admins", err))
			return
		}
		if remaining == 0 {
			writeError(w, http.StatusConflict, "last_admin", "cannot remove the organization's last active admin")
			return
		}
	}

	target.Role = newRole
	target.Status = newStatus
	if err := h.Store.Users().Update(r.Context(), target); err != nil {
		h.writeServiceError(w, service.Internal("failed to update user", err))
		return
	}
	// approval_action is a convenience label so an approval/rejection
	// stands out in the audit log without the reader having to compare
	// previous_status themselves; it's derived, not a separate code path.
	approvalAction := ""
	if prevStatus == store.UserStatusPending && target.Status != prevStatus {
		if target.Status == store.UserStatusActive {
			approvalAction = "approved"
		} else if target.Status == store.UserStatusDisabled {
			approvalAction = "rejected"
		}
	}
	_ = auth.Audit(r.Context(), h.Store, actor(r).ID, "org.user.update", "user:"+target.ID,
		map[string]any{
			"role": string(target.Role), "status": string(target.Status),
			"previous_role": string(prevRole), "previous_status": string(prevStatus),
			"approval_action": approvalAction,
		})
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

// handleAuditLogs implements GET /api/v1/org/audit-logs
// (?cursor=&limit=), admin-only.
func (h *Handler) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	if !h.requireOrgAdmin(w, r) {
		return
	}
	cursor := r.URL.Query().Get("cursor")
	limit := 0
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := parsePositiveInt(s); err == nil {
			limit = n
		}
	}
	logs, err := h.Store.Audit().List(r.Context(), cursor, limit)
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to list audit logs", err))
		return
	}
	dtos := make([]map[string]any, 0, len(logs))
	for _, l := range logs {
		var detail any
		_ = json.Unmarshal(l.Detail, &detail)
		dtos = append(dtos, map[string]any{
			"id":         l.ID,
			"actor_id":   l.ActorID,
			"action":     l.Action,
			"target":     l.Target,
			"detail":     detail,
			"created_at": l.CreatedAt,
		})
	}
	next := ""
	if len(logs) > 0 {
		next = logs[len(logs)-1].ID
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit_logs": dtos, "next_cursor": next})
}
