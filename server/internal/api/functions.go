package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/syumai/funcbox/internal/auth"
	"github.com/syumai/funcbox/internal/service"
	"github.com/syumai/funcbox/internal/settings"
	"github.com/syumai/funcbox/internal/store"
	"github.com/syumai/funcbox/manifest"
)

// handleList implements GET /api/v1/functions[?owner=...]
// (tmp/07-http-api.md §7.3): with no ?owner=, "自分が見える関数の一覧" --
// everything the actor owns directly, plus everything owned by a
// workspace they belong to (or, for an org admin, every function in the
// organization). With ?owner=, the list is restricted to that owner,
// still gated by the same visibility rule.
func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	a := actor(r)
	ctx := r.Context()

	owner := r.URL.Query().Get("owner")
	if owner != "" {
		hnd, err := h.Store.Handles().ByHandle(ctx, owner)
		if err != nil {
			h.writeServiceError(w, service.NotFoundErr("owner not found", err))
			return
		}
		ok, err := h.Functions.CanView(ctx, a, hnd.OwnerType, hnd.OwnerID)
		if err != nil {
			h.writeServiceError(w, service.Internal("failed to check visibility", err))
			return
		}
		if !ok {
			h.writeServiceError(w, service.NotFoundErr("owner not found", nil))
			return
		}
		fns, err := h.Functions.ListByOwner(ctx, owner)
		if err != nil {
			h.writeServiceError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"functions": functionDTOs(fns, owner)})
		return
	}

	var (
		fns []*store.Function
		err error
	)
	if a.Role == store.RoleAdmin {
		fns, err = h.Functions.ListAll(ctx)
	} else {
		fns, err = h.Functions.List(ctx, a.ID)
	}
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"functions": functionDTOs(fns, "")})
}

func functionDTOs(fns []*store.Function, owner string) []map[string]any {
	dtos := make([]map[string]any, 0, len(fns))
	for _, fn := range fns {
		dtos = append(dtos, functionDTO(fn, owner))
	}
	return dtos
}

// resolveVisible looks up owner/name and checks the actor may see it,
// returning a *service.Error(404) either way if not -- unauthorized reads
// are indistinguishable from a nonexistent function, to avoid leaking
// existence to a caller who shouldn't know about it (see this package's
// doc comment).
func (h *Handler) resolveVisible(r *http.Request, owner, name string) (*store.Function, error) {
	fn, err := h.Functions.Resolve(r.Context(), owner, name)
	if err != nil {
		return nil, err
	}
	ok, err := h.Functions.CanView(r.Context(), actor(r), fn.OwnerType, fn.OwnerID)
	if err != nil {
		return nil, service.Internal("failed to check visibility", err)
	}
	if !ok {
		return nil, service.NotFoundErr("function not found", nil)
	}
	return fn, nil
}

// handleGet implements GET /api/v1/functions/{owner}/{name}: detail
// including the normalized manifest and active version.
func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request, owner, name string) {
	fn, err := h.resolveVisible(r, owner, name)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	body := functionDTO(fn, owner)

	if fn.ActiveVersionID != nil {
		v, err := h.Functions.ActiveVersion(r.Context(), fn)
		if err != nil {
			h.writeServiceError(w, err)
			return
		}
		body["active_version"] = versionDTO(v)
	}

	// fetch_policy_levels carries the organization and (if any) workspace
	// fetch-policy levels alongside the manifest one already embedded in
	// active_version.manifest.permissions.fetch, so a caller (the
	// dashboard's function detail page, tmp/09-dashboard.md §9.5's
	// "実効 fetch ポリシーを組織/WS/manifestの3段で可視化") can render all
	// three levels of policy.Effective's intersection without a
	// second round trip. This is deliberately embedded here rather than
	// exposed as GET /api/v1/workspaces/{handle} (which a function's
	// non-member viewer -- legitimately allowed to see a public/org-visible
	// function -- is not authorized to read; see resolveWorkspace's
	// membership gate).
	levels, err := h.fetchPolicyLevels(r, fn)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	body["fetch_policy_levels"] = levels

	writeJSON(w, http.StatusOK, body)
}

// fetchPolicyLevels loads the organization- and (for a workspace-owned
// function) workspace-level fetch policy for fn, in the same
// settings.FetchPolicy{mode,allow} shape PATCH /api/v1/org and PATCH
// /api/v1/workspaces/{handle} accept, so a caller can render them without
// re-deriving anything from policy.
func (h *Handler) fetchPolicyLevels(r *http.Request, fn *store.Function) (map[string]any, error) {
	org, err := h.loadOrg(r)
	if err != nil {
		return nil, err
	}
	orgSet, err := settings.ParseOrg(org.Settings)
	if err != nil {
		return nil, service.Internal("failed to parse organization settings", err)
	}

	levels := map[string]any{
		"organization": orgSet.FetchPolicy,
		"workspace":    nil,
	}
	if fn.OwnerType == store.OwnerTypeWorkspace {
		ws, err := h.Store.Workspaces().ByID(r.Context(), fn.OwnerID)
		if err != nil {
			return nil, service.Internal("failed to load workspace", err)
		}
		wsSet, err := settings.ParseWorkspace(ws.Settings)
		if err != nil {
			return nil, service.Internal("failed to parse workspace settings", err)
		}
		levels["workspace"] = wsSet.FetchPolicy
	}
	return levels, nil
}

// handleListVersions implements GET /api/v1/functions/{owner}/{name}/versions.
func (h *Handler) handleListVersions(w http.ResponseWriter, r *http.Request, owner, name string) {
	fn, err := h.resolveVisible(r, owner, name)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	limit := 0
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			limit = n
		}
	}
	versions, err := h.Functions.ListVersions(r.Context(), fn, limit)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	dtos := make([]map[string]any, 0, len(versions))
	for _, v := range versions {
		dtos = append(dtos, versionDTO(v))
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": dtos})
}

// handleLogs implements GET /api/v1/functions/{owner}/{name}/logs?since=&limit=
// (tmp/07-http-api.md §7.3): newest-first keyset pagination over the
// function's invocation_logs, gated by the same visibility check as
// handleGet ("auth: same as function read"). since, when present, is the
// InvocationLog.ID cursor returned as next_cursor by a previous call (the
// same keyset-pagination convention as GET .../versions and
// GET /api/v1/org/audit-logs); omit it for the first (newest) page.
func (h *Handler) handleLogs(w http.ResponseWriter, r *http.Request, owner, name string) {
	fn, err := h.resolveVisible(r, owner, name)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	limit := 0
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			limit = n
		}
	}
	since := r.URL.Query().Get("since")

	logs, err := h.Store.InvocationLogs().List(r.Context(), fn.ID, since, limit)
	if err != nil {
		h.writeServiceError(w, service.Internal("failed to list invocation logs", err))
		return
	}
	dtos := make([]map[string]any, 0, len(logs))
	for _, l := range logs {
		dtos = append(dtos, invocationLogDTO(l))
	}
	nextCursor := ""
	if len(logs) > 0 {
		nextCursor = logs[len(logs)-1].ID
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": dtos, "next_cursor": nextCursor})
}

// invocationLogDTO builds the JSON view of a store.InvocationLog, decoding
// its stored FetchDecisions JSON column into a structured field the same
// way versionDTO decodes Manifest/Files.
func invocationLogDTO(l *store.InvocationLog) map[string]any {
	var fetchDecisions []store.FetchDecision
	_ = json.Unmarshal(l.FetchDecisions, &fetchDecisions)
	return map[string]any{
		"id":              l.ID,
		"version_id":      l.VersionID,
		"method":          l.Method,
		"path":            l.Path,
		"status":          l.Status,
		"duration_ms":     l.DurationMS,
		"stdout":          l.Stdout,
		"stderr":          l.Stderr,
		"fetch_decisions": fetchDecisions,
		"created_at":      l.CreatedAt.Format(time.RFC3339),
	}
}

// handleActivate implements POST
// /api/v1/functions/{owner}/{name}/versions/{id}/activate (rollback).
func (h *Handler) handleActivate(w http.ResponseWriter, r *http.Request, owner, name, versionID string) {
	fn, err := h.resolveVisible(r, owner, name)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	if err := h.Functions.CanManage(r.Context(), actor(r), fn); err != nil {
		h.writeServiceError(w, err)
		return
	}
	fn, err = h.Functions.Activate(r.Context(), fn, versionID)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	_ = auth.Audit(r.Context(), h.Store, actor(r).ID, "function.rollback", "function:"+fn.ID,
		map[string]any{"version_id": versionID})
	writeJSON(w, http.StatusOK, functionDTO(fn, owner))
}

// handleDelete implements DELETE /api/v1/functions/{owner}/{name}.
func (h *Handler) handleDelete(w http.ResponseWriter, r *http.Request, owner, name string) {
	fn, err := h.resolveVisible(r, owner, name)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	if err := h.Functions.CanManage(r.Context(), actor(r), fn); err != nil {
		h.writeServiceError(w, err)
		return
	}
	if err := h.Functions.Delete(r.Context(), fn); err != nil {
		h.writeServiceError(w, err)
		return
	}
	_ = auth.Audit(r.Context(), h.Store, actor(r).ID, "function.delete", "function:"+fn.ID,
		map[string]any{"owner": owner, "name": name})
	w.WriteHeader(http.StatusNoContent)
}

// envValueBody is the request body for PUT .../env/{key}
// (tmp/07-http-api.md §7.3: "値は書き込み専用").
type envValueBody struct {
	Value string `json:"value"`
}

// handleSetEnv implements PUT /api/v1/functions/{owner}/{name}/env/{key}.
func (h *Handler) handleSetEnv(w http.ResponseWriter, r *http.Request, owner, name, key string) {
	if !manifest.IsValidEnvKey(key) {
		writeError(w, http.StatusBadRequest, "invalid_env_key", "env var key must match ^[A-Za-z_][A-Za-z0-9_]*$")
		return
	}
	fn, err := h.Functions.Resolve(r.Context(), owner, name)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	var body envValueBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be JSON: {\"value\": \"...\"}")
		return
	}
	if err := h.Functions.SetEnv(r.Context(), actor(r), fn, key, body.Value); err != nil {
		h.writeServiceError(w, err)
		return
	}
	_ = auth.Audit(r.Context(), h.Store, actor(r).ID, "function.env.set", "function:"+fn.ID, map[string]any{"key": key})
	w.WriteHeader(http.StatusNoContent)
}

// handleDeleteEnv implements DELETE /api/v1/functions/{owner}/{name}/env/{key}.
func (h *Handler) handleDeleteEnv(w http.ResponseWriter, r *http.Request, owner, name, key string) {
	fn, err := h.Functions.Resolve(r.Context(), owner, name)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	if err := h.Functions.DeleteEnv(r.Context(), actor(r), fn, key); err != nil {
		h.writeServiceError(w, err)
		return
	}
	_ = auth.Audit(r.Context(), h.Store, actor(r).ID, "function.env.delete", "function:"+fn.ID, map[string]any{"key": key})
	w.WriteHeader(http.StatusNoContent)
}

// functionDTO builds the JSON view of a store.Function. owner is the
// caller-known handle string when available (the URL already named it, or
// the list was filtered by it); if empty, functionDTO leaves "owner" out
// rather than doing an extra store round trip per item.
func functionDTO(fn *store.Function, owner string) map[string]any {
	body := map[string]any{
		"id":          fn.ID,
		"owner_type":  string(fn.OwnerType),
		"name":        fn.Name,
		"description": fn.Description,
		"created_at":  fn.CreatedAt,
		"updated_at":  fn.UpdatedAt,
	}
	if owner != "" {
		body["owner"] = owner
	}
	if fn.ActiveVersionID != nil {
		body["active_version_id"] = *fn.ActiveVersionID
	}
	return body
}

// versionDTO builds the JSON view of a store.FunctionVersion, decoding its
// stored Manifest/Files JSON columns into structured fields.
func versionDTO(v *store.FunctionVersion) map[string]any {
	var nm manifest.Normalized
	_ = json.Unmarshal(v.Manifest, &nm)
	var files []store.BundleFile
	_ = json.Unmarshal(v.Files, &files)

	return map[string]any{
		"id":            v.ID,
		"main_path":     v.MainPath,
		"bundle_hash":   v.BundleHash,
		"bundle_size":   v.BundleSize,
		"unpacked_size": v.UnpackedSize,
		"files":         files,
		"manifest":      nm,
		"note":          v.Note,
		"created_at":    v.CreatedAt.Format(time.RFC3339),
	}
}
