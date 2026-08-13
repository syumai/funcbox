package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/syumai/funcbox/internal/auth"
	"github.com/syumai/funcbox/internal/manifest"
	"github.com/syumai/funcbox/internal/service"
	"github.com/syumai/funcbox/internal/store"
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
	writeJSON(w, http.StatusOK, body)
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
