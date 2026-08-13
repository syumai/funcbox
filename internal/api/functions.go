package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/syumai/funcbox/internal/manifest"
	"github.com/syumai/funcbox/internal/store"
)

// handleList implements GET /api/v1/functions?owner=... (tmp/07-http-api.md
// §7.3). Phase 1 has no authentication (see this package's doc comment), so
// unlike the eventual "自分が見える関数の一覧", listing requires an explicit
// ?owner= filter rather than resolving visibility from a session.
func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	owner := r.URL.Query().Get("owner")
	if owner == "" {
		writeError(w, http.StatusBadRequest, "missing_owner", "?owner= is required (Phase 1 has no session to derive a default from)")
		return
	}
	fns, err := h.Functions.ListByOwner(r.Context(), owner)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	dtos := make([]map[string]any, 0, len(fns))
	for _, fn := range fns {
		dtos = append(dtos, functionDTO(fn, owner))
	}
	writeJSON(w, http.StatusOK, map[string]any{"functions": dtos})
}

// handleGet implements GET /api/v1/functions/{owner}/{name}: detail
// including the normalized manifest and active version.
func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request, owner, name string) {
	fn, err := h.Functions.Resolve(r.Context(), owner, name)
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
	fn, err := h.Functions.Resolve(r.Context(), owner, name)
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
	fn, err := h.Functions.Resolve(r.Context(), owner, name)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	fn, err = h.Functions.Activate(r.Context(), fn, versionID)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, functionDTO(fn, owner))
}

// handleDelete implements DELETE /api/v1/functions/{owner}/{name}.
func (h *Handler) handleDelete(w http.ResponseWriter, r *http.Request, owner, name string) {
	fn, err := h.Functions.Resolve(r.Context(), owner, name)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	if err := h.Functions.Delete(r.Context(), fn); err != nil {
		h.writeServiceError(w, err)
		return
	}
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
