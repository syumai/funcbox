package api

import (
	"net/http"

	"github.com/syumai/funcbox/internal/auth"
	"github.com/syumai/funcbox/internal/service"
)

// deployMultipartMemory bounds the in-memory portion of multipart form
// parsing (small text fields stay in memory; a large "bundle" file part
// spills to a temp file). The overall request is already capped at
// service.MaxCompressedBundleBytes by the MaxBytesReader below, so this
// only tunes where that data lives while being parsed.
const deployMultipartMemory = 1 << 20 // 1 MiB

// handleDeploy implements POST /api/v1/functions (tmp/07-http-api.md
// §7.3): multipart upload, ?dry_run=true for validation only.
func (h *Handler) handleDeploy(w http.ResponseWriter, r *http.Request) {
	dryRun := r.URL.Query().Get("dry_run") == "true"

	r.Body = http.MaxBytesReader(w, r.Body, service.MaxCompressedBundleBytes)
	if err := r.ParseMultipartForm(deployMultipartMemory); err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", "request body exceeds the compressed bundle size limit or is not a valid multipart form")
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}

	file, _, err := r.FormFile("bundle")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing_bundle", `multipart field "bundle" (the tar.gz upload) is required`)
		return
	}
	defer file.Close()

	result, err := h.Deployer.Deploy(r.Context(), service.DeployParams{
		Bundle: file,
		Owner:  r.FormValue("owner"),
		Name:   r.FormValue("name"),
		Note:   r.FormValue("note"),
		DryRun: dryRun,
		Actor:  actor(r),
	})
	if err != nil {
		h.writeServiceError(w, err)
		return
	}

	status := http.StatusCreated
	if result.DryRun {
		status = http.StatusOK
	}
	if !result.DryRun {
		a := actor(r)
		_ = auth.Audit(r.Context(), h.Store, a.ID, "function.deploy",
			"function:"+result.Function.ID,
			map[string]any{"owner": r.FormValue("owner"), "name": result.Function.Name, "version_id": result.Version.ID})
	}
	writeJSON(w, status, deployResponseBody(result))
}

func deployResponseBody(result *service.DeployResult) map[string]any {
	body := map[string]any{
		"dry_run":  result.DryRun,
		"manifest": result.Manifest,
		"warnings": nonNilStrings(result.Warnings),
	}
	if result.Function != nil {
		body["function"] = functionDTO(result.Function, "")
	}
	if result.Version != nil {
		body["version"] = versionDTO(result.Version)
	}
	return body
}

// nonNilStrings turns a nil slice into an empty (non-null) one, so the
// warnings field always serializes as "[]" rather than "null".
func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
