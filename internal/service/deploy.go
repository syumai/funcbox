package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/syumai/funcbox/internal/blob"
	"github.com/syumai/funcbox/internal/bundle"
	"github.com/syumai/funcbox/internal/manifest"
	"github.com/syumai/funcbox/internal/runtime"
	"github.com/syumai/funcbox/internal/store"
)

// MaxCompressedBundleBytes is the request-body limit applied to an upload
// before it ever reaches bundle.Unpack (tmp/02-architecture.md: "圧縮サイズ
// 上限 5MB"). The HTTP layer is expected to wrap the request body in
// http.MaxBytesReader(w, r.Body, MaxCompressedBundleBytes) before parsing
// the multipart form.
const MaxCompressedBundleBytes = 5 << 20

// BundleBlobKey returns the content-addressed blob.Store key for a
// canonical bundle's sha256 hex digest, e.g.
// "bundles/sha256/<hex>.tar.gz" (tmp/02-architecture.md). Exported so the
// invoke path can recompute the same key from a stored FunctionVersion's
// BundleHash without duplicating the format.
func BundleBlobKey(sha256Hex string) string {
	return "bundles/sha256/" + sha256Hex + ".tar.gz"
}

// Deployer implements the deploy use case (tmp/02-architecture.md "関数デ
// プロイ"): unpack, validate, canonicalize, store, and activate.
type Deployer struct {
	Store store.Store
	Blob  blob.Store

	// Runtime is invalidated for a function's previous active version after
	// a successful (non-dry-run) deploy, so the next invocation picks up the
	// new version instead of a pool warmed from stale bundle bytes. May be
	// nil (e.g. a dry-run-only caller), in which case invalidation is
	// skipped.
	Runtime *runtime.Manager
}

// DeployParams is the input to Deploy, mirroring the multipart form fields
// of POST /api/v1/functions (tmp/07-http-api.md §7.3).
type DeployParams struct {
	// Bundle is the raw tar.gz upload. The caller is responsible for
	// bounding its size (e.g. http.MaxBytesReader) before Deploy is called;
	// Deploy itself only enforces the post-decompression limit via
	// bundle.Unpack.
	Bundle io.Reader
	// Owner is the deploying owner's handle. Required.
	Owner string
	// Name is the function name, used only when the manifest doesn't
	// declare one itself (manifest name wins on conflict; see tmp/04).
	Name string
	Note string
	// DryRun stops Deploy before any write; see Deploy's doc comment.
	DryRun bool

	// CreatedBy is the store.User.ID to record as the version's author.
	// Phase 1 has no authentication (see Deployer's package doc), so
	// callers currently leave this empty; Phase 2 will populate it from the
	// authenticated session/token.
	CreatedBy string
}

// DeployResult is what Deploy returns: the normalized manifest and any
// warnings are always populated (even for a dry run); Function and Version
// are nil for a dry run, since nothing was written.
type DeployResult struct {
	DryRun   bool
	Function *store.Function
	Version  *store.FunctionVersion
	Manifest *manifest.Normalized
	Warnings []string
}

// Deploy runs the full deploy flow (tmp/02-architecture.md):
//
//  1. bundle.Unpack the upload (guarded streaming extraction; typed errors
//     map to 4xx/413 via mapBundleErr).
//  2. manifest.Parse, reconcile Name with params.Name (manifest wins if
//     set), then manifest.Validate.
//  3. manifest.ResolveMain against the unpacked files.
//  4. If compat.nodejs is set, reject any "node:*" import
//     (runtime.DetectNodeCoreImports) — cfworkers.Pool has no hook to
//     install node core modules yet (tmp/03-runtime.md 3.5).
//  5. Build warnings, bundle.Pack a canonical tar.gz, and sha256 it.
//
// If params.DryRun is set, Deploy returns here: DeployResult carries the
// normalized manifest and warnings but Function/Version are nil, and
// nothing has been written to the store or blob backend.
//
// Otherwise Deploy continues:
//
//  6. Resolve params.Owner to a store owner, auto-creating a user + handle
//     if the handle doesn't exist yet (see resolveOwner's doc comment for
//     why — this is a Phase 1 stand-in for real authentication).
//  7. blob.Put the canonical bundle (idempotent; a re-upload of identical
//     content is a no-op write).
//  8. Create the Function row if this is the owner's first deploy of this
//     name, or reuse the existing one.
//  9. CreateVersion + Store.ActivateVersion (atomic rollback point).
//  10. Invalidate the function's previous active version's pool, if any.
func (d *Deployer) Deploy(ctx context.Context, p DeployParams) (*DeployResult, error) {
	if p.Owner == "" {
		return nil, BadRequest("missing_owner", "owner is required", nil)
	}
	if err := manifest.ValidateHandle(p.Owner); err != nil {
		return nil, mapManifestErr(err)
	}

	files, err := bundle.Unpack(p.Bundle)
	if err != nil {
		return nil, mapBundleErr(err)
	}
	var unpackedSize int64
	for _, data := range files {
		unpackedSize += int64(len(data))
	}

	m, err := manifest.Parse(files)
	if err != nil {
		return nil, mapManifestErr(err)
	}

	// Name reconciliation (tmp/04): the manifest's own name wins if it set
	// one; the "name" form field only fills in when the manifest didn't.
	name := m.Name
	if name == "" {
		name = p.Name
	}
	if name == "" {
		return nil, BadRequest("missing_name", "function name is required (set it in the manifest's \"name\" field or the deploy request's \"name\" form field)", nil)
	}
	m.Name = name

	if err := manifest.Validate(m); err != nil {
		return nil, mapManifestErr(err)
	}

	mainPath, err := manifest.ResolveMain(m.Main, files)
	if err != nil {
		return nil, BadRequest("main_not_found", err.Error(), err)
	}
	m.Main = mainPath

	if m.Compat.Nodejs {
		if imports := detectNodeCoreImports(files); len(imports) > 0 {
			return nil, BadRequest("node_core_import",
				fmt.Sprintf("compat.nodejs functions cannot import node core modules yet (no nodejs.Install hook in cfworkers.Pool; see tmp/03-runtime.md 3.5): %s", strings.Join(imports, ", ")),
				nil)
		}
	}

	warnings := buildWarnings(m)
	normalized := m.Normalized()
	normalizedJSON, err := json.Marshal(normalized)
	if err != nil {
		return nil, Internal("failed to serialize manifest", err)
	}

	result := &DeployResult{DryRun: p.DryRun, Manifest: normalized, Warnings: warnings}
	if p.DryRun {
		return result, nil
	}

	packed, err := bundle.Pack(files)
	if err != nil {
		return nil, Internal("failed to repack bundle", err)
	}
	sum := sha256.Sum256(packed)
	hash := hex.EncodeToString(sum[:])

	ownerType, ownerID, err := d.resolveOwner(ctx, p.Owner)
	if err != nil {
		return nil, err
	}

	if err := d.Blob.Put(ctx, BundleBlobKey(hash), bytes.NewReader(packed), int64(len(packed))); err != nil {
		return nil, Internal("failed to store bundle", err)
	}

	fn, err := d.Store.Functions().ByOwnerAndName(ctx, ownerType, ownerID, name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		fn = &store.Function{OwnerType: ownerType, OwnerID: ownerID, Name: name, Description: m.Description}
		if err := d.Store.Functions().Create(ctx, fn); err != nil {
			return nil, Internal("failed to create function", err)
		}
	case err != nil:
		return nil, Internal("failed to look up function", err)
	case fn.Description != m.Description:
		fn.Description = m.Description
		if err := d.Store.Functions().Update(ctx, fn); err != nil {
			return nil, Internal("failed to update function", err)
		}
	}

	filesJSON, err := json.Marshal(bundleFilesMeta(files))
	if err != nil {
		return nil, Internal("failed to serialize file list", err)
	}

	version := &store.FunctionVersion{
		FunctionID:   fn.ID,
		Manifest:     normalizedJSON,
		MainPath:     mainPath,
		BundleHash:   hash,
		BundleSize:   int64(len(packed)),
		UnpackedSize: unpackedSize,
		Files:        filesJSON,
		CreatedBy:    p.CreatedBy,
		Note:         p.Note,
	}
	if err := d.Store.Functions().CreateVersion(ctx, version); err != nil {
		return nil, Internal("failed to create version", err)
	}

	oldVersionID := fn.ActiveVersionID
	if err := d.Store.ActivateVersion(ctx, fn.ID, version.ID); err != nil {
		return nil, Internal("failed to activate version", err)
	}
	fn.ActiveVersionID = &version.ID

	if d.Runtime != nil && oldVersionID != nil {
		d.Runtime.Invalidate(*oldVersionID)
	}

	result.Function = fn
	result.Version = version
	return result, nil
}

// resolveOwner maps an owner handle to the (OwnerType, OwnerID) pair
// Function rows key on.
//
// Phase 1 shortcut, clearly called out per this task's scope: authentication
// doesn't exist yet (that's Phase 2), so there is no session/token to derive
// an owner from. If the handle isn't already claimed, resolveOwner
// auto-creates a brand-new User + Handle for it on the spot, so `funcbox
// deploy` works end-to-end today. This is NOT atomic across the two writes
// (a concurrent deploy under the same brand-new handle could race), which
// is acceptable for a single-process Phase 1 target; Phase 2's real account
// resolution (session/token -> known user) removes this path entirely.
func (d *Deployer) resolveOwner(ctx context.Context, owner string) (store.OwnerType, string, error) {
	h, err := d.Store.Handles().ByHandle(ctx, owner)
	if err == nil {
		return h.OwnerType, h.OwnerID, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return "", "", Internal("failed to look up owner handle", err)
	}

	u := &store.User{
		GoogleSub: "phase1-auto-owner:" + owner,
		Email:     owner + "@phase1-auto-owner.invalid",
		Name:      owner,
	}
	if err := d.Store.Users().Create(ctx, u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return "", "", ConflictErr("owner handle is in the middle of being provisioned by a concurrent request; retry", err)
		}
		return "", "", Internal("failed to auto-create owner user", err)
	}
	handle := &store.Handle{Handle: owner, OwnerType: store.OwnerTypeUser, OwnerID: u.ID}
	if err := d.Store.Handles().Create(ctx, handle); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return "", "", ConflictErr("owner handle was just claimed by a concurrent request; retry", err)
		}
		return "", "", Internal("failed to claim owner handle", err)
	}
	return store.OwnerTypeUser, u.ID, nil
}

// buildWarnings produces the deploy response's warnings[] (tmp/07-http-api.md:
// "?dry_run=true で検証のみ" implies the same warning set is computed for a
// dry run and a real deploy). Kept deliberately minimal for Phase 1 per this
// task's scope; org/workspace-level policy narrowing warnings arrive in
// Phase 2 once those levels exist.
func buildWarnings(m *manifest.Manifest) []string {
	var warnings []string
	if m.Source == "" {
		warnings = append(warnings, "no funcbox.yaml/funcbox.json found; using all-default settings (main resolved from index.js/index.mjs, fetch denied, no compat.nodejs)")
	}
	if m.Permissions.Fetch.Mode.String() == "allowlist" && len(m.Permissions.Fetch.Allow) == 0 {
		warnings = append(warnings, "permissions.fetch.mode is \"allowlist\" with an empty allow list, which behaves the same as \"deny\"")
	}
	return warnings
}

// detectNodeCoreImports scans every plausible JS/TS module in files for a
// "node:*" import via runtime.DetectNodeCoreImports, returning the distinct
// set found across the whole bundle (not just one file).
func detectNodeCoreImports(files map[string][]byte) []string {
	seen := make(map[string]bool)
	var out []string
	// Sort for deterministic error messages/tests.
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !looksLikeJSModule(name) {
			continue
		}
		for _, spec := range runtime.DetectNodeCoreImports(string(files[name])) {
			if !seen[spec] {
				seen[spec] = true
				out = append(out, spec)
			}
		}
	}
	return out
}

func looksLikeJSModule(path string) bool {
	for _, ext := range [...]string{".js", ".mjs", ".cjs"} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// bundleFilesMeta builds the sorted []store.BundleFile list persisted on a
// version for dashboard display.
func bundleFilesMeta(files map[string][]byte) []store.BundleFile {
	out := make([]store.BundleFile, 0, len(files))
	for path, data := range files {
		out = append(out, store.BundleFile{Path: path, Size: int64(len(data))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// mapBundleErr translates a bundle.Unpack error into the matching *Error
// status/code (tmp/02-architecture.md's guard table).
func mapBundleErr(err error) error {
	switch {
	case errors.Is(err, bundle.ErrTooLarge):
		return TooLarge("bundle exceeds the unpacked size limit", err)
	case errors.Is(err, bundle.ErrTooManyFiles):
		return BadRequest("too_many_files", err.Error(), err)
	case errors.Is(err, bundle.ErrBadPath):
		return BadRequest("bad_path", err.Error(), err)
	case errors.Is(err, bundle.ErrBadEntryType):
		return BadRequest("bad_entry_type", err.Error(), err)
	default:
		return BadRequest("bad_bundle", err.Error(), err)
	}
}

// mapManifestErr translates any manifest package error (Parse, Validate, or
// ValidateHandle) into a 400 *Error, using the error's own message (they are
// already written to be user-facing) and a code derived from its sentinel.
func mapManifestErr(err error) error {
	code := "invalid_manifest"
	switch {
	case errors.Is(err, manifest.ErrReservedName):
		code = "reserved_name"
	case errors.Is(err, manifest.ErrInvalidName), errors.Is(err, manifest.ErrInvalidOwner):
		code = "invalid_name"
	case errors.Is(err, manifest.ErrDescriptionTooLong):
		code = "description_too_long"
	case errors.Is(err, manifest.ErrInvalidEnv):
		code = "invalid_env"
	case errors.Is(err, manifest.ErrParse):
		code = "manifest_parse_error"
	case errors.Is(err, manifest.ErrInvalidTimeout):
		code = "invalid_timeout"
	case errors.Is(err, manifest.ErrInvalidMemory):
		code = "invalid_memory"
	case errors.Is(err, manifest.ErrInvalidFetchPolicy):
		code = "invalid_fetch_policy"
	case errors.Is(err, manifest.ErrInvalidVisibility):
		code = "invalid_visibility"
	}
	return BadRequest(code, err.Error(), err)
}
