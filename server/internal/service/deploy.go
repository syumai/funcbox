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

	"github.com/syumai/funcbox/bundle"
	"github.com/syumai/funcbox/manifest"
	"github.com/syumai/funcbox/runtime"
	"github.com/syumai/funcbox/server/internal/authz"
	"github.com/syumai/funcbox/server/internal/blob"
	"github.com/syumai/funcbox/server/internal/settings"
	"github.com/syumai/funcbox/server/internal/store"
)

// MaxCompressedBundleBytes is the request-body limit applied to an upload
// 上限 5MB"). The HTTP layer is expected to wrap the request body in
// http.MaxBytesReader(w, r.Body, MaxCompressedBundleBytes) before parsing
// the multipart form.
const MaxCompressedBundleBytes = 5 << 20

// BundleBlobKey returns the content-addressed blob.Store key for a
// canonical bundle's sha256 hex digest, e.g.
// invoke path can recompute the same key from a stored FunctionVersion's
// BundleHash without duplicating the format.
func BundleBlobKey(sha256Hex string) string {
	return "bundles/sha256/" + sha256Hex + ".tar.gz"
}

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
type DeployParams struct {
	// Bundle is the raw tar.gz upload. The caller is responsible for
	// bounding its size (e.g. http.MaxBytesReader) before Deploy is called;
	// Deploy itself only enforces the post-decompression limit via
	// bundle.Unpack.
	Bundle io.Reader
	// Owner is the public User ID or immutable workspace ID. Required.
	Owner string
	// Name is the function name, used only when the manifest doesn't
	Name string
	Note string
	// DryRun stops Deploy before any write; see Deploy's doc comment. A
	// dry run only validates the manifest -- it never resolves or
	// authorizes against Owner, so Actor is not consulted in this case.
	DryRun bool

	// Actor is the authenticated caller deploying. Required for any
	// non-dry-run deploy: Deploy authorizes Owner against Actor (own
	// public User ID, or a workspace Actor may deploy to -- see
	// resolveOwner) and records Actor.ID as the created version's author.
	Actor *store.User
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

//  1. bundle.Unpack the upload (guarded streaming extraction; typed errors
//     map to 4xx/413 via mapBundleErr).
//  2. manifest.Parse, reconcile Name with params.Name (manifest wins if
//     set), then manifest.Validate.
//  3. manifest.ResolveMain against the unpacked files.
//  4. If compat.nodejs is set, reject any "node:*" import
//     (runtime.DetectNodeCoreImports) — cfworkers.Pool has no hook to
//  5. Build warnings, bundle.Pack a canonical tar.gz, and sha256 it.
//
// If params.DryRun is set, Deploy returns here: DeployResult carries the
// normalized manifest and warnings but Function/Version are nil, and
// nothing has been written to the store or blob backend.
//
// Otherwise Deploy continues:
//
//  6. Resolve params.Owner to a store owner (resolveOwner) and authorize
//     User ID must be Actor's own (org admins may deploy under any user),
//     or a workspace Actor may deploy to.
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
	if !p.DryRun && p.Actor == nil {
		return nil, Unauthorized("authentication is required to deploy")
	}
	if err := manifest.ValidateUserID(p.Owner); err != nil && p.Owner == strings.ToLower(p.Owner) {
		return nil, mapManifestErr(err)
	}
	// Loaded once, up front: buildWarnings needs it for the
	// allow_nodejs_compat warning, and authorizeDeploy reuses it for its
	// own user-owner check below, rather than fetching organizations
	// twice per deploy.
	orgSet, err := d.loadOrgSettings(ctx)
	if err != nil {
		return nil, err
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

	warnings := buildWarnings(m, orgSet)
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
	if err := d.authorizeDeploy(ctx, p.Actor, ownerType, ownerID, orgSet); err != nil {
		return nil, err
	}

	if err := d.Blob.Put(ctx, BundleBlobKey(hash), bytes.NewReader(packed), int64(len(packed))); err != nil {
		return nil, Internal("failed to store bundle", err)
	}

	fn, err := d.Store.Functions().ByName(ctx, name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		fn = &store.Function{OwnerType: ownerType, OwnerID: ownerID, Name: name, Description: m.Description}
		if err := d.Store.Functions().Create(ctx, fn); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return nil, FunctionNameTaken(err)
			}
			return nil, Internal("failed to create function", err)
		}
	case err != nil:
		return nil, Internal("failed to look up function", err)
	case fn.OwnerType != ownerType || fn.OwnerID != ownerID:
		return nil, FunctionNameTaken(store.ErrConflict)
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
		CreatedBy:    p.Actor.ID,
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

// resolveOwner maps a public User ID or immutable workspace ID to the
// (OwnerType, OwnerID) pair Function rows key on.
func (d *Deployer) resolveOwner(ctx context.Context, owner string) (store.OwnerType, string, error) {
	id, err := d.Store.PublicUserIDs().ByUserID(ctx, owner)
	if err == nil {
		return store.OwnerTypeUser, id.InternalUserID, nil
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", "", Internal("failed to look up User ID", err)
	}
	ws, wsErr := d.Store.Workspaces().ByID(ctx, owner)
	if wsErr == nil {
		return store.OwnerTypeWorkspace, ws.ID, nil
	}
	if !errors.Is(wsErr, store.ErrNotFound) {
		return "", "", Internal("failed to look up workspace", wsErr)
	}
	if err := manifest.ValidateUserID(owner); err != nil {
		return "", "", mapManifestErr(err)
	}
	return "", "", NotFoundErr("owner not found", store.ErrNotFound)
}

// loadOrgSettings loads and parses the organization's settings, falling
// back to settings.DefaultOrg if the organization row doesn't exist yet
// (e.g. a store that hasn't gone through BootstrapFirstUser -- notably,
// some unit tests construct a Deployer directly against a bare store).
func (d *Deployer) loadOrgSettings(ctx context.Context) (settings.Org, error) {
	org, err := d.Store.Organizations().Get(ctx)
	switch {
	case err == nil:
		orgSet, parseErr := settings.ParseOrg(org.Settings)
		if parseErr != nil {
			return settings.Org{}, Internal("failed to parse organization settings", parseErr)
		}
		return orgSet, nil
	case errors.Is(err, store.ErrNotFound):
		return settings.DefaultOrg(), nil
	default:
		return settings.Org{}, Internal("failed to load organization settings", err)
	}
}

// authorizeDeploy checks that actor may deploy to (ownerType, ownerID),
// プロイ" rows (internal/authz.CanDeployPersonal / CanDeployToWorkspace).
func (d *Deployer) authorizeDeploy(ctx context.Context, actor *store.User, ownerType store.OwnerType, ownerID string, orgSet settings.Org) error {
	a := authz.Actor{UserID: actor.ID, Role: actor.Role}

	if ownerType == store.OwnerTypeUser {
		if !authz.CanDeployPersonal(a, ownerID, orgSet.AllowUserFunctions) {
			return Forbidden("not permitted to deploy as this user")
		}
		return nil
	}

	ws, err := d.Store.Workspaces().ByID(ctx, ownerID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return NotFoundErr("owner workspace not found", err)
		}
		return Internal("failed to load workspace", err)
	}
	wsSet, err := settings.ParseWorkspace(ws.Settings)
	if err != nil {
		return Internal("failed to parse workspace settings", err)
	}
	role, err := workspaceRole(ctx, d.Store, ownerID, actor.ID)
	if err != nil {
		return Internal("failed to load workspace membership", err)
	}
	if !authz.CanDeployToWorkspace(a, role, wsSet.MemberCanDeploy) {
		return Forbidden("not permitted to deploy to this workspace")
	}
	return nil
}

// workspaceRole returns userID's role within wsID, or nil if userID is not
// a member. Shared by Deployer and Functions (functions.go).
func workspaceRole(ctx context.Context, st store.Store, wsID, userID string) (*store.Role, error) {
	members, err := st.Workspaces().ListMembers(ctx, wsID)
	if err != nil {
		return nil, err
	}
	for _, m := range members {
		if m.UserID == userID {
			r := m.Role
			return &r, nil
		}
	}
	return nil, nil
}

// "?dry_run=true で検証のみ" implies the same warning set is computed for a
// dry run and a real deploy).
func buildWarnings(m *manifest.Manifest, orgSet settings.Org) []string {
	var warnings []string
	if m.Source == "" {
		warnings = append(warnings, "no funcbox.yaml/funcbox.json found; using all-default settings (main resolved from index.js/index.mjs, fetch denied, no compat.nodejs)")
	}
	if m.Permissions.Fetch.Mode.String() == "allowlist" && len(m.Permissions.Fetch.Allow) == 0 {
		warnings = append(warnings, "permissions.fetch.mode is \"allowlist\" with an empty allow list, which behaves the same as \"deny\"")
	}
	if m.Compat.Nodejs && !orgSet.AllowNodejsCompat {
		// (org level) → deploy warning + runtime disable". The runtime
		// disable half lives in internal/invoke/pool.go's
		// orgAllowsNodejsCompat, re-checked at invoke time (not frozen at
		// deploy time) since the org setting can change after this
		// deploy.
		warnings = append(warnings, "compat.nodejs is set, but this organization has allow_nodejs_compat disabled; Node.js-compatible module resolution will be OFF at runtime regardless of this manifest")
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
// ValidateUserID) into a 400 *Error, using the error's own message (they are
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
