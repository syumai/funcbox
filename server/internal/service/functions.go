package service

import (
	"context"
	"errors"

	"github.com/syumai/funcbox/runtime"
	"github.com/syumai/funcbox/server/internal/authz"
	"github.com/syumai/funcbox/server/internal/crypto"
	"github.com/syumai/funcbox/server/internal/settings"
	"github.com/syumai/funcbox/server/internal/store"
)

// Functions implements the read/rollback/delete function-management use
// cases behind GET/POST/DELETE /api/v1/functions/... (tmp/07-http-api.md
// §7.3). Deploy itself lives in Deployer (deploy.go); this type covers
// everything else so a caller only needing lookups doesn't need a
// blob.Store.
type Functions struct {
	Store store.Store

	// Runtime is invalidated for the function's active version on Activate
	// (rollback) and Delete, so a stale pool never keeps serving a version
	// that's no longer active/no longer exists. May be nil, in which case
	// invalidation is skipped (e.g. a CLI-side dry tool with no runtime).
	Runtime *runtime.Manager

	// EnvKey is the AES-256-GCM key env vars are encrypted/decrypted
	// under (derived from FUNCBOX_SESSION_SECRET via internal/crypto;
	// tmp/06-data-model.md's env_vars.value_enc). Required by
	// SetEnv/DeleteEnv; the invoke path derives and uses the same key
	// independently to decrypt at read time (internal/invoke/pool.go).
	EnvKey []byte
}

// Resolve looks up a function by owner handle + name, returning
// NotFoundErr if either the handle or the function doesn't exist.
func (f *Functions) Resolve(ctx context.Context, owner, name string) (*store.Function, error) {
	h, err := f.Store.Handles().ByHandle(ctx, owner)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, NotFoundErr("owner not found", err)
		}
		return nil, Internal("failed to look up owner", err)
	}
	fn, err := f.Store.Functions().ByOwnerAndName(ctx, h.OwnerType, h.OwnerID, name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, NotFoundErr("function not found", err)
		}
		return nil, Internal("failed to look up function", err)
	}
	return fn, nil
}

// List returns every function owned by userID directly or by a workspace
// userID is a member of (dashboard function list for a non-admin actor;
// see ListAll for the org-admin's unrestricted view).
func (f *Functions) List(ctx context.Context, userID string) ([]*store.Function, error) {
	fns, err := f.Store.Functions().ListVisibleTo(ctx, userID)
	if err != nil {
		return nil, Internal("failed to list functions", err)
	}
	return fns, nil
}

// ListAll returns every function in the organization, for an org admin
// (tmp/05-auth-and-permissions.md §5.3: an org admin implicitly manages
// every function).
func (f *Functions) ListAll(ctx context.Context) ([]*store.Function, error) {
	fns, err := f.Store.Functions().ListAll(ctx)
	if err != nil {
		return nil, Internal("failed to list functions", err)
	}
	return fns, nil
}

// CanView reports whether actor may see a function owned by
// (ownerType, ownerID): an org admin, the function's own user owner, or
// any member of the function's owning workspace.
func (f *Functions) CanView(ctx context.Context, actor *store.User, ownerType store.OwnerType, ownerID string) (bool, error) {
	a := authz.Actor{UserID: actor.ID, Role: actor.Role}
	if a.IsOrgAdmin() {
		return true, nil
	}
	if ownerType == store.OwnerTypeUser {
		return actor.ID == ownerID, nil
	}
	role, err := workspaceRole(ctx, f.Store, ownerID, actor.ID)
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

// ListByOwner returns every function owned by the given handle. This is the
// Phase 1 stand-in for List's userID-scoped visibility (tmp/07-http-api.md's
// "?owner= で絞り込み"): with no auth yet, "everything visible to me" isn't
// meaningful, so the API handler filters by the explicit ?owner= query
// param instead.
func (f *Functions) ListByOwner(ctx context.Context, owner string) ([]*store.Function, error) {
	h, err := f.Store.Handles().ByHandle(ctx, owner)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, NotFoundErr("owner not found", err)
		}
		return nil, Internal("failed to look up owner", err)
	}
	fns, err := f.Store.Functions().ListByOwner(ctx, h.OwnerType, h.OwnerID)
	if err != nil {
		return nil, Internal("failed to list functions", err)
	}
	return fns, nil
}

// OwnerHandle resolves fn's (OwnerType, OwnerID) back to its handle string
// — the inverse of Resolve, needed when building an API response for a
// function looked up some other way (e.g. Functions().ListByOwner already
// knows the handle from its own argument, but List/ListVisibleTo don't).
func (f *Functions) OwnerHandle(ctx context.Context, fn *store.Function) (string, error) {
	h, err := f.Store.Handles().ByOwner(ctx, fn.OwnerType, fn.OwnerID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", NotFoundErr("owner handle not found", err)
		}
		return "", Internal("failed to resolve owner handle", err)
	}
	return h.Handle, nil
}

// ActiveVersion returns fn's active FunctionVersion, or NotFoundErr if fn
// has never had a version activated.
func (f *Functions) ActiveVersion(ctx context.Context, fn *store.Function) (*store.FunctionVersion, error) {
	if fn.ActiveVersionID == nil {
		return nil, NotFoundErr("function has no active version", nil)
	}
	v, err := f.Store.Functions().Version(ctx, *fn.ActiveVersionID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, NotFoundErr("active version not found", err)
		}
		return nil, Internal("failed to look up active version", err)
	}
	return v, nil
}

// ListVersions returns fn's versions, newest first.
func (f *Functions) ListVersions(ctx context.Context, fn *store.Function, limit int) ([]*store.FunctionVersion, error) {
	versions, err := f.Store.Functions().ListVersions(ctx, fn.ID, limit)
	if err != nil {
		return nil, Internal("failed to list versions", err)
	}
	return versions, nil
}

// Activate rolls fn back (or forward) to versionID: it must already be one
// of fn's existing versions (Store.ActivateVersion enforces this). The
// function's previously active version's pool is invalidated so the next
// invocation is served by the newly activated version instead of a stale
// warm pool.
func (f *Functions) Activate(ctx context.Context, fn *store.Function, versionID string) (*store.Function, error) {
	oldVersionID := fn.ActiveVersionID
	if err := f.Store.ActivateVersion(ctx, fn.ID, versionID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, NotFoundErr("version not found for this function", err)
		}
		return nil, Internal("failed to activate version", err)
	}
	fn.ActiveVersionID = &versionID

	if f.Runtime != nil && oldVersionID != nil && *oldVersionID != versionID {
		f.Runtime.Invalidate(*oldVersionID)
	}
	return fn, nil
}

// Delete removes fn (and its versions/env vars, per FunctionRepo.Delete)
// and invalidates its active pool if one exists. Blob GC is intentionally
// out of scope for Phase 1 (tmp task scope): the canonical bundle bytes are
// content-addressed and may be shared by other versions/functions, so
// deleting them here would need reference counting this phase doesn't
// implement.
func (f *Functions) Delete(ctx context.Context, fn *store.Function) error {
	if f.Runtime != nil && fn.ActiveVersionID != nil {
		f.Runtime.Invalidate(*fn.ActiveVersionID)
	}
	if err := f.Store.Functions().Delete(ctx, fn.ID); err != nil {
		return Internal("failed to delete function", err)
	}
	return nil
}

// CanManage checks whether actor may manage fn -- rollback (Activate),
// delete, and env var changes all share this one rule
// (tmp/07-http-api.md §7.4: rollback/delete/env all "follow deploy
// rights" for the function's owner). Returns a *Error (Forbidden) if not,
// nil if so.
func (f *Functions) CanManage(ctx context.Context, actor *store.User, fn *store.Function) error {
	a := authz.Actor{UserID: actor.ID, Role: actor.Role}

	if fn.OwnerType == store.OwnerTypeWorkspace {
		ws, err := f.Store.Workspaces().ByID(ctx, fn.OwnerID)
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
		role, err := workspaceRole(ctx, f.Store, fn.OwnerID, actor.ID)
		if err != nil {
			return Internal("failed to load workspace membership", err)
		}
		if !authz.CanManageFunction(a, fn.OwnerType, "", role, wsSet.MemberCanDeploy) {
			return Forbidden("not permitted to manage this function")
		}
		return nil
	}

	if !authz.CanManageFunction(a, fn.OwnerType, fn.OwnerID, nil, false) {
		return Forbidden("not permitted to manage this function")
	}
	return nil
}

// SetEnv encrypts value under EnvKey and upserts it as key on fn's env
// vars, after checking actor may manage fn (CanManage).
func (f *Functions) SetEnv(ctx context.Context, actor *store.User, fn *store.Function, key, value string) error {
	if err := f.CanManage(ctx, actor, fn); err != nil {
		return err
	}
	if len(f.EnvKey) == 0 {
		return Internal("env var encryption key is not configured", nil)
	}
	ciphertext, err := crypto.Encrypt(f.EnvKey, []byte(value))
	if err != nil {
		return Internal("failed to encrypt env var", err)
	}
	if err := f.Store.Functions().SetEnv(ctx, fn.ID, key, ciphertext); err != nil {
		return Internal("failed to store env var", err)
	}
	return nil
}

// DeleteEnv removes key from fn's env vars, after checking actor may
// manage fn (CanManage).
func (f *Functions) DeleteEnv(ctx context.Context, actor *store.User, fn *store.Function, key string) error {
	if err := f.CanManage(ctx, actor, fn); err != nil {
		return err
	}
	if err := f.Store.Functions().DeleteEnv(ctx, fn.ID, key); err != nil {
		return Internal("failed to delete env var", err)
	}
	return nil
}

// ListEnvKeys returns the set of env var keys currently set on fn (never
// their values -- tmp/07-http-api.md §7.3: "値は書き込み専用"), for
// dashboard display.
func (f *Functions) ListEnvKeys(ctx context.Context, fn *store.Function) ([]string, error) {
	env, err := f.Store.Functions().ListEnv(ctx, fn.ID)
	if err != nil {
		return nil, Internal("failed to list env vars", err)
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	return keys, nil
}
