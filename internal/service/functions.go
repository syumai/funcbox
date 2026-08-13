package service

import (
	"context"
	"errors"

	"github.com/syumai/funcbox/internal/runtime"
	"github.com/syumai/funcbox/internal/store"
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

// List returns every function visible to userID (dashboard function list).
// Phase 1 has no authentication (see Deployer's package doc), so the API
// handler currently has no real userID to pass; ListAll below serves
// unauthenticated listing until Phase 2 wires a session in.
func (f *Functions) List(ctx context.Context, userID string) ([]*store.Function, error) {
	fns, err := f.Store.Functions().ListVisibleTo(ctx, userID)
	if err != nil {
		return nil, Internal("failed to list functions", err)
	}
	return fns, nil
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
