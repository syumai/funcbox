package invoke

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/syumai/funcbox/policy"
	"github.com/syumai/funcbox/server/internal/settings"
	"github.com/syumai/funcbox/server/internal/store"
)

// storeLookupTimeout bounds the org/workspace settings lookups this file
// performs on the guest's behalf mid-request (both from Invoker.Serve, and
// from a warm pool's fetch hooks — see effectiveCache's doc comment).
const storeLookupTimeout = 3 * time.Second

// effectiveCache memoizes the effective fetch policy (org ∩ workspace ∩
// manifest, tmp/05-auth-and-permissions.md §5.6) keyed by
// (org.SettingsGen, ws.SettingsGen, versionID), so that a long-lived,
// warmed runtime.Manager pool's fetch hooks (see fetchPolicyAdapter in
// policy.go) don't reparse host-allowlist patterns on every single
// outbound fetch call. The generation numbers are looked up fresh on
// every call regardless of cache hit/miss -- there is no push-based
// invalidation -- but they're the only thing that changes cheaply-often;
// looking them up is what makes a settings change "take effect
// immediately" (tmp/05 §5.6: "実効ポリシーは実行時に解決する") even
// against a pool that was warmed long before the change, without needing
// the runtime.Manager to rebuild that pool.
//
// This means every fetch() call, however hot the pool, does one or two
// small store reads (org row, plus a workspace row for a workspace-owned
// function) to learn the current generation before it can even consult
// the cache. That's an accepted phase-2 tradeoff for a single-writer
// SQLite backend; a future phase could push generation changes into an
// in-memory value instead of reading them per-call.
type effectiveCache struct {
	mu      sync.RWMutex
	entries map[string]policy.EffectivePolicy
}

func newEffectiveCache() *effectiveCache {
	return &effectiveCache{entries: make(map[string]policy.EffectivePolicy)}
}

// ownerSettings is the (generation, parsed fetch policy) pair for one
// policy level (organization or workspace).
type ownerSettings struct {
	gen    int
	fetch  policy.FetchPolicy
	exists bool // false for a workspace level on a user-owned function
}

func loadOrgSettings(ctx context.Context, st store.Store) (ownerSettings, error) {
	org, err := st.Organizations().Get(ctx)
	if err != nil {
		return ownerSettings{}, fmt.Errorf("invoke: load organization: %w", err)
	}
	orgSet, err := settings.ParseOrg(org.Settings)
	if err != nil {
		return ownerSettings{}, fmt.Errorf("invoke: parse organization settings: %w", err)
	}
	fp, err := orgSet.FetchPolicy.Policy()
	if err != nil {
		return ownerSettings{}, fmt.Errorf("invoke: parse organization fetch policy: %w", err)
	}
	return ownerSettings{gen: org.SettingsGen, fetch: fp, exists: true}, nil
}

func loadWorkspaceSettings(ctx context.Context, st store.Store, wsID string) (ownerSettings, error) {
	ws, err := st.Workspaces().ByID(ctx, wsID)
	if err != nil {
		return ownerSettings{}, fmt.Errorf("invoke: load workspace: %w", err)
	}
	wsSet, err := settings.ParseWorkspace(ws.Settings)
	if err != nil {
		return ownerSettings{}, fmt.Errorf("invoke: parse workspace settings: %w", err)
	}
	fp, err := wsSet.FetchPolicy.Policy()
	if err != nil {
		return ownerSettings{}, fmt.Errorf("invoke: parse workspace fetch policy: %w", err)
	}
	return ownerSettings{gen: ws.SettingsGen, fetch: fp, exists: true}, nil
}

// resolveFetch computes (and caches, per this type's doc comment) the
// effective fetch policy for a function version, intersecting the
// organization, (if any) workspace, and manifest levels
// (tmp/05-auth-and-permissions.md §5.6). It fails closed (deny) if the
// organization row can't be loaded at all -- that should never happen in
// practice (Migrate + BootstrapFirstUser always create it before any
// function can exist), but a fetch policy is exactly the kind of check
// that must never fail open.
func (c *effectiveCache) resolveFetch(st store.Store, ownerType store.OwnerType, ownerID, versionID string, manifestLevel policy.FetchPolicy) policy.EffectivePolicy {
	ctx, cancel := context.WithTimeout(context.Background(), storeLookupTimeout)
	defer cancel()

	org, err := loadOrgSettings(ctx, st)
	if err != nil {
		return policy.Effective(policy.FetchPolicy{Mode: policy.FetchModeDeny})
	}

	ws := ownerSettings{}
	if ownerType == store.OwnerTypeWorkspace {
		ws, err = loadWorkspaceSettings(ctx, st, ownerID)
		if err != nil {
			return policy.Effective(policy.FetchPolicy{Mode: policy.FetchModeDeny})
		}
	}

	key := fmt.Sprintf("%d:%d:%s", org.gen, ws.gen, versionID)
	c.mu.RLock()
	if cached, ok := c.entries[key]; ok {
		c.mu.RUnlock()
		return cached
	}
	c.mu.RUnlock()

	levels := []policy.FetchPolicy{org.fetch}
	if ws.exists {
		levels = append(levels, ws.fetch)
	}
	levels = append(levels, manifestLevel)
	eff := policy.Effective(levels...)

	c.mu.Lock()
	c.entries[key] = eff
	c.mu.Unlock()
	return eff
}

// resolveVisibility computes the effective visibility for a function
// version (tmp/05-auth-and-permissions.md §5.6: "実効 visibility =
// min(manifest.visibility, ws.max_visibility, org.max_visibility)"),
// applying the organization's default_visibility when the manifest itself
// doesn't declare one (tmp/04-manifest.md). Unlike fetch policy this is
// computed once per HTTP request directly by Invoker.Serve (not from
// inside a long-lived pool), so it needs no cache -- it's already as live
// as a per-request DB read can be.
func resolveVisibility(ctx context.Context, st store.Store, ownerType store.OwnerType, ownerID string, manifestVisibility string) (policy.Visibility, error) {
	org, err := st.Organizations().Get(ctx)
	if err != nil {
		return 0, fmt.Errorf("invoke: load organization: %w", err)
	}
	orgSet, err := settings.ParseOrg(org.Settings)
	if err != nil {
		return 0, fmt.Errorf("invoke: parse organization settings: %w", err)
	}
	orgMax, err := policy.ParseVisibility(orgSet.MaxVisibility)
	if err != nil {
		return 0, fmt.Errorf("invoke: parse organization max_visibility: %w", err)
	}

	declared := manifestVisibility
	if declared == "" {
		declared = orgSet.DefaultVisibility
	}
	manifestVis, err := policy.ParseVisibility(declared)
	if err != nil {
		return 0, fmt.Errorf("invoke: parse effective manifest visibility %q: %w", declared, err)
	}

	if ownerType != store.OwnerTypeWorkspace {
		return policy.MinVisibility(manifestVis, orgMax), nil
	}

	ws, err := st.Workspaces().ByID(ctx, ownerID)
	if err != nil {
		return 0, fmt.Errorf("invoke: load workspace: %w", err)
	}
	wsSet, err := settings.ParseWorkspace(ws.Settings)
	if err != nil {
		return 0, fmt.Errorf("invoke: parse workspace settings: %w", err)
	}
	if wsSet.MaxVisibility == "" {
		return policy.MinVisibility(manifestVis, orgMax), nil
	}
	wsMax, err := policy.ParseVisibility(wsSet.MaxVisibility)
	if err != nil {
		return 0, fmt.Errorf("invoke: parse workspace max_visibility: %w", err)
	}
	return policy.MinVisibility(manifestVis, wsMax, orgMax), nil
}

// checkWorkspaceMembership reports whether userID is a member of wsID.
func checkWorkspaceMembership(ctx context.Context, st store.Store, wsID, userID string) (bool, error) {
	members, err := st.Workspaces().ListMembers(ctx, wsID)
	if err != nil {
		return false, err
	}
	for _, m := range members {
		if m.UserID == userID {
			return true, nil
		}
	}
	return false, nil
}
