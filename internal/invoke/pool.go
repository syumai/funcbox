package invoke

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"

	spidermonkey "github.com/goccy/go-spidermonkey"
	"github.com/goccy/go-spidermonkey/compat/cfworkers"
	"github.com/goccy/go-spidermonkey/compat/nodejs"

	"github.com/syumai/funcbox/internal/blob"
	"github.com/syumai/funcbox/internal/bundle"
	"github.com/syumai/funcbox/internal/manifest"
	"github.com/syumai/funcbox/internal/policy"
	"github.com/syumai/funcbox/internal/runtime"
	"github.com/syumai/funcbox/internal/service"
	"github.com/syumai/funcbox/internal/store"
)

// DefaultPoolSize is the number of warmed instances created per function
// version (tmp/03-runtime.md 3.2: "デフォルト Size は小さめ（2）"). Phase 1
// has no per-function/org override yet.
const DefaultPoolSize = 2

// buildPool is a runtime.VersionSpec.Build function: it loads v's canonical
// bundle from blob storage, re-unpacks it (defense in depth — the same
// guarded unpack used at deploy time; tmp/03-runtime.md 3.5), and warms a
// cfworkers.Pool configured from v's stored normalized manifest.
func buildPool(ctx context.Context, blobStore blob.Store, st store.Store, v *store.FunctionVersion) (*cfworkers.Pool, error) {
	var nm manifest.Normalized
	if err := json.Unmarshal(v.Manifest, &nm); err != nil {
		return nil, fmt.Errorf("invoke: decode stored manifest for version %s: %w", v.ID, err)
	}

	rc, err := blobStore.Get(ctx, service.BundleBlobKey(v.BundleHash))
	if err != nil {
		return nil, fmt.Errorf("invoke: fetch bundle for version %s: %w", v.ID, err)
	}
	defer rc.Close()

	files, err := bundle.Unpack(rc)
	if err != nil {
		return nil, fmt.Errorf("invoke: unpack bundle for version %s: %w", v.ID, err)
	}
	b := runtime.Bundle(files)

	var loader spidermonkey.ModuleLoader
	var fsys fs.FS
	if nm.Compat.Nodejs {
		loader = nodejs.ESMLoader
		fsys = b.FS()
	} else {
		loader = runtime.NewLoader(b)
	}

	fp, err := buildFetchPolicy(nm.Permissions.Fetch)
	if err != nil {
		return nil, fmt.Errorf("invoke: build fetch policy for version %s: %w", v.ID, err)
	}

	env, err := buildEnvBindings(ctx, st, v.FunctionID, nm.Env)
	if err != nil {
		return nil, err
	}

	cfg := spidermonkey.Config{
		FS:      fsys,
		Resolve: runtime.ResolveHook(fp),
		Dial:    runtime.DialHook(fp),
	}
	if nm.Memory > 0 {
		cfg.MaxMemoryBytes = int(nm.Memory)
	}

	pool, err := cfworkers.NewPool(cfworkers.PoolConfig{
		Config: cfg,
		Size:   DefaultPoolSize,
		Source: fmt.Sprintf("import handler from %q; export default handler;", "./"+v.MainPath),
		Loader: loader,
		Env:    env,
	})
	if err != nil {
		return nil, fmt.Errorf("invoke: warm pool for version %s: %w", v.ID, err)
	}
	return pool, nil
}

// buildFetchPolicy converts a stored version's normalized fetch permission
// into the runtime.FetchPolicy the Resolve/Dial hooks need, running it
// through policy.Effective so that adding org/workspace levels in Phase 2
// is a one-liner (tmp/03-runtime.md 3.4) — Phase 1 only ever has the
// manifest level.
func buildFetchPolicy(f manifest.NormalizedFetch) (*fetchPolicyAdapter, error) {
	mode, err := policy.ParseFetchMode(f.Mode)
	if err != nil {
		return nil, fmt.Errorf("stored manifest fetch mode %q: %w", f.Mode, err)
	}
	allow := make([]policy.Pattern, 0, len(f.Allow))
	for _, s := range f.Allow {
		p, err := policy.ParsePattern(s)
		if err != nil {
			return nil, fmt.Errorf("stored manifest fetch allow pattern %q: %w", s, err)
		}
		allow = append(allow, p)
	}
	manifestLevel := policy.FetchPolicy{Mode: mode, Allow: allow}
	effective := policy.Effective(manifestLevel)
	return newFetchPolicyAdapter(effective, allow), nil
}

// buildEnvBindings exposes the function's stored env vars as env.KEY
// static bindings, restricted to the keys the active version's manifest
// declares (store.EnvVar's doc comment: "Only keys also declared in the
// active version's manifest are exposed at runtime").
//
// Phase 1 note (this task's scope): EnvVar.ValueEnc is plaintext for now —
// real AES-GCM encryption at rest is Phase 2 work (auth also lands then,
// and the two are related: encryption needs a key management story tied to
// the org). This function is a straight passthrough, documented so Phase 2
// knows exactly where to add a Decrypt call.
func buildEnvBindings(ctx context.Context, st store.Store, functionID string, declared []string) (map[string]cfworkers.Binding, error) {
	if len(declared) == 0 {
		return nil, nil
	}
	values, err := st.Functions().ListEnv(ctx, functionID)
	if err != nil {
		return nil, fmt.Errorf("invoke: list env vars for function %s: %w", functionID, err)
	}
	env := make(map[string]cfworkers.Binding, len(declared))
	for _, key := range declared {
		if v, ok := values[key]; ok {
			env[key] = runtime.StaticBinding(string(v))
		}
	}
	return env, nil
}
