package invoke

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"

	spidermonkey "github.com/goccy/go-spidermonkey"
	"github.com/goccy/go-spidermonkey/compat/cfworkers"
	"github.com/goccy/go-spidermonkey/compat/nodejs"

	"github.com/syumai/funcbox/bundle"
	"github.com/syumai/funcbox/manifest"
	"github.com/syumai/funcbox/policy"
	"github.com/syumai/funcbox/runtime"
	"github.com/syumai/funcbox/server/internal/blob"
	fcrypto "github.com/syumai/funcbox/server/internal/crypto"
	"github.com/syumai/funcbox/server/internal/service"
	"github.com/syumai/funcbox/server/internal/settings"
	"github.com/syumai/funcbox/server/internal/store"
)

// DefaultPoolSize is the number of warmed instances created per function
// has no per-function/org override yet.
const DefaultPoolSize = 2

// buildPool is a runtime.VersionSpec.Build function: it loads v's canonical
// bundle from blob storage, re-unpacks it (defense in depth — the same
// cfworkers.Pool configured from v's stored normalized manifest.
//
// ownerType/ownerID identify v's function's owner, needed to intersect the
// org/workspace fetch policy levels (see effective.go); cache is the
// Invoker's shared effectiveCache, so fetch-policy changes take effect on
// this pool without a rebuild (see fetchPolicyAdapter's doc comment in
// policy.go). envKey decrypts the function's stored env vars
// exposure entirely (fails closed rather than exposing ciphertext).
//
// allow_nodejs_compat is checked here at pool-BUILD time only, not
// live-resolved like fetch policy: swapping a pool's module loader after
// construction isn't something the runtime.Manager/cfworkers.Pool
// abstraction supports, so an org disabling compat.nodejs takes effect
// the next time this version's pool is (re)built (a redeploy, or the pool
// being evicted/invalidated) rather than on the next request the way
// oversight — a future phase could fold org.SettingsGen into the pool
// cache key to make it fully live.
func buildPool(ctx context.Context, blobStore blob.Store, st store.Store, v *store.FunctionVersion, ownerType store.OwnerType, ownerID string, envKey []byte, cache *effectiveCache, tracker *invocationTracker) (*cfworkers.Pool, error) {
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

	useNodejs := nm.Compat.Nodejs && orgAllowsNodejsCompat(ctx, st)

	var loader spidermonkey.ModuleLoader
	var fsys fs.FS
	if useNodejs {
		loader = nodejs.ESMLoader
		fsys = b.FS()
	} else {
		loader = runtime.NewLoader(b)
	}

	fp, err := buildFetchPolicy(nm.Permissions.Fetch, st, ownerType, ownerID, v.ID, cache, tracker)
	if err != nil {
		return nil, fmt.Errorf("invoke: build fetch policy for version %s: %w", v.ID, err)
	}

	env, err := buildEnvBindings(ctx, st, v.FunctionID, nm.Env, envKey)
	if err != nil {
		return nil, err
	}

	cfg := spidermonkey.Config{
		FS:      fsys,
		Resolve: runtime.ResolveHook(fp),
		Dial:    runtime.DialHook(fp),
		// Stdout/Stderr are per-pool (fixed here, at build time, and then
		// shared across every request the warmed pool serves), but
		// stdoutWriter/stderrWriter demultiplex back to the correct
		// invocation via tracker; see logcapture.go.
		Stdout: stdoutWriter{t: tracker},
		Stderr: stderrWriter{t: tracker},
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
// into the runtime.FetchPolicy the Resolve/Dial hooks need. The manifest
// level's mode/allow-list is parsed once here (versions are immutable, so
// this never changes for a given v.ID); the org/workspace levels are
// resolved live on every call via cache.resolveFetch (see policy.go's
// fetchPolicyAdapter and effective.go's effectiveCache for why).
func buildFetchPolicy(f manifest.NormalizedFetch, st store.Store, ownerType store.OwnerType, ownerID, versionID string, cache *effectiveCache, tracker *invocationTracker) (*fetchPolicyAdapter, error) {
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

	resolve := func() policy.EffectivePolicy {
		return cache.resolveFetch(st, ownerType, ownerID, versionID, manifestLevel)
	}
	return newFetchPolicyAdapter(resolve, allow, tracker), nil
}

// orgAllowsNodejsCompat reports the organization's current
// failing closed (false, i.e. compat.nodejs is disabled) if the setting
// can't be loaded for any reason -- a missing/corrupt org row should never
// silently grant a wider capability than intended.
func orgAllowsNodejsCompat(ctx context.Context, st store.Store) bool {
	org, err := st.Organizations().Get(ctx)
	if err != nil {
		return false
	}
	orgSet, err := settings.ParseOrg(org.Settings)
	if err != nil {
		return false
	}
	return orgSet.AllowNodejsCompat
}

// buildEnvBindings exposes the function's stored env vars as env.KEY
// static bindings, restricted to the keys the active version's manifest
// declares (store.EnvVar's doc comment: "Only keys also declared in the
// active version's manifest are exposed at runtime"), decrypting each
// internal/crypto). A nil/empty envKey means encryption isn't configured
// at all -- buildEnvBindings fails closed (an error, not a silent
// plaintext passthrough) rather than exposing ciphertext to guest code.
func buildEnvBindings(ctx context.Context, st store.Store, functionID string, declared []string, envKey []byte) (map[string]cfworkers.Binding, error) {
	if len(declared) == 0 {
		return nil, nil
	}
	if len(envKey) == 0 {
		return nil, fmt.Errorf("invoke: env vars declared but no encryption key is configured (FUNCBOX_SESSION_SECRET)")
	}
	values, err := st.Functions().ListEnv(ctx, functionID)
	if err != nil {
		return nil, fmt.Errorf("invoke: list env vars for function %s: %w", functionID, err)
	}
	env := make(map[string]cfworkers.Binding, len(declared))
	for _, key := range declared {
		ciphertext, ok := values[key]
		if !ok {
			continue
		}
		plaintext, err := fcrypto.Decrypt(envKey, ciphertext)
		if err != nil {
			return nil, fmt.Errorf("invoke: decrypt env var %q for function %s: %w", key, functionID, err)
		}
		env[key] = runtime.StaticBinding(string(plaintext))
	}
	return env, nil
}
