package runtime

import (
	"container/list"
	"context"
	"net/http"
	"sync"

	"github.com/syumai/funcbox/runtime/enginepool"
)

// VersionSpec is what Manager needs to build the Pool for one function
// version: a cache Key (a function-version id) and a Build func that
// constructs (and warms — enginepool.NewPool warms eagerly) the Pool from
// scratch. Build runs at most once per Key, lazily, on first HandlerFor
// call — this is the "cold start" 03-runtime.md 3.2 describes.
type VersionSpec struct {
	Key   string
	Build func(ctx context.Context) (*enginepool.Pool, error)
}

// Manager maps a function-version key to its warmed enginepool.Pool. This is
// a mutex-guarded map, and Close-on-Invalidate, plus an optional LRU cap
// (WithMaxPools) on the number of warm pools it keeps at once: every
// HandlerFor call touches (moves to most-recently-used) the accessed
// entry, and inserting a new entry past the cap evicts and closes the
// least-recently-used one. This is deliberately independent of (and meant
// to coexist with) idle-based reaping some callers may layer on top: idle
// reaping is time-based (a pool unused for N minutes is dropped), the LRU
// cap here is count-based (the Nth-oldest pool is dropped the moment a new
// one is needed) — whichever fires first wins, and neither needs to know
// about the other since both just call the same Invalidate-shaped
// remove-from-map-then-Close path.
type Manager struct {
	mu    sync.Mutex
	pools map[string]*managedPool

	// lru orders live pools by recency of HandlerFor access,
	// most-recently-used at the front. Populated and consulted only when
	// maxPools > 0 — an unlimited Manager pays no LRU bookkeeping cost.
	lru *list.List

	// maxPools caps the number of warm pools Manager keeps at once. Zero
	// (the default) means unlimited. See WithMaxPools.
	maxPools int

	// onEvict, if non-nil, is called with the key of every pool the LRU
	// cap (not Invalidate — see its doc comment) evicts. This is how
	// server/internal/metrics's eviction counter gets wired up without
	// runtime importing prometheus (see the root module's 3-dependency
	// rule, enforced by cmd/funcbox/dep_separation_test.go). Called from a
	// background goroutine, never while m.mu is held.
	onEvict func(key string)
}

// managedPool holds one version's pool plus the state needed to let
// concurrent HandlerFor callers for the same key share a single in-flight
// Build instead of racing separate ones.
type managedPool struct {
	key   string
	pool  *enginepool.Pool
	err   error
	ready chan struct{} // closed once pool/err are set
	elem  *list.Element // this entry's node in Manager.lru; nil until first touched
}

// ManagerOption configures a Manager constructed by NewManager.
type ManagerOption func(*Manager)

// WithMaxPools caps the number of warm pools Manager keeps at once (an LRU
// cap over function-version keys, touched on every HandlerFor call). Once
// the cap is reached, inserting a pool for a new key evicts and closes
// (gracefully — see enginepool.Pool.Close) the least-recently-accessed
// pool. n <= 0 means unlimited, which is also NewManager's default when
// this option is omitted.
func WithMaxPools(n int) ManagerOption {
	return func(m *Manager) { m.maxPools = n }
}

// WithEvictHook registers fn to be called, with the evicted function-version
// key, every time the LRU cap (WithMaxPools) evicts a pool to make room for
// another. It is NOT called for Invalidate, which is a caller-driven
// removal (a redeploy or env change), not a capacity-driven eviction — the
// two are counted separately by design. fn is called from a background
// goroutine after the evicted pool's Close has completed, never while
// Manager's internal mutex is held.
func WithEvictHook(fn func(key string)) ManagerOption {
	return func(m *Manager) { m.onEvict = fn }
}

// NewManager returns an empty Manager, configured by opts.
func NewManager(opts ...ManagerOption) *Manager {
	m := &Manager{pools: make(map[string]*managedPool), lru: list.New()}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// HandlerFor returns the http.Handler (a *enginepool.Pool) for spec.Key,
// calling spec.Build to create and warm it on first use. Concurrent callers
// racing the same key's first call all wait on that one Build rather than
// each starting their own pool.
//
// Every call touches spec.Key in the LRU (see touchLocked) when a cap is
// configured. A cache miss that pushes the tracked-pool count over the cap
// evicts the least-recently-used entry; that entry's Close (and the
// WithEvictHook callback) run on a background goroutine, exactly like
// Invalidate, so HandlerFor itself never blocks on old traffic draining.
func (m *Manager) HandlerFor(ctx context.Context, spec VersionSpec) (http.Handler, error) {
	m.mu.Lock()
	mp, ok := m.pools[spec.Key]
	if ok {
		m.touchLocked(mp)
		m.mu.Unlock()
	} else {
		mp = &managedPool{key: spec.Key, ready: make(chan struct{})}
		m.pools[spec.Key] = mp
		m.touchLocked(mp)
		evictKey, evictMP := m.evictIfOverCapLocked()
		m.mu.Unlock()
		if evictMP != nil {
			m.evictAsync(evictKey, evictMP)
		}
		mp.pool, mp.err = spec.Build(ctx)
		close(mp.ready)
	}

	select {
	case <-mp.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if mp.err != nil {
		return nil, mp.err
	}
	return mp.pool, nil
}

// touchLocked records mp as the most-recently-used pool for the LRU cap.
// Must be called with m.mu held. A no-op when the cap is disabled
// (maxPools <= 0), so an unlimited Manager never pays for list bookkeeping
// it has no use for.
func (m *Manager) touchLocked(mp *managedPool) {
	if m.maxPools <= 0 {
		return
	}
	if mp.elem != nil {
		m.lru.MoveToFront(mp.elem)
		return
	}
	mp.elem = m.lru.PushFront(mp)
}

// evictIfOverCapLocked removes the least-recently-used pool from m.pools
// and m.lru if the cap is currently exceeded, returning it for the caller
// to close outside the lock. Must be called with m.mu held, right after
// inserting a new entry — the only place the tracked count can grow past
// the cap, since touching an already-tracked entry never changes it.
// Returns ("", nil) if nothing needs evicting (including when the cap is
// disabled).
func (m *Manager) evictIfOverCapLocked() (string, *managedPool) {
	if m.maxPools <= 0 || m.lru.Len() <= m.maxPools {
		return "", nil
	}
	back := m.lru.Back()
	victim := back.Value.(*managedPool)
	m.lru.Remove(back)
	delete(m.pools, victim.key)
	return victim.key, victim
}

// evictAsync closes victim's pool in the background, once its Build (if
// still in flight — a pool can be evicted before its own first build
// completes, under a very small cap and a burst of distinct new keys)
// finishes, then reports the eviction via onEvict. Mirrors Invalidate's
// async close so LRU cap enforcement inside HandlerFor never blocks on old
// traffic; enginepool.Pool.Close itself is graceful (in-flight requests on
// the evicted pool keep running to completion).
func (m *Manager) evictAsync(key string, victim *managedPool) {
	go func() {
		<-victim.ready
		if victim.pool != nil {
			victim.pool.Close()
		}
		if m.onEvict != nil {
			m.onEvict(key)
		}
	}()
}

// Invalidate removes key's pool from the map and the LRU list (so the next
// HandlerFor call rebuilds it from scratch) and closes the old one in the
// background. Pool.Close is a graceful drain — in-flight requests on the
// old pool keep running to completion — so Invalidate itself never blocks
// on old traffic; it only blocks briefly on the map mutex.
//
// Per 03-runtime.md 3.2, this is the right response to a version switch, an
// env change (Env bindings are fixed at Pool-creation time), or a function
// deletion. A fetch-policy change does NOT need Invalidate: the Resolve/Dial
// hooks built in hooks.go close over whatever FetchPolicy the caller's
// spec.Build captures, so a caller that re-resolves the effective policy on
// every hook invocation (rather than baking one snapshot into the closure)
// gets live policy updates for free, without rebuilding the pool.
//
// Invalidate does NOT call the WithEvictHook callback: that hook counts LRU
// capacity evictions specifically, and a version switch/env change/deletion
// is a different, caller-driven kind of removal.
func (m *Manager) Invalidate(key string) {
	m.mu.Lock()
	mp, ok := m.pools[key]
	if ok {
		delete(m.pools, key)
		if mp.elem != nil {
			m.lru.Remove(mp.elem)
		}
	}
	m.mu.Unlock()
	if !ok {
		return
	}
	go func() {
		<-mp.ready
		if mp.pool != nil {
			mp.pool.Close()
		}
	}()
}

// Close synchronously shuts down every currently-tracked pool. Intended for
// process shutdown, unlike Invalidate (which is fire-and-forget so a single
// version switch never blocks on old traffic).
func (m *Manager) Close() error {
	m.mu.Lock()
	pools := m.pools
	m.pools = make(map[string]*managedPool)
	m.lru = list.New()
	m.mu.Unlock()

	var firstErr error
	for _, mp := range pools {
		<-mp.ready
		if mp.pool == nil {
			continue
		}
		if err := mp.pool.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
