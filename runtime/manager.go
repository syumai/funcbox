package runtime

import (
	"context"
	"net/http"
	"sync"

	"github.com/goccy/go-spidermonkey/compat/cfworkers"
)

// VersionSpec is what Manager needs to build the Pool for one function
// version: a cache Key (a function-version id) and a Build func that
// constructs (and warms — cfworkers.NewPool warms eagerly) the Pool from
// scratch. Build runs at most once per Key, lazily, on first HandlerFor
// call — this is the "cold start" 03-runtime.md 3.2 describes.
type VersionSpec struct {
	Key   string
	Build func(ctx context.Context) (*cfworkers.Pool, error)
}

// Manager maps a function-version key to its warmed cfworkers.Pool. This is
// mutex-guarded map, and Close-on-Invalidate. It does NOT implement the
// eventual LRU total-instance cap or 5-minute idle reaping described
// there — those are left as a TODO for the integration phase (see
type Manager struct {
	mu    sync.Mutex
	pools map[string]*managedPool
}

// managedPool holds one version's pool plus the state needed to let
// concurrent HandlerFor callers for the same key share a single in-flight
// Build instead of racing separate ones.
type managedPool struct {
	pool  *cfworkers.Pool
	err   error
	ready chan struct{} // closed once pool/err are set
}

// NewManager returns an empty Manager.
func NewManager() *Manager {
	return &Manager{pools: make(map[string]*managedPool)}
}

// HandlerFor returns the http.Handler (a *cfworkers.Pool) for spec.Key,
// calling spec.Build to create and warm it on first use. Concurrent callers
// racing the same key's first call all wait on that one Build rather than
// each starting their own pool.
func (m *Manager) HandlerFor(ctx context.Context, spec VersionSpec) (http.Handler, error) {
	m.mu.Lock()
	mp, ok := m.pools[spec.Key]
	if !ok {
		mp = &managedPool{ready: make(chan struct{})}
		m.pools[spec.Key] = mp
		m.mu.Unlock()
		mp.pool, mp.err = spec.Build(ctx)
		close(mp.ready)
	} else {
		m.mu.Unlock()
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

// Invalidate removes key's pool from the map (so the next HandlerFor call
// rebuilds it from scratch) and closes the old one in the background.
// Pool.Close is a graceful drain — in-flight requests on the old pool keep
// running to completion — so Invalidate itself never blocks on old traffic;
// it only blocks briefly on the map mutex.
//
// Per 03-runtime.md 3.2, this is the right response to a version switch, an
// env change (Env bindings are fixed at Pool-creation time), or a function
// deletion. A fetch-policy change does NOT need Invalidate: the Resolve/Dial
// hooks built in hooks.go close over whatever FetchPolicy the caller's
// spec.Build captures, so a caller that re-resolves the effective policy on
// every hook invocation (rather than baking one snapshot into the closure)
// gets live policy updates for free, without rebuilding the pool.
func (m *Manager) Invalidate(key string) {
	m.mu.Lock()
	mp, ok := m.pools[key]
	if ok {
		delete(m.pools, key)
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
