package runtime

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/goccy/go-spidermonkey/compat/cfworkers"
)

// fakePool returns a distinct, unwarmed *cfworkers.Pool. Its zero value has
// size 0, so Close() loops zero times and returns immediately — no real
// spidermonkey engine startup, which keeps the pure LRU-bookkeeping tests
// in this file fast. Pointer identity is all these tests need: they never
// serve a request through it.
func fakePool() *cfworkers.Pool {
	return &cfworkers.Pool{}
}

// countingSpec returns a VersionSpec whose Build increments *builds each
// time it actually runs (a cache miss / post-eviction rebuild), and always
// succeeds with a fresh fakePool().
func countingSpec(key string, builds *int, mu *sync.Mutex) VersionSpec {
	return VersionSpec{
		Key: key,
		Build: func(context.Context) (*cfworkers.Pool, error) {
			mu.Lock()
			*builds++
			mu.Unlock()
			return fakePool(), nil
		},
	}
}

func TestManager_UnlimitedByDefaultNeverEvicts(t *testing.T) {
	m := NewManager() // no WithMaxPools: cap disabled
	var mu sync.Mutex
	builds := 0
	var evicted []string
	m.onEvict = func(key string) { mu.Lock(); evicted = append(evicted, key); mu.Unlock() }

	ctx := context.Background()
	for i := 0; i < 50; i++ {
		key := string(rune('a' + i%26))
		if _, err := m.HandlerFor(ctx, countingSpec(key, &builds, &mu)); err != nil {
			t.Fatalf("HandlerFor(%q): %v", key, err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(evicted) != 0 {
		t.Fatalf("evicted = %v, want none (unlimited cap)", evicted)
	}
	if len(m.pools) != 26 {
		t.Fatalf("len(m.pools) = %d, want 26 (every distinct key still tracked)", len(m.pools))
	}
}

func TestManager_EvictsLeastRecentlyUsedOverCap(t *testing.T) {
	m := NewManager(WithMaxPools(2))
	var mu sync.Mutex
	builds := 0
	evictedCh := make(chan string, 10)
	m.onEvict = func(key string) { evictedCh <- key }

	ctx := context.Background()
	mustHandler := func(key string) {
		t.Helper()
		if _, err := m.HandlerFor(ctx, countingSpec(key, &builds, &mu)); err != nil {
			t.Fatalf("HandlerFor(%q): %v", key, err)
		}
	}

	mustHandler("a")
	mustHandler("b")
	// Cap is 2 and both a, b are tracked; inserting c must evict a (the
	// least-recently-used: a was accessed before b, and neither was
	// touched again since).
	mustHandler("c")

	select {
	case key := <-evictedCh:
		if key != "a" {
			t.Fatalf("evicted key = %q, want %q", key, "a")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for eviction")
	}

	m.mu.Lock()
	_, aTracked := m.pools["a"]
	_, bTracked := m.pools["b"]
	_, cTracked := m.pools["c"]
	poolCount := len(m.pools)
	m.mu.Unlock()
	if aTracked {
		t.Error("a is still tracked, want evicted")
	}
	if !bTracked || !cTracked {
		t.Errorf("b tracked=%v c tracked=%v, want both true", bTracked, cTracked)
	}
	if poolCount != 2 {
		t.Fatalf("len(m.pools) = %d, want 2 (cap)", poolCount)
	}

	// Accessing "a" again must rebuild it (a genuine cold start), proving
	// eviction actually dropped it rather than merely reordering it.
	mu.Lock()
	before := builds
	mu.Unlock()
	mustHandler("a")
	mu.Lock()
	after := builds
	mu.Unlock()
	if after != before+1 {
		t.Fatalf("builds after re-accessing evicted key = %d, want %d (a fresh Build)", after, before+1)
	}
}

func TestManager_TouchOnAccessUpdatesRecency(t *testing.T) {
	m := NewManager(WithMaxPools(2))
	var mu sync.Mutex
	builds := 0
	evictedCh := make(chan string, 10)
	m.onEvict = func(key string) { evictedCh <- key }

	ctx := context.Background()
	mustHandler := func(key string) {
		t.Helper()
		if _, err := m.HandlerFor(ctx, countingSpec(key, &builds, &mu)); err != nil {
			t.Fatalf("HandlerFor(%q): %v", key, err)
		}
	}

	mustHandler("a")
	mustHandler("b")
	// Touch a again — it becomes the most-recently-used, so b is now the
	// least-recently-used entry.
	mustHandler("a")
	mustHandler("c")

	select {
	case key := <-evictedCh:
		if key != "b" {
			t.Fatalf("evicted key = %q, want %q (touching a should have protected it)", key, "b")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for eviction")
	}

	m.mu.Lock()
	_, aTracked := m.pools["a"]
	_, bTracked := m.pools["b"]
	_, cTracked := m.pools["c"]
	m.mu.Unlock()
	if !aTracked || bTracked || !cTracked {
		t.Fatalf("a tracked=%v b tracked=%v c tracked=%v, want true/false/true", aTracked, bTracked, cTracked)
	}
}

func TestManager_InvalidateRemovesLRUEntryToo(t *testing.T) {
	m := NewManager(WithMaxPools(2))
	var mu sync.Mutex
	builds := 0
	evictedCh := make(chan string, 10)
	m.onEvict = func(key string) { evictedCh <- key }

	ctx := context.Background()
	mustHandler := func(key string) {
		t.Helper()
		if _, err := m.HandlerFor(ctx, countingSpec(key, &builds, &mu)); err != nil {
			t.Fatalf("HandlerFor(%q): %v", key, err)
		}
	}

	mustHandler("a")
	mustHandler("b")
	m.Invalidate("a") // drops a from both the map and the LRU list

	m.mu.Lock()
	_, aTracked := m.pools["a"]
	lruLen := m.lru.Len()
	m.mu.Unlock()
	if aTracked {
		t.Error("a is still tracked after Invalidate")
	}
	if lruLen != 1 {
		t.Fatalf("lru.Len() after Invalidate = %d, want 1 (stale nodes must not linger)", lruLen)
	}

	// Refill up to and past the cap: c brings the count back to 2 (b, c),
	// d pushes it to 3 and must evict b -- the actual least-recently-used
	// survivor, not a stale reference to the already-invalidated a.
	mustHandler("c")
	mustHandler("d")

	select {
	case key := <-evictedCh:
		if key != "b" {
			t.Fatalf("evicted key = %q, want %q", key, "b")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for eviction")
	}

	// Invalidate itself must never fire the LRU eviction hook -- it's a
	// caller-driven removal, counted separately from capacity eviction.
	select {
	case key := <-evictedCh:
		t.Fatalf("unexpected second eviction %q (Invalidate must not call onEvict)", key)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestManager_GracefulEvictionOfInFlightRequest is the one test in this
// suite that uses REAL cfworkers pools end-to-end: it proves that a request
// already in flight against a pool that gets LRU-evicted mid-request still
// completes successfully, because cfworkers.Pool.Close() is a graceful
// drain (see its doc comment) and Manager's eviction runs on a background
// goroutine rather than closing the pool out from under the live request.
func TestManager_GracefulEvictionOfInFlightRequest(t *testing.T) {
	buildSlowPool := func(context.Context) (*cfworkers.Pool, error) {
		return cfworkers.NewPool(cfworkers.PoolConfig{
			Size: 1, // one instance: a real "in flight, no spare capacity" scenario
			Source: `
				export default {
					async fetch(req) {
						await new Promise((r) => setTimeout(r, 300));
						return new Response("slow done");
					},
				};
			`,
		})
	}
	buildFastPool := func(context.Context) (*cfworkers.Pool, error) {
		return cfworkers.NewPool(cfworkers.PoolConfig{
			Size: 1,
			Source: `
				export default {
					async fetch(req) {
						return new Response("fast done");
					},
				};
			`,
		})
	}

	m := NewManager(WithMaxPools(1))
	evictedCh := make(chan string, 1)
	m.onEvict = func(key string) { evictedCh <- key }

	ctx := context.Background()
	handlerA, err := m.HandlerFor(ctx, VersionSpec{Key: "slow", Build: buildSlowPool})
	if err != nil {
		t.Fatalf("HandlerFor(slow): %v", err)
	}
	srvA := httptest.NewServer(handlerA)
	t.Cleanup(srvA.Close)

	// Start the slow, in-flight request against "slow"'s pool in the
	// background; it checks out the pool's one worker for ~300ms.
	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := http.Get(srvA.URL + "/")
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	// Give the request a moment to actually check the worker out before
	// triggering the eviction, so this genuinely exercises "in-flight",
	// not "not-yet-started".
	time.Sleep(50 * time.Millisecond)

	// Cap is 1, so building a second, different key evicts "slow" while its
	// request is still running. HandlerFor(fast) must return promptly --
	// well under the ~300ms the in-flight request needs to finish and
	// release "slow"'s only worker -- proving eviction's Close() runs on a
	// background goroutine rather than blocking this call on that drain.
	start := time.Now()
	if _, err := m.HandlerFor(ctx, VersionSpec{Key: "fast", Build: buildFastPool}); err != nil {
		t.Fatalf("HandlerFor(fast): %v", err)
	}
	if elapsed := time.Since(start); elapsed > 150*time.Millisecond {
		t.Fatalf("HandlerFor(fast) took %v, want well under the in-flight request's ~300ms (eviction must not block the caller)", elapsed)
	}

	select {
	case key := <-evictedCh:
		if key != "slow" {
			t.Fatalf("evicted key = %q, want %q", key, "slow")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for eviction of the in-flight pool's key")
	}

	// The in-flight request must still complete successfully -- eviction's
	// Close() call must have waited for it rather than aborting it.
	select {
	case err := <-errCh:
		t.Fatalf("in-flight request against the evicted pool failed: %v", err)
	case resp := <-respCh:
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "slow done" {
			t.Fatalf("in-flight request = %d %q, want 200 \"slow done\"", resp.StatusCode, body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight request never completed")
	}
}
