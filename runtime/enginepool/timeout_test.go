package enginepool

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// These tests pin the invariant the spec calls out explicitly: a
// deadline-bound ctx is the ONLY mechanism that frees a pool slot stuck in a
// runaway guest handler. Ported from the Phase 0 cfworkers-based checklist
// (formerly runtime/timeout_test.go) onto enginepool.Pool directly.

// TestTimeoutHandlerInterruptsInfiniteLoopAndFreesInstance drives a genuine
// `while (true) {}` guest handler behind http.TimeoutHandler and confirms:
// (1) the client gets a prompt timeout response, well under how long the
// guest loop would otherwise run, and (2) the pool instance is usable again
// shortly after — the runaway script does not permanently occupy the pool
// slot.
func TestTimeoutHandlerInterruptsInfiniteLoopAndFreesInstance(t *testing.T) {
	loader := singleFileLoader(map[string]string{
		"index.js": `
			export default {
				async fetch(req) {
					const u = new URL(req.url);
					if (u.pathname === "/spin") {
						while (true) { /* never returns on its own */ }
					}
					return new Response("fast");
				},
			};
		`,
	})
	pool, err := NewPool(Config{Size: 1, Entry: "index.js", Loader: loader})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	const handlerTimeout = 80 * time.Millisecond
	th := http.TimeoutHandler(pool, handlerTimeout, "handler timeout")
	srv := httptest.NewServer(th)
	t.Cleanup(srv.Close)

	start := time.Now()
	resp, err := http.Get(srv.URL + "/spin")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("GET /spin: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (TimeoutHandler)", resp.StatusCode)
	}
	if string(body) != "handler timeout" {
		t.Errorf("body = %q, want the TimeoutHandler message", body)
	}
	if elapsed > handlerTimeout+2*time.Second {
		t.Fatalf("client waited %v for a %v timeout — the infinite loop was not interrupted promptly", elapsed, handlerTimeout)
	}
	t.Logf("infinite-loop request: elapsed=%v (handlerTimeout=%v)", elapsed, handlerTimeout)

	deadline := time.Now().Add(2 * time.Second)
	var resp2 *http.Response
	var body2 []byte
	for time.Now().Before(deadline) {
		resp2, err = http.Get(srv.URL + "/fast")
		if err == nil {
			body2, _ = io.ReadAll(resp2.Body)
			resp2.Body.Close()
			if resp2.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if resp2 == nil || resp2.StatusCode != http.StatusOK || string(body2) != "fast" {
		status := -1
		if resp2 != nil {
			status = resp2.StatusCode
		}
		t.Fatalf("follow-up request = %d %q, want 200 fast (instance should recover after the interrupted loop)", status, body2)
	}
}

// TestNoDeadlineCtxLeavesInfiniteLoopUninterrupted documents the flip side: a
// request context with no deadline gives the watchdog nothing to fire on, so
// the pool slot stays stuck for the process's life. Verified indirectly: a
// concurrent request against the same Size:1 pool, with its own short
// deadline, must fail to acquire the never-released worker.
func TestNoDeadlineCtxLeavesInfiniteLoopUninterrupted(t *testing.T) {
	loader := singleFileLoader(map[string]string{
		"index.js": `
			export default {
				async fetch(req) {
					const u = new URL(req.url);
					if (u.pathname === "/spin") {
						while (true) { /* never returns; caller gives no deadline */ }
					}
					return new Response("fast");
				},
			};
		`,
	})
	pool, err := NewPool(Config{Size: 1, Entry: "index.js", Loader: loader})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	// No pool.Close() cleanup: the stuck goroutine holds a busy instance for
	// the rest of the process's life. Deliberate, contained leak for a
	// single spike test.

	go func() {
		req := httptest.NewRequest(http.MethodGet, "/spin", nil)
		rec := httptest.NewRecorder()
		pool.ServeHTTP(rec, req) // never returns
	}()

	time.Sleep(100 * time.Millisecond)

	th := http.TimeoutHandler(pool, 150*time.Millisecond, "no worker available")
	srv := httptest.NewServer(th)
	t.Cleanup(srv.Close)

	respB, err := http.Get(srv.URL + "/fast")
	if err != nil {
		t.Fatalf("GET /fast: %v", err)
	}
	bodyB, _ := io.ReadAll(respB.Body)
	respB.Body.Close()
	if respB.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body=%q, want 503 (the only instance should still be stuck in the undeadlined loop)", respB.StatusCode, bodyB)
	}
}
