package runtime

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goccy/go-spidermonkey/compat/cfworkers"
)

// These tests are checklist item 4: wrap the pool in http.TimeoutHandler and
// run a guest infinite loop — does the client get a prompt timeout, and is
// the pool instance healthy (reusable) afterward?
//
// KEY FINDING, corrected from an initial (wrong) assumption while writing
// this test — see tmp/phase0-findings.md item 4 for the full writeup:
//
// cfworkers' glue always kicks the guest fetch handler through
// `Promise.resolve().then(() => handler.fetch(...))` (compat/cfworkers/js/
// glue.js's __cfw_run), NOT a direct synchronous call. So
// worker.serve's `wk.run.Call(reqObj)` (a plain, non-ctx-aware
// *spidermonkey.Object.Call) only ever SCHEDULES that microtask and returns
// immediately; the guest handler's body — including a `while (true) {}` —
// actually executes later, while `wk.web.Loop().RunUntil(ctx, stop)` drains
// the job queue. RunUntil IS ctx-aware, and go-spidermonkey's job-draining
// primitive arms the same watchdog-interrupt mechanism Eval(ctx, ...) and
// Agents.Interrupt use (internal/spidermonkey.go's "Interruption support":
// an uncatchable, engine-level interrupt that can abort a script mid-loop
// without corrupting the interpreter). The upshot: as long as the request
// context passed to Pool.ServeHTTP actually carries a deadline (http.
// TimeoutHandler, or any ctx with a deadline/cancellation), a runaway guest
// handler — even a bare `while (true) {}` with no await — gets interrupted
// at that deadline, the pool slot is released, and the instance is USABLE
// AGAIN immediately, not stuck. This is a materially better result than
// "http.TimeoutHandler frees the client but the goroutine (and pool slot)
// leaks forever", and it validates 03-runtime.md 3.3's prescription
// (wrap ServeHTTP in a deadline-bound ctx) as sufficient for this failure
// mode, not just a client-side mitigation.
//
// Caveat: this protection lives entirely in the CALLER supplying a
// deadline-bound ctx. A caller that invokes Pool.ServeHTTP with a request
// whose context has no deadline (e.g. forgetting the http.TimeoutHandler
// wrap) gets no interruption at all — the instance would then be stuck for
// as long as the guest loop runs, i.e. forever for a true infinite loop.
// funcbox's server MUST always wrap function invocation in a deadline-bound
// ctx; there is no other backstop.

// TestTimeoutHandlerInterruptsInfiniteLoopAndFreesInstance drives a genuine
// `while (true) {}` guest handler behind http.TimeoutHandler and confirms:
// (1) the client gets a prompt timeout response, well under how long the
// guest loop would otherwise run, and (2) the pool instance is usable again
// shortly after — the runaway script does not permanently occupy the pool
// slot.
func TestTimeoutHandlerInterruptsInfiniteLoopAndFreesInstance(t *testing.T) {
	pool, err := cfworkers.NewPool(cfworkers.PoolConfig{
		Size: 1, // one instance: proves recovery, not just "another one covered for it"
		Source: `
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
	// Generous upper bound: the client must come back close to
	// handlerTimeout, not "never" (there is no other clock in this test
	// that would ever end the loop).
	if elapsed > handlerTimeout+2*time.Second {
		t.Fatalf("client waited %v for a %v timeout — the infinite loop was not interrupted promptly", elapsed, handlerTimeout)
	}
	t.Logf("infinite-loop request: elapsed=%v (handlerTimeout=%v)", elapsed, handlerTimeout)

	// Give the interrupted instance a brief moment to unwind (the interrupt
	// fires inside RunUntil; the goroutine still needs to propagate the
	// error and return the worker to the pool channel) and confirm it is
	// fully usable again — not merely "not crashed", but actually able to
	// serve a normal request correctly.
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

// TestNoDeadlineCtxLeavesInfiniteLoopUninterrupted documents the flip side
// of the above finding: calling Pool.ServeHTTP directly with a request
// whose context carries NO deadline gives the watchdog nothing to fire on,
// so an infinite loop is never interrupted and the pool slot is gone for
// the lifetime of the test process. To keep the test suite finite, this is
// verified INDIRECTLY: a concurrent request to the same Size:1 pool, given
// a short ctx of its own, must time out waiting for the (never-released)
// worker — proving the slot really is stuck, not just briefly busy.
func TestNoDeadlineCtxLeavesInfiniteLoopUninterrupted(t *testing.T) {
	pool, err := cfworkers.NewPool(cfworkers.PoolConfig{
		Size: 1,
		Source: `
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
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	// No pool.Close() cleanup: the stuck goroutine holds a busy instance for
	// the rest of the process's life, which Close (a graceful, bounded
	// drain) would just block on. This is a deliberate, contained leak for
	// a single spike test.

	// Request A: served directly through the plain pool (no TimeoutHandler,
	// no ctx deadline of any kind) — the request context here is
	// *httptest.ResponseRecorder-backed and never cancelled, exactly what a
	// caller who forgot to wrap ServeHTTP would produce.
	go func() {
		req := httptest.NewRequest(http.MethodGet, "/spin", nil)
		rec := httptest.NewRecorder()
		pool.ServeHTTP(rec, req) // never returns
	}()

	// Give A a moment to actually check out the only worker.
	time.Sleep(100 * time.Millisecond)

	// Request B: a short-deadline ctx against the SAME pool must fail to
	// acquire a worker, proving A's instance was never released.
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
