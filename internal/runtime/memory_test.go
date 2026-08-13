package runtime

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	spidermonkey "github.com/goccy/go-spidermonkey"
	"github.com/goccy/go-spidermonkey/compat/cfworkers"
)

// These tests are checklist item 5: MaxMemoryBytes. A guest that allocates
// unboundedly must abort rather than take down the host process; the
// question this item asks is HOW that surfaces through ServeHTTP, and
// whether a Manager can detect it well enough to recycle the pool.

// TestMaxMemoryBytesAbortSurfacesAsWorkerError confirms an unbounded
// allocation aborts the guest and the abort surfaces through ServeHTTP as
// an ordinary-looking 500 with a "worker error: ..." body — the SAME shape
// as any other uncaught guest exception (compat/cfworkers/js/glue.js's
// __cfw_run catches everything, OOM included, into state.result.error).
// There is no distinct HTTP status or header marking this as a
// memory-specific failure; a Manager that wants to react specifically to
// OOM (as opposed to any other guest error) has to pattern-match the
// message text, which is a real limitation - see the finding below.
func TestMaxMemoryBytesAbortSurfacesAsWorkerError(t *testing.T) {
	pool, err := cfworkers.NewPool(cfworkers.PoolConfig{
		Size: 1,
		Config: spidermonkey.Config{
			MaxMemoryBytes: 64 << 20, // small cap so the test is fast, but enough to boot the interpreter
		},
		Source: `
			export default {
				async fetch(req) {
					// Grow an array of ever-larger buffers until the engine's
					// linear memory is exhausted. try/catch is pointless against
					// the engine's OOM (it is a guest-visible throw caught by the
					// glue's own .catch, not something we need to catch here) but
					// keep it simple: just let it throw.
					let chunks = [];
					for (let i = 0; i < 100000; i++) {
						chunks.push(new Uint8Array(4 * 1024 * 1024));
					}
					return new Response("should never get here: " + chunks.length);
				},
			};
		`,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	srv := httptest.NewServer(pool)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d body=%q, want 500 (worker error path)", resp.StatusCode, body)
	}
	if !strings.HasPrefix(string(body), "worker error:") {
		t.Fatalf("body = %q, want the generic \"worker error: ...\" prefix cfworkers uses for any uncaught guest throw", body)
	}
	t.Logf("OOM error body: %q", body)
}

// TestInstanceSurvivesAfterMaxMemoryAbort is the Manager-design-relevant
// half of item 5: once an instance has hit its MaxMemoryBytes ceiling and
// "spent" itself (config.go's own wording), is it still usable for a
// SUBSEQUENT, much smaller request on the same pooled instance? Linear
// memory never shrinks (config.go: "Zero means the default... Hitting it
// aborts the guest... the instance is spent"), so if the ceiling was
// actually reached (not just a large-but-recoverable allocation that GC'd
// away), a later normal-sized allocation on the SAME instance could keep
// failing too - a poisoned instance that ordinary error handling won't
// distinguish from a one-off failure.
func TestInstanceSurvivesAfterMaxMemoryAbort(t *testing.T) {
	pool, err := cfworkers.NewPool(cfworkers.PoolConfig{
		Size: 1, // force reuse of the exact instance that just hit the ceiling
		Config: spidermonkey.Config{
			MaxMemoryBytes: 64 << 20,
		},
		Source: `
			export default {
				async fetch(req) {
					const u = new URL(req.url);
					if (u.pathname === "/blow") {
						let chunks = [];
						for (let i = 0; i < 100000; i++) {
							chunks.push(new Uint8Array(4 * 1024 * 1024));
						}
						return new Response("unreachable");
					}
					return new Response("still alive");
				},
			};
		`,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	srv := httptest.NewServer(pool)
	t.Cleanup(srv.Close)

	resp1, err := http.Get(srv.URL + "/blow")
	if err != nil {
		t.Fatalf("GET /blow: %v", err)
	}
	io.Copy(io.Discard, resp1.Body)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusInternalServerError {
		t.Fatalf("first request status = %d, want 500", resp1.StatusCode)
	}

	resp2, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET / (post-OOM): %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	t.Logf("post-OOM request: status=%d body=%q", resp2.StatusCode, body2)
	// Deliberately NOT asserting success here: this test's job is to
	// OBSERVE and document the actual behavior for the findings doc, not
	// to assume it. See tmp/phase0-findings.md item 5 for what was
	// observed and what it means for the Manager's recycling policy.
}
