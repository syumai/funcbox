package enginepool

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	spidermonkey "github.com/goccy/go-spidermonkey"
)

// These tests are the OOM-invariant half of the Phase 0 checklist, ported
// onto enginepool.Pool directly (formerly runtime/memory_test.go): an
// unbounded allocation must abort the guest, and that abort must surface
// through ServeHTTP as a "worker error: ..." 500 — the exact shape a caller
// (server/internal/invoke) string-matches for "out of memory" to decide
// whether to Invalidate the pool. This shape must NOT change.

func TestMaxMemoryBytesAbortSurfacesAsWorkerError(t *testing.T) {
	loader := singleFileLoader(map[string]string{
		"index.js": `
			export default {
				async fetch(req) {
					let chunks = [];
					for (let i = 0; i < 100000; i++) {
						chunks.push(new Uint8Array(4 * 1024 * 1024));
					}
					return new Response("should never get here: " + chunks.length);
				},
			};
		`,
	})
	pool, err := NewPool(Config{
		Size:   1,
		Entry:  "index.js",
		Loader: loader,
		Engine: spidermonkey.Config{MaxMemoryBytes: 64 << 20},
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
		t.Fatalf("body = %q, want the generic \"worker error: ...\" prefix", body)
	}
	t.Logf("OOM error body: %q", body)
}

// TestInstanceSurvivesAfterMaxMemoryAbort observes (does not assert success
// of) a follow-up request on the same spent instance — see the original
// finding this documents in the pre-migration runtime package.
func TestInstanceSurvivesAfterMaxMemoryAbort(t *testing.T) {
	loader := singleFileLoader(map[string]string{
		"index.js": `
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
	pool, err := NewPool(Config{
		Size:   1,
		Entry:  "index.js",
		Loader: loader,
		Engine: spidermonkey.Config{MaxMemoryBytes: 64 << 20},
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
}
