package runtime

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goccy/go-spidermonkey/compat/cfworkers"
)

// These tests are checklist item 3: request-isolation behavior on a reused
// pooled instance. They confirm the compat/cfworkers library's own
// documented and tested behavior (request_lifecycle_test.go /
// cfworkers_test.go upstream) rather than re-implementing anything —
// funcbox's runtime package adds nothing to this behavior, so the tests
// exist to pin it as a funcbox-level assumption (03-runtime.md 3.2's
// "module-level state persists" claim) that would need updating if a future
// library version changes it.

// TestModuleStateSurvivesRequestReuse asserts module-level state DOES
// persist across requests on a reused instance — this is expected Workers
// semantics (03-runtime.md 3.2), not a bug, so this test exists to notice
// if it ever stops being true.
func TestModuleStateSurvivesRequestReuse(t *testing.T) {
	pool, err := cfworkers.NewPool(cfworkers.PoolConfig{
		Size: 1, // force the same instance to serve every request
		Source: `
			let counter = 0;
			export default {
				async fetch(req) {
					counter++;
					return new Response(String(counter));
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

	for i, want := range []string{"1", "2", "3"} {
		resp, err := http.Get(srv.URL + "/")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != want {
			t.Fatalf("request %d: counter = %q, want %q (module state did not persist)", i, body, want)
		}
	}
}

// TestTimerFromOneRequestDoesNotFireIntoNext asserts a setTimeout scheduled
// during request 1 does not leak into request 2's response: the pool's
// per-request reset (web.Web.ResetPerRequest + Loop().Reset(), called from
// cfworkers' serve()) clears leftover timers before the instance is reused.
func TestTimerFromOneRequestDoesNotFireIntoNext(t *testing.T) {
	pool, err := cfworkers.NewPool(cfworkers.PoolConfig{
		Size: 1,
		Source: `
			let flag = "unset";
			export default {
				async fetch(req) {
					const u = new URL(req.url);
					if (u.pathname === "/arm") {
						// Scheduled but never awaited: if request boundaries didn't
						// reset timers, this could fire during request 2 instead.
						setTimeout(() => { flag = "fired-late"; }, 0);
						return new Response("armed");
					}
					// Give any leaked timer every chance to fire before we check —
					// a real leak would show up here, not just theoretically exist.
					await new Promise((r) => setTimeout(r, 50));
					return new Response("flag=" + flag);
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

	resp1, err := http.Get(srv.URL + "/arm")
	if err != nil {
		t.Fatalf("request 1: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	if string(body1) != "armed" {
		t.Fatalf("request 1 body = %q, want armed", body1)
	}

	resp2, err := http.Get(srv.URL + "/check")
	if err != nil {
		t.Fatalf("request 2: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if string(body2) != "flag=unset" {
		t.Fatalf("request 2 body = %q, want flag=unset (request 1's timer leaked into request 2)", body2)
	}
}

// TestCryptoKeyPersistsAcrossRequestReuse asserts a SubtleCrypto key cached
// in a module global on request 1 keeps working on request 2 on the same
// pooled instance — cfworkers deliberately does NOT wipe the key table
// between requests (only web.Web.ResetKeys, which cfworkers never calls,
// does that); this is documented upstream
// (compat/cfworkers/request_lifecycle_test.go's
// TestCryptoKeyCachedAcrossRequests) and this test pins the same behavior
// as a funcbox-level assumption.
func TestCryptoKeyPersistsAcrossRequestReuse(t *testing.T) {
	pool, err := cfworkers.NewPool(cfworkers.PoolConfig{
		Size: 1,
		Source: `
			let cachedKey;
			export default {
				async fetch(req, env, ctx) {
					if (!cachedKey) {
						cachedKey = await crypto.subtle.importKey(
							"raw", new TextEncoder().encode("secret-key-material"),
							{ name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
					}
					try {
						const sig = await crypto.subtle.sign("HMAC", cachedKey, new TextEncoder().encode("payload"));
						return new Response("ok:" + new Uint8Array(sig).length);
					} catch (e) {
						return new Response("fail:" + String((e && e.message) || e), { status: 500 });
					}
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

	for i := 0; i < 3; i++ {
		resp, err := http.Get(srv.URL + "/")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || string(body) != "ok:32" {
			t.Fatalf("request %d: status=%d body=%q, want 200 ok:32 (cached key broke on reuse)", i, resp.StatusCode, body)
		}
	}
}

// TestInFlightFetchDoesNotCorruptNextRequest asserts a fire-and-forget
// fetch() left in flight (never awaited, no ctx.waitUntil) in request 1
// does not corrupt or hang request 2 on the same reused instance: the
// per-request reset cancels in-flight fetches at the request boundary
// (web.Web.ResetPerRequest's fetch.cancelInflight/closeOpenStreams, per its
// doc comment).
func TestInFlightFetchDoesNotCorruptNextRequest(t *testing.T) {
	// A slow upstream ensures the fire-and-forget fetch is still in flight
	// when request 1's handler returns, so the reset actually has
	// something in flight to cancel.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.Write([]byte("late"))
	}))
	t.Cleanup(upstream.Close)

	policy := allowlistPolicy{
		hosts: map[string]bool{"127.0.0.1": true},
		ips:   map[string]bool{"127.0.0.1": true},
	}

	pool, err := cfworkers.NewPool(cfworkers.PoolConfig{
		Size:   1,
		Config: buildFetchConfig(policy),
		Env:    map[string]cfworkers.Binding{"UP": StaticBinding(upstream.URL)},
		Source: `
			export default {
				async fetch(req, env, ctx) {
					const u = new URL(req.url);
					if (u.pathname === "/fire") {
						fetch(env.UP).then((r) => r.text()); // never awaited
						return new Response("fired");
					}
					return new Response("ok:" + u.pathname);
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

	resp1, err := http.Get(srv.URL + "/fire")
	if err != nil {
		t.Fatalf("request 1: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	if string(body1) != "fired" {
		t.Fatalf("request 1 body = %q, want fired", body1)
	}

	for i, path := range []string{"/r1", "/r2", "/r3"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("request %d (%s): %v", i, path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		want := "ok:" + path
		if resp.StatusCode != 200 || string(body) != want {
			t.Fatalf("request %d (%s): status=%d body=%q, want 200 %q", i, path, resp.StatusCode, body, want)
		}
	}
}
