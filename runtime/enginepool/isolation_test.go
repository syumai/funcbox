package enginepool

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	spidermonkey "github.com/goccy/go-spidermonkey"
)

// These tests are checklist item 3: request-isolation behavior on a reused
// pooled instance, ported from runtime/isolation_test.go onto
// enginepool.Pool directly.

// TestModuleStateSurvivesRequestReuse asserts module-level state DOES
// persist across requests on a reused instance — expected Workers-style
// semantics, not a bug.
func TestModuleStateSurvivesRequestReuse(t *testing.T) {
	loader := singleFileLoader(map[string]string{
		"index.js": `
			let counter = 0;
			export default {
				async fetch(req) {
					counter++;
					return new Response(String(counter));
				},
			};
		`,
	})
	pool, err := NewPool(Config{Size: 1, Entry: "index.js", Loader: loader})
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
// during request 1 does not leak into request 2's response.
func TestTimerFromOneRequestDoesNotFireIntoNext(t *testing.T) {
	loader := singleFileLoader(map[string]string{
		"index.js": `
			let flag = "unset";
			export default {
				async fetch(req) {
					const u = new URL(req.url);
					if (u.pathname === "/arm") {
						setTimeout(() => { flag = "fired-late"; }, 0);
						return new Response("armed");
					}
					await new Promise((r) => setTimeout(r, 50));
					return new Response("flag=" + flag);
				},
			};
		`,
	})
	pool, err := NewPool(Config{Size: 1, Entry: "index.js", Loader: loader})
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
// in a module global on request 1 keeps working on request 2.
func TestCryptoKeyPersistsAcrossRequestReuse(t *testing.T) {
	loader := singleFileLoader(map[string]string{
		"index.js": `
			let cachedKey;
			export default {
				async fetch(req) {
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
	pool, err := NewPool(Config{Size: 1, Entry: "index.js", Loader: loader})
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
// fetch() left in flight in request 1 does not corrupt or hang request 2 on
// the same reused instance.
func TestInFlightFetchDoesNotCorruptNextRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.Write([]byte("late"))
	}))
	t.Cleanup(upstream.Close)

	loader := singleFileLoader(map[string]string{
		"index.js": fmt.Sprintf(`
			const UP = %q;
			export default {
				async fetch(req) {
					const u = new URL(req.url);
					if (u.pathname === "/fire") {
						fetch(UP).then((r) => r.text()); // never awaited
						return new Response("fired");
					}
					return new Response("ok:" + u.pathname);
				},
			};
		`, upstream.URL),
	})

	pool, err := NewPool(Config{
		Size:   1,
		Entry:  "index.js",
		Loader: loader,
		Engine: spidermonkey.Config{
			Resolve: func(host string) bool { return host == "127.0.0.1" },
			Dial:    func(network, host, ip string, port int) bool { return ip == "127.0.0.1" },
		},
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
