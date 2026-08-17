package enginepool

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	spidermonkey "github.com/goccy/go-spidermonkey"
)

// These tests exercise Config.NodeCompat: nodejs.Install wired into
// enginepool's own worker init, and the fix for the web.Install
// double-install trap documented in worker.go's newWorker (verified here by
// proving timers and await actually work — the double-install's symptom was
// exactly that they silently stopped).

// TestNodeCompatTimersAndAwaitWork is the double-install regression test:
// if web.Install ran twice, setTimeout/fetch/await would bind to an orphaned
// first event loop while RunUntil drives a different (second) one, and a
// handler awaiting a timer would simply hang until the loop goes idle
// without ever settling. A passing response here proves there is exactly
// one live event loop.
func TestNodeCompatTimersAndAwaitWork(t *testing.T) {
	fsys := fstest.MapFS{
		"index.js": &fstest.MapFile{Data: []byte(`
			export default {
				async fetch(req) {
					let fired = false;
					await new Promise((resolve) => setTimeout(() => { fired = true; resolve(); }, 20));
					return new Response(JSON.stringify({ fired }));
				},
			};
		`)},
	}
	pool, err := NewPool(Config{
		Size:       1,
		Entry:      "index.js",
		NodeCompat: true,
		Engine:     spidermonkey.Config{FS: fsys},
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
	if want := `{"fired":true}`; string(body) != want {
		t.Fatalf("body = %q, want %q (timers/await broken — double web.Install?)", body, want)
	}
}

// TestNodeCompatCoreModulesWork proves node:crypto and Buffer are reachable
// once NodeCompat installs the full node runtime.
func TestNodeCompatCoreModulesWork(t *testing.T) {
	fsys := fstest.MapFS{
		"index.js": &fstest.MapFile{Data: []byte(`
			import { createHash } from "node:crypto";
			export default {
				async fetch(req) {
					const buf = Buffer.from("hello");
					const hash = createHash("sha256").update(buf).digest("hex");
					return new Response(hash);
				},
			};
		`)},
	}
	pool, err := NewPool(Config{
		Size:       1,
		Entry:      "index.js",
		NodeCompat: true,
		Engine:     spidermonkey.Config{FS: fsys},
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
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" // sha256("hello")
	if string(body) != want {
		t.Fatalf("body = %q, want sha256(\"hello\") = %q", body, want)
	}
}

// TestNodeCompatFSIsReadOnly proves node:fs write calls fail (EROFS-shaped)
// against the bundle FS — funcbox never grants a function writable disk.
func TestNodeCompatFSIsReadOnly(t *testing.T) {
	fsys := fstest.MapFS{
		"index.js": &fstest.MapFile{Data: []byte(`
			import fs from "node:fs";
			export default {
				async fetch(req) {
					try {
						fs.writeFileSync("index.js", "nope");
						return new Response("wrote: should not happen", { status: 500 });
					} catch (e) {
						return new Response("denied:" + String((e && e.code) || e));
					}
				},
			};
		`)},
	}
	pool, err := NewPool(Config{
		Size:       1,
		Entry:      "index.js",
		NodeCompat: true,
		Engine:     spidermonkey.Config{FS: fsys},
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
	if !strings.HasPrefix(string(body), "denied:") {
		t.Fatalf("body = %q, want a denied: prefix (fs.writeFileSync must fail — read-only FS)", body)
	}
	t.Logf("write attempt result: %q", body)
}

// TestNodeCompatAsyncLocalStoragePerRequestIsolation proves ALS state set
// in one request does not leak into the next on the same reused instance —
// the general request-isolation invariant, specifically for Node's ALS.
func TestNodeCompatAsyncLocalStoragePerRequestIsolation(t *testing.T) {
	fsys := fstest.MapFS{
		"index.js": &fstest.MapFile{Data: []byte(`
			import { AsyncLocalStorage } from "node:async_hooks";
			const als = new AsyncLocalStorage();
			export default {
				async fetch(req) {
					const u = new URL(req.url);
					const id = u.searchParams.get("id");
					return als.run(id, async () => {
						await new Promise((r) => setTimeout(r, 5));
						return new Response("store=" + als.getStore());
					});
				},
			};
		`)},
	}
	pool, err := NewPool(Config{
		Size:       1, // force the SAME instance to serve every request
		Entry:      "index.js",
		NodeCompat: true,
		Engine:     spidermonkey.Config{FS: fsys},
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	srv := httptest.NewServer(pool)
	t.Cleanup(srv.Close)

	for _, id := range []string{"a", "b", "c"} {
		resp, err := http.Get(srv.URL + "/?id=" + id)
		if err != nil {
			t.Fatalf("request %s: %v", id, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		want := "store=" + id
		if string(body) != want {
			t.Fatalf("request %s: body = %q, want %q (ALS state leaked across requests)", id, body, want)
		}
	}
}

// TestNodeCompatAsyncLocalStorageConcurrentIsolation is the concurrency-
// pressure sibling of the sequential ALS isolation test: many goroutines,
// against a multi-instance pool, each set a distinct ALS value and must
// observe only their own — proving isolation holds under real concurrent
// load, not just across sequential reuse of one instance.
func TestNodeCompatAsyncLocalStorageConcurrentIsolation(t *testing.T) {
	fsys := fstest.MapFS{
		"index.js": &fstest.MapFile{Data: []byte(`
			import { AsyncLocalStorage } from "node:async_hooks";
			const als = new AsyncLocalStorage();
			export default {
				async fetch(req) {
					const u = new URL(req.url);
					const id = u.searchParams.get("id");
					return als.run(id, async () => {
						await new Promise((r) => setTimeout(r, 1 + Math.floor(Math.random() * 10)));
						return new Response("store=" + als.getStore());
					});
				},
			};
		`)},
	}
	pool, err := NewPool(Config{
		Size:       4,
		Entry:      "index.js",
		NodeCompat: true,
		Engine:     spidermonkey.Config{FS: fsys},
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	srv := httptest.NewServer(pool)
	t.Cleanup(srv.Close)

	const n = 40
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		id := "req-" + string(rune('A'+i%26)) + string(rune('0'+i/26))
		go func(id string) {
			resp, err := http.Get(srv.URL + "/?id=" + id)
			if err != nil {
				errCh <- err
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			want := "store=" + id
			if string(body) != want {
				errCh <- &staleALSError{got: string(body), want: want}
				return
			}
			errCh <- nil
		}(id)
	}
	for i := 0; i < n; i++ {
		if err := <-errCh; err != nil {
			t.Error(err)
		}
	}
}

type staleALSError struct{ got, want string }

func (e *staleALSError) Error() string {
	return "AsyncLocalStorage leaked across concurrent requests: got " + e.got + ", want " + e.want
}

// TestNodeCompatAsyncLocalStorageLostAcrossStreamedResponse documents a real
// gap, upstream in go-spidermonkey's compat/nodejs AsyncLocalStorage
// (runtime/enginepool does not fork or wrap that implementation): the store
// is a plain slot held for the duration of als.run(fn) — reset the instant
// fn's OWN return value settles (see go-spidermonkey's
// compat/nodejs/js/extras.js, and docs/engine-followups.md item 8 there,
// "async_hooks: a store cannot outlive the call that established it").
//
// That is exactly correct for the request-scoped `await`-everything-inside-
// run() pattern the two tests above cover. It breaks down for a distinct,
// also-common pattern: a function that runs INSIDE als.run() and constructs
// a ReadableStream (or pipes through a TransformStream) whose start/pull/
// transform callbacks read the store, then returns that stream SYNCHRONOUSLY
// — before it has been drained. The store is gone by the time anything
// later reads the stream, even though the stream itself was built while the
// store was active.
//
// This is not hypothetical: it is the literal shape of vinext's (and
// Next.js's) RSC rendering. vinext's own bundled request-context module
// does `asyncLocalStorageInstance.run(store, renderFn)` where renderFn
// returns `renderToReadableStream(...)` synchronously — the render, and any
// next/headers() / next/cookies() call inside it, happens later as the
// stream is pulled, by which point this slot has already been reset. That
// is the root cause of examples/vinext's `headers()`/`cookies()` failure —
// see that example's README "Known limitations" section.
//
// This test pins CURRENT (broken) behavior, the same way go-spidermonkey's
// own compat/nodejs/nextjs_flagship_test.go pins its "GET / = 500" case: so
// that if/when go-spidermonkey gains engine async-context hooks (the fix
// item 8 calls for) and this starts passing, it fails loudly here instead of
// silently — and examples/vinext/README.md's limitation note (and this
// comment) should be updated in the same change.
func TestNodeCompatAsyncLocalStorageLostAcrossStreamedResponse(t *testing.T) {
	fsys := fstest.MapFS{
		"index.js": &fstest.MapFile{Data: []byte(`
			import { AsyncLocalStorage } from "node:async_hooks";
			const als = new AsyncLocalStorage();
			export default {
				async fetch(req) {
					const u = new URL(req.url);
					const id = u.searchParams.get("id");
					// als.run()'s callback is NOT async and returns the Response
					// SYNCHRONOUSLY (no await inside run) -- exactly the
					// renderToReadableStream()-returns-synchronously shape.
					const resp = als.run(id, () => {
						const rs = new ReadableStream({
							pull(c) {
								c.enqueue(new TextEncoder().encode("store=" + als.getStore()));
								c.close();
							},
						});
						return new Response(rs);
					});
					// The stream is drained from OUTSIDE als.run()'s call stack --
					// this is where the store gets read, by pull() above.
					return resp;
				},
			};
		`)},
	}
	pool, err := NewPool(Config{
		Size:       1,
		Entry:      "index.js",
		NodeCompat: true,
		Engine:     spidermonkey.Config{FS: fsys},
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	srv := httptest.NewServer(pool)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/?id=should-be-visible")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// The CORRECT (Node-parity) answer would be "store=should-be-visible" --
	// verified against real Node in the investigation this test comes from.
	// go-spidermonkey's slot-based ALS instead reports "store=undefined"
	// because the slot was already reset by the time pull() ran. If this
	// starts failing, go-spidermonkey has fixed the gap: update this test's
	// expectation, remove the "known broken" framing here, and update
	// examples/vinext/README.md's limitation note.
	if want := "store=undefined"; string(body) != want {
		t.Fatalf("body = %q, want %q (go-spidermonkey's AsyncLocalStorage gap "+
			"for streamed responses appears to be fixed -- see this test's "+
			"doc comment for what to update)", body, want)
	}
}

// TestNodeCompatImportMetaEnvWorksForFirstPartyFiles proves the FS-level
// injection (nodecompat.go) populates import.meta.env for the entry module
// AND a first-party file it imports, under NodeCompat.
func TestNodeCompatImportMetaEnvWorksForFirstPartyFiles(t *testing.T) {
	fsys := fstest.MapFS{
		"index.js": &fstest.MapFile{Data: []byte(`
			import { childEnv } from "./child.js";
			export default {
				async fetch(req) {
					return new Response(JSON.stringify({ entry: import.meta.env, child: childEnv }));
				},
			};
		`)},
		"child.js": &fstest.MapFile{Data: []byte(`export const childEnv = import.meta.env;`)},
	}
	pool, err := NewPool(Config{
		Size:       1,
		Entry:      "index.js",
		NodeCompat: true,
		Engine:     spidermonkey.Config{FS: fsys},
		Env:        map[string]string{"MODE": "node"},
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
	want := `{"entry":{"MODE":"node"},"child":{"MODE":"node"}}`
	if string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}

// TestNodeCompatNetIsGatedByResolveDial proves node:net (and, by the same
// mechanism, node:http/node:tls) is gated by the SAME Engine.Resolve/Dial
// hooks as the Web fetch API — NodeCompat does not open a side door around
// the fetch allowlist.
func TestNodeCompatNetIsGatedByResolveDial(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "upstream data")
	}))
	t.Cleanup(upstream.Close)
	_, port, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	fsys := fstest.MapFS{
		"index.js": &fstest.MapFile{Data: []byte(`
			import net from "node:net";
			export default {
				async fetch(req) {
					const u = new URL(req.url);
					const port = Number(u.searchParams.get("port"));
					return new Promise((resolve) => {
						const sock = net.connect({ host: "127.0.0.1", port }, () => {
							sock.end();
							resolve(new Response("connected"));
						});
						sock.on("error", (e) => resolve(new Response("denied:" + String(e && e.message || e), { status: 502 })));
					});
				},
			};
		`)},
	}

	// Deny-everything: no Resolve/Dial hooks set at all (fail-closed default).
	poolDenied, err := NewPool(Config{
		Size: 1, Entry: "index.js", NodeCompat: true,
		Engine: spidermonkey.Config{FS: fsys},
	})
	if err != nil {
		t.Fatalf("NewPool (denied): %v", err)
	}
	t.Cleanup(func() { poolDenied.Close() })
	srvDenied := httptest.NewServer(poolDenied)
	t.Cleanup(srvDenied.Close)

	resp, err := http.Get(srvDenied.URL + "/?port=" + port)
	if err != nil {
		t.Fatalf("GET (denied): %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.HasPrefix(string(body), "denied:") {
		t.Fatalf("body = %q, want a denied: prefix (node:net must be gated by Dial, not open by default)", body)
	}

	// Allow-everything: Dial approves the exact loopback address.
	poolAllowed, err := NewPool(Config{
		Size: 1, Entry: "index.js", NodeCompat: true,
		Engine: spidermonkey.Config{
			FS:      fsys,
			Resolve: func(host string) bool { return true },
			Dial:    func(network, host, ip string, port int) bool { return true },
		},
	})
	if err != nil {
		t.Fatalf("NewPool (allowed): %v", err)
	}
	t.Cleanup(func() { poolAllowed.Close() })
	srvAllowed := httptest.NewServer(poolAllowed)
	t.Cleanup(srvAllowed.Close)

	resp2, err := http.Get(srvAllowed.URL + "/?port=" + port)
	if err != nil {
		t.Fatalf("GET (allowed): %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if string(body2) != "connected" {
		t.Fatalf("body = %q, want \"connected\" (an allowed Dial must let node:net connect)", body2)
	}
}

// TestNodeCompatEnvInjectionNeverTouchesNodeModules proves the FS wrap
// leaves node_modules/ content byte-for-byte untouched — dependency
// CJS/JSON files must never risk corruption from the injection.
func TestNodeCompatEnvInjectionNeverTouchesNodeModules(t *testing.T) {
	const pkgSrc = `module.exports.greet = function(name) { return "hi " + name; };`
	fsys := fstest.MapFS{
		"index.js": &fstest.MapFile{Data: []byte(`
			import pkg from "deppkg";
			export default {
				async fetch(req) { return new Response(pkg.greet("world")); },
			};
		`)},
		"node_modules/deppkg/package.json": &fstest.MapFile{Data: []byte(`{"name":"deppkg","version":"1.0.0","main":"index.js"}`)},
		"node_modules/deppkg/index.js":     &fstest.MapFile{Data: []byte(pkgSrc)},
	}
	wrapped := wrapFSWithEnv(fsys)
	f, err := wrapped.Open("node_modules/deppkg/index.js")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	data, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(data) != pkgSrc {
		t.Fatalf("node_modules file was modified by the env-injecting FS wrap: got %q, want unchanged %q", data, pkgSrc)
	}

	// And end to end: the CJS dependency still works when actually run
	// through NodeCompat (proves the wrap doesn't just pass Open through
	// untouched but that resolution/require of a CJS dep still succeeds).
	pool, err := NewPool(Config{
		Size:       1,
		Entry:      "index.js",
		NodeCompat: true,
		Engine:     spidermonkey.Config{FS: fsys},
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
	if want := "hi world"; string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}
