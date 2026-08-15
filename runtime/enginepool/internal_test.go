package enginepool

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	spidermonkey "github.com/goccy/go-spidermonkey"
)

// TestInternalModuleCallableFromDashboardStylePool proves a pool built with
// Config.Internal can import a funcbox:-namespaced module and call both a
// sync (FuncExport) and an async (AsyncExport) export from it.
func TestInternalModuleCallableFromDashboardStylePool(t *testing.T) {
	loader := singleFileLoader(map[string]string{
		"index.js": `
			import { ping, asyncGreet } from "funcbox:internal";
			export default {
				async fetch(req) {
					const sync = ping();
					const async = await asyncGreet("world");
					return new Response(JSON.stringify({ sync, async }));
				},
			};
		`,
	})
	internal := InternalModule{
		"ping": FuncExport("ping", func(cfg spidermonkey.Config, args []spidermonkey.Value) (spidermonkey.Value, error) {
			return spidermonkey.ValueOf("pong"), nil
		}),
		"asyncGreet": AsyncExport("asyncGreet", func(cfg spidermonkey.Config, args []spidermonkey.Value) (spidermonkey.Value, error) {
			if len(args) < 1 {
				return nil, fmt.Errorf("asyncGreet: name required")
			}
			return spidermonkey.ValueOf("hello, " + args[0].String()), nil
		}),
	}
	pool, err := NewPool(Config{
		Size: 1, Entry: "index.js", Loader: loader,
		Internal: map[string]InternalModule{"funcbox:internal": internal},
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
	want := `{"sync":"pong","async":"hello, world"}`
	if string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}

// TestInternalModuleAsyncRejectsPropagateErrors proves an error returned
// from an AsyncExport's Go function rejects the guest-side promise (not a
// silently-swallowed failure or a hang).
func TestInternalModuleAsyncRejectsPropagateErrors(t *testing.T) {
	loader := singleFileLoader(map[string]string{
		"index.js": `
			import { fail } from "funcbox:internal";
			export default {
				async fetch(req) {
					try {
						await fail();
						return new Response("should have thrown", { status: 500 });
					} catch (e) {
						return new Response("caught:" + String(e));
					}
				},
			};
		`,
	})
	internal := InternalModule{
		"fail": AsyncExport("fail", func(cfg spidermonkey.Config, args []spidermonkey.Value) (spidermonkey.Value, error) {
			return nil, fmt.Errorf("boom")
		}),
	}
	pool, err := NewPool(Config{
		Size: 1, Entry: "index.js", Loader: loader,
		Internal: map[string]InternalModule{"funcbox:internal": internal},
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
	if !strings.Contains(string(body), "boom") {
		t.Fatalf("body = %q, want it to contain the Go error message", body)
	}
}

// TestInternalModuleNotFoundWithoutConfigInternal proves a pool built with
// Internal == nil (every ordinary user function pool) cannot import
// "funcbox:internal" at all — the namespace is unreachable, not merely
// unpopulated.
func TestInternalModuleNotFoundWithoutConfigInternal(t *testing.T) {
	loader := singleFileLoader(map[string]string{
		"index.js": `
			import { ping } from "funcbox:internal";
			export default {
				async fetch(req) { return new Response(String(ping)); },
			};
		`,
	})
	_, err := NewPool(Config{Size: 1, Entry: "index.js", Loader: loader})
	if err == nil {
		t.Fatal("NewPool succeeded importing funcbox:internal with no Config.Internal, want an error")
	}
	t.Logf("expected boot error: %v", err)
}

// TestInternalModuleUnknownSpecifierNotFound proves an UNCONFIGURED
// funcbox:-namespaced specifier is "not found" even when Config.Internal IS
// set (for a different specifier) — the gate is per-specifier, not just
// per-prefix.
func TestInternalModuleUnknownSpecifierNotFound(t *testing.T) {
	loader := singleFileLoader(map[string]string{
		"index.js": `
			import { x } from "funcbox:unconfigured";
			export default {
				async fetch(req) { return new Response(String(x)); },
			};
		`,
	})
	internal := InternalModule{"ping": StaticExport("pong")}
	_, err := NewPool(Config{
		Size: 1, Entry: "index.js", Loader: loader,
		Internal: map[string]InternalModule{"funcbox:internal": internal},
	})
	if err == nil {
		t.Fatal("NewPool succeeded importing an unconfigured funcbox: specifier, want an error")
	}
}
