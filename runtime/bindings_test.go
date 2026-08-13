package runtime

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	spidermonkey "github.com/goccy/go-spidermonkey"
	"github.com/goccy/go-spidermonkey/compat/cfworkers"
)

// These tests are checklist item 6: calling a Go function from the guest
// via env.SOMETHING(...), both synchronously and (bindings.go's
// AsyncFuncBinding) asynchronously.

// TestStaticBindingExposesPlainData is the baseline: env.NAME as a plain
// value (not a function), the cfworkers.Static passthrough this package
// re-exports as StaticBinding.
func TestStaticBindingExposesPlainData(t *testing.T) {
	pool, err := cfworkers.NewPool(cfworkers.PoolConfig{
		Size: 1,
		Env: map[string]cfworkers.Binding{
			"GREETING": StaticBinding("hello from Go"),
			"NUMBER":   StaticBinding(42),
		},
		Source: `
			export default {
				async fetch(req, env) {
					return new Response(env.GREETING + ":" + env.NUMBER);
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
	if want := "hello from Go:42"; string(body) != want {
		t.Errorf("body = %q, want %q", body, want)
	}
}

// TestFuncBindingCallableSynchronously proves env.NAME(...) calls straight
// into Go and returns the Go function's result to the guest, blocking (no
// Promise involved) — the shape a fast, already-synchronous host operation
// (a cache lookup, a local computation) wants.
func TestFuncBindingCallableSynchronously(t *testing.T) {
	var gotArgs []string
	pool, err := cfworkers.NewPool(cfworkers.PoolConfig{
		Size: 1,
		Env: map[string]cfworkers.Binding{
			"add": FuncBinding("add", func(cfg spidermonkey.Config, args []spidermonkey.Value) (spidermonkey.Value, error) {
				gotArgs = append(gotArgs, args[0].String()+"+"+args[1].String())
				return spidermonkey.ValueOf(args[0].Float() + args[1].Float()), nil
			}),
		},
		Source: `
			export default {
				async fetch(req, env) {
					const sum = env.add(20, 22);
					return new Response("sum=" + sum);
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
	if string(body) != "sum=42" {
		t.Fatalf("body = %q, want sum=42", body)
	}
	if len(gotArgs) != 1 || gotArgs[0] != "20+22" {
		t.Errorf("Go side observed args = %v, want one call with 20+22", gotArgs)
	}
}

// TestFuncBindingErrorSurfacesAsGuestThrow proves a Go-side error from a
// FuncBinding becomes a catchable guest exception, not a host crash or a
// silently swallowed failure.
func TestFuncBindingErrorSurfacesAsGuestThrow(t *testing.T) {
	pool, err := cfworkers.NewPool(cfworkers.PoolConfig{
		Size: 1,
		Env: map[string]cfworkers.Binding{
			"boom": FuncBinding("boom", func(cfg spidermonkey.Config, args []spidermonkey.Value) (spidermonkey.Value, error) {
				return nil, errors.New("go-side failure")
			}),
		},
		Source: `
			export default {
				async fetch(req, env) {
					try {
						env.boom();
						return new Response("should not reach here");
					} catch (e) {
						return new Response("caught:" + String((e && e.message) || e));
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

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if want := "caught:go-side failure"; string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}

// TestAsyncFuncBindingResolvesFromGoroutine proves AsyncFuncBinding's
// documented pattern actually works end to end: env.NAME(...) returns a
// Promise immediately, the guest awaits it, and the Go function's result
// (computed on a background goroutine, simulating a blocking DB/service
// call) resolves that promise.
func TestAsyncFuncBindingResolvesFromGoroutine(t *testing.T) {
	pool, err := cfworkers.NewPool(cfworkers.PoolConfig{
		Size: 1,
		Env: map[string]cfworkers.Binding{
			"lookup": AsyncFuncBinding("lookup", func(cfg spidermonkey.Config, args []spidermonkey.Value) (spidermonkey.Value, error) {
				// Simulate blocking I/O on the goroutine AsyncFuncBinding spawns.
				key := args[0].String()
				return spidermonkey.ValueOf("value-for-" + key), nil
			}),
		},
		Source: `
			export default {
				async fetch(req, env) {
					const v = await env.lookup("widget");
					return new Response("got:" + v);
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
	if want := "got:value-for-widget"; string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}

// TestAsyncFuncBindingRejectsOnError proves a returned error from an
// AsyncFuncBinding's fn rejects the guest Promise (catchable via try/catch
// around an await, or .catch), not just resolves with garbage.
func TestAsyncFuncBindingRejectsOnError(t *testing.T) {
	pool, err := cfworkers.NewPool(cfworkers.PoolConfig{
		Size: 1,
		Env: map[string]cfworkers.Binding{
			"fail": AsyncFuncBinding("fail", func(cfg spidermonkey.Config, args []spidermonkey.Value) (spidermonkey.Value, error) {
				return nil, errors.New("async go-side failure")
			}),
		},
		Source: `
			export default {
				async fetch(req, env) {
					try {
						await env.fail();
						return new Response("should not reach here");
					} catch (e) {
						return new Response("caught:" + String(e));
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

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if want := "caught:async go-side failure"; string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}

// TestAsyncFuncBindingMultipleConcurrentCalls proves several concurrent
// env.NAME(...) calls within one request each resolve to their OWN result
// (no cross-talk between the resolve/reject pairs), since AsyncFuncBinding
// builds one starter registration shared by every call and relies on each
// call's own resolve/reject closure to route the result correctly.
func TestAsyncFuncBindingMultipleConcurrentCalls(t *testing.T) {
	pool, err := cfworkers.NewPool(cfworkers.PoolConfig{
		Size: 1,
		Env: map[string]cfworkers.Binding{
			"echo": AsyncFuncBinding("echo", func(cfg spidermonkey.Config, args []spidermonkey.Value) (spidermonkey.Value, error) {
				return spidermonkey.ValueOf(args[0].String() + "-echoed"), nil
			}),
		},
		Source: `
			export default {
				async fetch(req, env) {
					const [a, b, c] = await Promise.all([
						env.echo("one"), env.echo("two"), env.echo("three"),
					]);
					return new Response([a, b, c].join(","));
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
	want := "one-echoed,two-echoed,three-echoed"
	if string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}
