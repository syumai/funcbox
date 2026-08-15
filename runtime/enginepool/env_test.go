package enginepool

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestImportMetaEnvExposesDeclaredKeysOnly proves Config.Env populates
// import.meta.env with exactly the string values it was given — nothing
// more, nothing coerced.
func TestImportMetaEnvExposesDeclaredKeysOnly(t *testing.T) {
	loader := singleFileLoader(map[string]string{
		"index.js": `
			export default {
				async fetch(req) {
					return new Response(JSON.stringify(import.meta.env));
				},
			};
		`,
	})
	pool, err := NewPool(Config{
		Size: 1, Entry: "index.js", Loader: loader,
		Env: map[string]string{"GREETING": "hello", "MODE": "test"},
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

	var got map[string]string
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decoding response %q: %v", body, err)
	}
	want := map[string]string{"GREETING": "hello", "MODE": "test"}
	if len(got) != len(want) || got["GREETING"] != want["GREETING"] || got["MODE"] != want["MODE"] {
		t.Fatalf("import.meta.env = %v, want %v", got, want)
	}
}

// TestImportMetaEnvIsFrozen proves import.meta.env cannot be mutated (a
// declared key reassigned, or a new key added) from guest code.
func TestImportMetaEnvIsFrozen(t *testing.T) {
	loader := singleFileLoader(map[string]string{
		"index.js": `
			export default {
				async fetch(req) {
					let threw = false;
					try {
						"use strict";
						(function() { "use strict"; import.meta.env.KEY = "changed"; })();
					} catch (e) { threw = true; }
					const stillFrozen = Object.isFrozen(import.meta.env) && import.meta.env.KEY === "value";
					return new Response(JSON.stringify({ threw, stillFrozen }));
				},
			};
		`,
	})
	pool, err := NewPool(Config{
		Size: 1, Entry: "index.js", Loader: loader,
		Env: map[string]string{"KEY": "value"},
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

	var got struct {
		Threw       bool `json:"threw"`
		StillFrozen bool `json:"stillFrozen"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decoding response %q: %v", body, err)
	}
	if !got.Threw {
		t.Error("assigning to a frozen import.meta.env property did not throw in strict mode")
	}
	if !got.StillFrozen {
		t.Error("import.meta.env was mutated, or is not reported as frozen")
	}
}

// TestImportMetaEnvSameValueAcrossModules proves every module in the
// instance observes the same import.meta.env — including a module imported
// by the entry module, not just the entry itself.
func TestImportMetaEnvSameValueAcrossModules(t *testing.T) {
	loader := singleFileLoader(map[string]string{
		"index.js": `
			import { childEnv } from "./child.js";
			export default {
				async fetch(req) {
					const same = JSON.stringify(import.meta.env) === JSON.stringify(childEnv);
					return new Response(JSON.stringify({ same, entry: import.meta.env, child: childEnv }));
				},
			};
		`,
		"child.js": `export const childEnv = import.meta.env;`,
	})
	pool, err := NewPool(Config{
		Size: 1, Entry: "index.js", Loader: loader,
		Env: map[string]string{"SHARED": "yes"},
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

	var got struct {
		Same bool `json:"same"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decoding response %q: %v", body, err)
	}
	if !got.Same {
		t.Errorf("import.meta.env differed between the entry module and an imported module: %s", body)
	}
}

// TestImportMetaEnvEmptyWhenNoEnvConfigured proves a pool with no Config.Env
// still gets a (frozen, empty) import.meta.env rather than undefined —
// guest code can always safely read import.meta.env.SOMETHING without a
// TypeError, matching Bun's behavior of always defining import.meta.env.
func TestImportMetaEnvEmptyWhenNoEnvConfigured(t *testing.T) {
	loader := singleFileLoader(map[string]string{
		"index.js": `
			export default {
				async fetch(req) {
					return new Response(JSON.stringify({
						isObject: typeof import.meta.env === "object" && import.meta.env !== null,
						keys: Object.keys(import.meta.env),
						missing: import.meta.env.NOPE,
					}));
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

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if want := `{"isObject":true,"keys":[]}`; string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}
