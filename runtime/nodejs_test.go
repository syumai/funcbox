package runtime

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	spidermonkey "github.com/goccy/go-spidermonkey"
	"github.com/goccy/go-spidermonkey/compat/nodejs"

	"github.com/syumai/funcbox/runtime/enginepool"
)

// These tests are checklist item 7: nodejs.ESMLoader + a bundle FS resolving
// a bare specifier from a hand-written node_modules fixture (NOT run
// through npm — testdata/nodeapp/node_modules/tinypkg is committed by
// hand), and confirming "node:*" imports fail without nodejs.Install.

// TestNodejsESMLoaderResolvesBareSpecifierFromRealFS mirrors the upstream
// hono_flagship_test.go pattern (Loader: nodejs.ESMLoader, Config.FS:
// os.DirFS(dir)) but against our own tiny hand-written fixture instead of a
// real npm install, proving compat.nodejs's node_modules resolution
// (package.json "exports", bare specifier -> node_modules walk-up) works
// for a funcbox-shaped deployment.
func TestNodejsESMLoaderResolvesBareSpecifierFromRealFS(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("testdata", "nodeapp"))
	if err != nil {
		t.Fatal(err)
	}

	pool, err := enginepool.NewPool(enginepool.Config{
		Size:   1,
		Entry:  "index.js",
		Loader: nodejs.ESMLoader,
		Engine: spidermonkey.Config{FS: os.DirFS(dir)},
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
	if want := "tinypkg says hi, world!"; string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}

// TestNodejsESMLoaderResolvesBareSpecifierFromBundleFS proves the SAME
// resolution works over our own in-memory Bundle.FS() (loader.go), not just
// a real os.DirFS — the actual shape a funcbox deployment would use
// (bundle extracted to memory, never touching disk).
func TestNodejsESMLoaderResolvesBareSpecifierFromBundleFS(t *testing.T) {
	dir := filepath.Join("testdata", "nodeapp")
	pkgJSON, err := os.ReadFile(filepath.Join(dir, "node_modules", "tinypkg", "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	indexMJS, err := os.ReadFile(filepath.Join(dir, "node_modules", "tinypkg", "index.mjs"))
	if err != nil {
		t.Fatal(err)
	}
	bundle := Bundle{
		"index.js": []byte(`
			import { greet } from "tinypkg";
			export default {
				async fetch(req) {
					return new Response(greet("bundle"));
				},
			};
		`),
		"node_modules/tinypkg/package.json": pkgJSON,
		"node_modules/tinypkg/index.mjs":    indexMJS,
	}

	pool, err := enginepool.NewPool(enginepool.Config{
		Size:   1,
		Entry:  "index.js",
		Loader: nodejs.ESMLoader,
		Engine: spidermonkey.Config{FS: bundle.FS()},
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
	if want := "tinypkg says hi, bundle!"; string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}

// TestNodejsESMLoaderRejectsNodeCoreImportWithoutInstall confirms a
// pool built with plain Loader: nodejs.ESMLoader (NOT Config.NodeCompat —
// see enginepool.Config's doc comment: NodeCompat is what actually runs
// nodejs.Install) still can't resolve "node:*" — the error is a clear,
// actionable one (not a generic "module not found"), which matters for
// surfacing it well to a function author who wired up ESMLoader by hand
// instead of using NodeCompat.
func TestNodejsESMLoaderRejectsNodeCoreImportWithoutInstall(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("testdata", "nodeapp"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = enginepool.NewPool(enginepool.Config{
		Size:   1,
		Entry:  "nodecore.js",
		Loader: nodejs.ESMLoader,
		Engine: spidermonkey.Config{FS: os.DirFS(dir)},
	})
	if err == nil {
		t.Fatal("NewPool succeeded importing node:fs without nodejs.Install, want an error")
	}
	if !strings.Contains(err.Error(), "nodejs.Install") {
		t.Errorf("error = %q, want it to mention nodejs.Install (ESMLoader's own diagnostic)", err)
	}
	t.Logf("node:fs without nodejs.Install: %v", err)
}

// TestDetectNodeCoreImports exercises the lightweight, deploy-time static
// scanner proposed for funcbox's manifest/deploy validation (see
// deploying a compat.nodejs function, rather than letting a function author
// discover the unsupported-import error at first invocation. It is
// deliberately a cheap regex/text scan, not a real parser — see the
// function's own doc comment for what that trades away.
func TestDetectNodeCoreImports(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   []string
	}{
		{
			name:   "static import",
			source: `import fs from "node:fs"; import { join } from "node:path";`,
			want:   []string{"node:fs", "node:path"},
		},
		{
			name:   "dynamic import",
			source: `const fs = await import("node:fs/promises");`,
			want:   []string{"node:fs/promises"},
		},
		{
			name:   "require",
			source: `const crypto = require("node:crypto");`,
			want:   []string{"node:crypto"},
		},
		{
			name:   "bare npm package, no node: prefix",
			source: `import { Hono } from "hono";`,
			want:   nil,
		},
		{
			name:   "relative import unaffected",
			source: `import "./lib/greet.js";`,
			want:   nil,
		},
		{
			name:   "single-quoted specifier",
			source: `import fs from 'node:fs';`,
			want:   []string{"node:fs"},
		},
		{
			name:   "duplicate imports deduplicated",
			source: `import "node:fs"; import "node:fs";`,
			want:   []string{"node:fs"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectNodeCoreImports(tc.source)
			if !stringSlicesEqual(got, tc.want) {
				t.Errorf("DetectNodeCoreImports(%q) = %v, want %v", tc.source, got, tc.want)
			}
		})
	}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
