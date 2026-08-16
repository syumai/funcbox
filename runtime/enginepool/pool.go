// Package enginepool runs funcbox's own function execution model —
// `export default { fetch(request) }` — on go-spidermonkey behind Go's
// net/http.
//
// This package is derived from go-spidermonkey's compat/cfworkers package
// (MIT License, Copyright (c) 2026 Masaaki Goshima) —
// https://github.com/goccy/go-spidermonkey — see NOTICE for the full notice
// and a summary of what changed. funcbox does not aim for Cloudflare
// Workers compatibility: there is no env/ctx binding mechanism, no
// waitUntil, and no scheduled()/queue() handler support — only
// fetch(request), plus funcbox's own import.meta.env and (optional)
// Node.js compat.
//
// The serving model is goroutine-per-request over a pool of warmed engine
// instances (the sql.DB shape): Go owns accept/TLS/HTTP parsing, the guest
// sees Request → Response.
//
//	pool, err := enginepool.NewPool(enginepool.Config{
//		Loader: enginepool.NewLoader(bundle), // or any spidermonkey.ModuleLoader
//		Entry:  "index.js",                   // export default { fetch }
//	})
//	http.ListenAndServe(":8080", pool)
//
// Instances are reused across requests, so module-level state persists
// (exactly like a warm Workers isolate).
package enginepool

import (
	_ "embed"
	"fmt"
	"net/http"
	"runtime"

	spidermonkey "github.com/goccy/go-spidermonkey"
)

//go:embed js/glue.js
var glueJS string

// Config configures NewPool.
type Config struct {
	// Engine is the per-instance engine config — including the permission
	// hooks, which govern everything the function can reach.
	Engine spidermonkey.Config
	// Size is the number of warmed instances (max concurrent requests).
	// Zero means GOMAXPROCS.
	Size int
	// Loader resolves the function module's own imports (and, in
	// non-NodeCompat mode, is the ONLY module source of truth — see
	// NodeCompat's doc comment on Config for how Node compat mode differs).
	Loader spidermonkey.ModuleLoader
	// Entry is the main module's specifier, resolved through Loader (or,
	// under NodeCompat, through Engine.FS): `export default { fetch }`.
	Entry string
	// Env populates import.meta.env for every module the function loads
	// (Bun-compatible: string values only). The caller is responsible for
	// having already filtered this down to the manifest's declared `env:`
	// keys — enginepool exposes exactly what it's given, nothing more. It is
	// frozen before any module evaluates, and every module observes the
	// SAME frozen object (see env.go).
	Env map[string]string
	// NodeCompat, when true, installs compat/nodejs (node: core modules,
	// process, Buffer, CommonJS/node_modules resolution, ESM<->CJS interop)
	// on the instance instead of just compat/web. Module resolution then
	// goes entirely through Engine.FS (compat/nodejs's own loader) — Loader
	// is ignored. import.meta.env still works for first-party (non-
	// node_modules) .js/.mjs files; see nodecompat.go for the mechanism and
	// its narrow limitation.
	NodeCompat bool
	// Internal maps a funcbox:-namespaced module specifier (e.g.
	// "funcbox:internal") to its exports. Only a pool actually constructed
	// with a non-nil Internal can import anything under "funcbox:" — a pool
	// built with Internal == nil (every ordinary user function pool) never
	// registers the "funcbox:" resolver at all, so the namespace is simply
	// unreachable, not merely unpopulated. This is how the dashboard's own
	// pool (and only the dashboard's) gets "funcbox:internal".
	Internal map[string]InternalModule
	// Warn, if non-nil, is called once per pooled instance for every extra
	// key (besides "fetch") funcbox finds on the module's default export —
	// e.g. a `scheduled` or `queue` handler ported from another runtime.
	// funcbox does not support them; this is a warning, not a boot error, so
	// porting a function from elsewhere doesn't fail just because it also
	// exports a handler funcbox ignores. A nil Warn silently ignores them.
	Warn func(key string)
	// MaxRequestBody caps how many bytes of an incoming request body a
	// single worker will buffer into memory before handing it to the
	// guest as Request.body (see worker.go's serve). A request whose body
	// exceeds this is rejected with 413 without ever finishing the read,
	// so a large/slow upload can't pin a pooled instance's memory for its
	// duration. Zero (the default for a caller that doesn't set it) means
	// DefaultMaxRequestBody.
	MaxRequestBody int64
}

// Pool is a fixed-size pool of warmed function instances. It implements
// http.Handler: each request checks out an instance for its duration.
type Pool struct {
	workers chan *worker
	size    int
}

// NewPool builds and warms the pool: every instance boots the module,
// validates its default export, and resolves its fetch handler before
// NewPool returns.
func NewPool(cfg Config) (*Pool, error) {
	size := cfg.Size
	if size <= 0 {
		size = runtime.GOMAXPROCS(0)
	}
	p := &Pool{workers: make(chan *worker, size), size: size}
	var created []*worker
	for i := 0; i < size; i++ {
		w, err := newWorker(cfg)
		if err != nil {
			for _, cw := range created {
				cw.close()
			}
			return nil, fmt.Errorf("enginepool: warming instance %d: %w", i, err)
		}
		created = append(created, w)
	}
	for _, w := range created {
		p.workers <- w
	}
	return p, nil
}

// Close shuts down every pooled instance. In-flight requests keep their
// instance until they finish; Close reclaims instances as they return.
// Unlike cfworkers' Close, there is no waitUntil drain to bound — funcbox
// has no background work outliving a response — so Close blocks only on
// requests actually still in flight, with no separate timeout of its own.
func (p *Pool) Close() error {
	var firstErr error
	for i := 0; i < p.size; i++ {
		w := <-p.workers
		if err := w.close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	p.size = 0
	return firstErr
}

// ServeHTTP checks an instance out of the pool for the request's duration.
// The caller MUST give req a deadline-bound context: that is the only
// mechanism that frees a slot stuck in a runaway guest handler (see
// worker.go's serve).
func (p *Pool) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	select {
	case w := <-p.workers:
		defer func() { p.workers <- w }()
		w.serve(rw, req)
	case <-req.Context().Done():
		http.Error(rw, "no worker available", http.StatusServiceUnavailable)
	}
}
