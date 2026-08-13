package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	spidermonkey "github.com/goccy/go-spidermonkey"
	"github.com/goccy/go-spidermonkey/compat/cfworkers"
	"github.com/goccy/go-spidermonkey/compat/nodejs"

	"github.com/fsnotify/fsnotify"

	"github.com/syumai/funcbox/internal/manifest"
	"github.com/syumai/funcbox/internal/policy"
	"github.com/syumai/funcbox/internal/runtime"
)

// devKey is the runtime.Manager cache key funcbox dev uses. There is only
// ever one function hosted per `funcbox dev` process, so a constant key is
// enough; hot reload works by rebuilding the snapshot Build reads and then
// calling Manager.Invalidate(devKey) so the next request rebuilds the pool
// from it.
const devKey = "dev"

// devPoolSize matches invoke's DefaultPoolSize (internal/invoke/pool.go);
// duplicated here rather than imported since internal/invoke is
// server-only and off-limits to the CLI binary (tmp/02-architecture.md).
const devPoolSize = 2

// devInvokeTimeout is the hard per-request deadline funcbox dev applies to
// every request, matching production's invariant that a request is never
// served without a deadline context (tmp/phase0-findings.md item 4: it is
// the only mechanism that frees a runaway instance's pool slot).
const devInvokeTimeout = 30 * time.Second

// devReloadDebounce coalesces a burst of filesystem events (e.g. an editor
// save that touches several files, or a `git checkout`) into a single
// rebuild.
const devReloadDebounce = 200 * time.Millisecond

// RunDev implements `funcbox dev [dir] [--addr 127.0.0.1:8787]
// [--env KEY=VALUE]... [--env-file PATH]` (tmp/07-http-api.md §7.5): parse
// flags, build a devServer, and run it until an interrupt/TERM signal or a
// fatal serve error.
func RunDev(args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("dev", flag.ContinueOnError)
	fset.SetOutput(stderr)
	addr := fset.String("addr", "127.0.0.1:8787", "address to listen on")
	envFile := fset.String("env-file", ".env", "path to a KEY=VALUE env file (skipped silently if it doesn't exist)")
	var envFlagsList envFlags
	fset.Var(&envFlagsList, "env", "KEY=VALUE env var; may be repeated. Overrides --env-file")
	positional, err := parseFlagsInterspersed(fset, args)
	if err != nil {
		return err
	}

	dir := "."
	if len(positional) > 0 {
		dir = positional[0]
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return err
	}

	envValues, err := resolveDevEnv(*envFile, envFlagsList)
	if err != nil {
		return err
	}

	ds, err := newDevServer(dir, *addr, envValues, stdout, stderr)
	if err != nil {
		return fmt.Errorf("cli: dev: %w", err)
	}
	defer ds.Close()

	fmt.Fprintf(stdout, "funcbox dev: hosting %s/%s\n", ds.owner, ds.name)
	fmt.Fprintln(stdout, "note: fetch policy applied here is manifest-level only; production may narrow it further via organization/workspace settings")
	fmt.Fprintln(stdout, "note: loopback addresses are allowed for local development; production always blocks them")
	fmt.Fprintf(stdout, "Listening on http://%s/%s/%s\n", ds.Addr(), ds.owner, ds.name)

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() { serveErr <- ds.Serve() }()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-sigCtx.Done():
		fmt.Fprintln(stdout, "shutting down")
		return nil // deferred ds.Close() performs the actual graceful shutdown
	}
}

// devServer is the running state of `funcbox dev`: an HTTP server hosting
// one function at /{owner}/{name}/..., a runtime.Manager owning its warmed
// pool, and an fsnotify watcher driving hot reload. Split out from RunDev
// so tests can drive a devServer directly without going through flag
// parsing or OS signal handling.
type devServer struct {
	ln         net.Listener
	httpServer *http.Server
	watcher    *fsnotify.Watcher
	manager    *runtime.Manager
	stopReload chan struct{}
	stopOnce   sync.Once
	owner      string
	name       string
}

// newDevServer builds and binds (but does not yet run) a devServer for the
// project at dir: parses/validates the manifest, collects the initial
// bundle, resolves owner/name, starts the file watcher and its reload
// loop, and listens on addr. Callers must eventually call Close (or
// Shutdown, which also stops the reload loop and watcher).
func newDevServer(dir, addr string, envValues map[string]string, stdout, stderr io.Writer) (*devServer, error) {
	snap, err := buildDevSnapshot(dir)
	if err != nil {
		return nil, err
	}

	owner := snap.manifest.Owner
	if owner == "" {
		// tmp/07-http-api.md §7.5: "owner は manifest の owner、無ければ
		// dev". This literal is intentionally NOT run through
		// manifest.ValidateHandle: "dev" is a reserved route on the
		// server (internal/manifest/reserved.go) precisely because it's
		// this local-only convention, not something a real deployment
		// would ever use.
		owner = "dev"
	}
	name := snap.manifest.Name
	if name == "" {
		return nil, fmt.Errorf("manifest is missing \"name\"; funcbox dev needs a name (set it in funcbox.yaml)")
	}

	st := &devState{}
	st.set(snap)

	watcher, err := newDevWatcher(dir, snap.manifest.Compat.Nodejs)
	if err != nil {
		return nil, fmt.Errorf("start file watcher: %w", err)
	}

	manager := runtime.NewManager()

	build := func(ctx context.Context) (*cfworkers.Pool, error) {
		return buildDevPool(st, envValues)
	}

	stopReload := make(chan struct{})
	go runDevReloadLoop(watcher, dir, snap.manifest.Compat.Nodejs, st, manager, stdout, stderr, stopReload)

	mux := http.NewServeMux()
	prefix := "/" + owner + "/" + name
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, prefix, http.StatusFound)
			return
		}
		if r.URL.Path != prefix && !strings.HasPrefix(r.URL.Path, prefix+"/") {
			http.NotFound(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), devInvokeTimeout)
		defer cancel()
		handler, err := manager.HandlerFor(ctx, runtime.VersionSpec{Key: devKey, Build: build})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		handler.ServeHTTP(w, r.WithContext(ctx))
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		close(stopReload)
		watcher.Close()
		manager.Close()
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}

	return &devServer{
		ln:         ln,
		httpServer: &http.Server{Handler: mux},
		watcher:    watcher,
		manager:    manager,
		stopReload: stopReload,
		owner:      owner,
		name:       name,
	}, nil
}

// Addr returns the address the server is actually listening on (useful
// after binding to ":0" for a random port, e.g. in tests).
func (ds *devServer) Addr() string { return ds.ln.Addr().String() }

// Serve blocks, serving requests until Close/Shutdown is called (mirrors
// http.Server.Serve: returns http.ErrServerClosed on a clean shutdown).
func (ds *devServer) Serve() error { return ds.httpServer.Serve(ds.ln) }

// Shutdown gracefully stops the HTTP server, the reload loop, and the file
// watcher.
func (ds *devServer) Shutdown(ctx context.Context) error {
	ds.stopOnce.Do(func() {
		close(ds.stopReload)
		ds.watcher.Close()
		ds.manager.Close()
	})
	return ds.httpServer.Shutdown(ctx)
}

// Close is Shutdown with a short bounded deadline, for defer statements
// that don't otherwise need a context.
func (ds *devServer) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return ds.Shutdown(ctx)
}

// devState holds the currently-served snapshot (bundle files, manifest,
// resolved main path) behind a mutex, so the HTTP-serving goroutine and the
// file-watcher's reload goroutine can safely hand off a rebuilt snapshot
// (tmp/07-http-api.md §7.5: "ファイル変更を監視して Pool を再作成").
type devState struct {
	mu   sync.RWMutex
	snap *devSnapshot
}

func (s *devState) set(snap *devSnapshot) {
	s.mu.Lock()
	s.snap = snap
	s.mu.Unlock()
}

func (s *devState) get() *devSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap
}

// devSnapshot is one buildable version of the hosted function: the
// collected bundle, its parsed manifest, and the resolved entry point.
type devSnapshot struct {
	files    map[string][]byte
	manifest *manifest.Manifest
	mainPath string
}

// buildDevSnapshot re-reads dir from disk and produces a fresh
// devSnapshot: parse + validate the manifest, collect the bundle (same
// rules as deploy), enforce the 5MiB limit, resolve main, and — for
// compat.nodejs — fail fast on a node:* import exactly as deploy would
// (tmp/07-http-api.md §7.5: "compat.nodejs: true → ... 同じメッセージで
// fail fast", mirroring internal/service.Deploy's node_core_import check,
// duplicated here since internal/service is server-only).
func buildDevSnapshot(dir string) (*devSnapshot, error) {
	m, err := LoadProjectManifest(dir)
	if err != nil {
		return nil, err
	}
	if err := manifest.Validate(m); err != nil {
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}

	ignoreMatcher, err := LoadIgnoreMatcher(dir)
	if err != nil {
		return nil, err
	}
	files, err := CollectFiles(dir, m.Compat.Nodejs, ignoreMatcher)
	if err != nil {
		return nil, err
	}
	if err := CheckUnpackedSize(files); err != nil {
		return nil, err
	}

	mainPath, err := manifest.ResolveMain(m.Main, files)
	if err != nil {
		return nil, err
	}

	if m.Compat.Nodejs {
		if imports := detectNodeCoreImportsInFiles(files); len(imports) > 0 {
			return nil, fmt.Errorf("compat.nodejs functions cannot import node core modules yet (no nodejs.Install hook in cfworkers.Pool; see tmp/03-runtime.md 3.5): %s", strings.Join(imports, ", "))
		}
	}

	return &devSnapshot{files: files, manifest: m, mainPath: mainPath}, nil
}

// detectNodeCoreImportsInFiles mirrors internal/service.Deploy's own
// detectNodeCoreImports (unexported, in the server-only internal/service
// package), scanning every plausible JS module in files for a "node:*"
// import via runtime.DetectNodeCoreImports.
func detectNodeCoreImportsInFiles(files map[string][]byte) []string {
	seen := make(map[string]bool)
	var out []string
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !looksLikeJSModule(name) {
			continue
		}
		for _, spec := range runtime.DetectNodeCoreImports(string(files[name])) {
			if !seen[spec] {
				seen[spec] = true
				out = append(out, spec)
			}
		}
	}
	return out
}

func looksLikeJSModule(path string) bool {
	for _, ext := range [...]string{".js", ".mjs", ".cjs"} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// buildDevPool is a runtime.VersionSpec.Build function: it reads st's
// current snapshot and warms a cfworkers.Pool from it, mirroring
// internal/invoke/pool.go's buildPool but sourced from an in-memory
// snapshot instead of blob storage + a store-backed manifest.
func buildDevPool(st *devState, envValues map[string]string) (*cfworkers.Pool, error) {
	snap := st.get()
	m := snap.manifest
	b := runtime.Bundle(snap.files)

	var loader spidermonkey.ModuleLoader
	var fsys fs.FS
	if m.Compat.Nodejs {
		loader = nodejs.ESMLoader
		fsys = b.FS()
	} else {
		loader = runtime.NewLoader(b)
	}

	eff := policy.Effective(m.Permissions.Fetch.FetchPolicy())
	fp := devFetchPolicy{eff: eff}

	cfg := spidermonkey.Config{
		FS:      fsys,
		Resolve: runtime.ResolveHook(fp),
		Dial:    runtime.DialHook(fp),
	}
	if m.Memory != nil {
		cfg.MaxMemoryBytes = int(*m.Memory)
	}

	pool, err := cfworkers.NewPool(cfworkers.PoolConfig{
		Config: cfg,
		Size:   devPoolSize,
		Source: fmt.Sprintf("import handler from %q; export default handler;", "./"+snap.mainPath),
		Loader: loader,
		Env:    buildDevEnvBindings(m.Env, envValues),
	})
	if err != nil {
		return nil, fmt.Errorf("cli: dev: warm pool: %w", err)
	}
	return pool, nil
}

func buildDevEnvBindings(declared []string, values map[string]string) map[string]cfworkers.Binding {
	if len(declared) == 0 {
		return nil
	}
	env := make(map[string]cfworkers.Binding, len(declared))
	for _, key := range declared {
		if v, ok := values[key]; ok {
			env[key] = runtime.StaticBinding(v)
		}
	}
	return env
}

// devFetchPolicy implements runtime.FetchPolicy for funcbox dev: it
// applies only the manifest level (no org/workspace intersection is
// possible locally) and relaxes policy.BlockedIP's loopback check, since
// local development routinely needs to fetch a local backend
// (tmp/07-http-api.md §7.5). Every other category BlockedIP blocks
// (link-local/metadata, multicast, unspecified) stays blocked even in dev.
type devFetchPolicy struct {
	eff policy.EffectivePolicy
}

func (p devFetchPolicy) AllowHost(host string, port int) bool {
	return p.eff.Decision(host, port)
}

func (p devFetchPolicy) AllowIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() {
		return true
	}
	return !policy.BlockedIP(parsed)
}

// envFlags collects repeated --env KEY=VALUE flags (flag.Value).
type envFlags []string

func (e *envFlags) String() string { return strings.Join(*e, ",") }
func (e *envFlags) Set(v string) error {
	*e = append(*e, v)
	return nil
}

// resolveDevEnv merges --env-file (default ".env", silently skipped if
// absent) with repeated --env flags, which take precedence on conflict.
func resolveDevEnv(envFile string, flags envFlags) (map[string]string, error) {
	values, err := parseEnvFile(envFile)
	if err != nil {
		return nil, err
	}
	for _, kv := range flags {
		key, value, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, fmt.Errorf("cli: dev: invalid --env %q (expected KEY=VALUE)", kv)
		}
		values[key] = value
	}
	return values, nil
}

func parseEnvFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("cli: dev: read env file %s: %w", path, err)
	}
	return parseEnvLines(data), nil
}

func parseEnvLines(data []byte) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		out[key] = value
	}
	return out
}

// newDevWatcher creates an fsnotify.Watcher and adds dir plus every
// non-excluded subdirectory (the same implicit excludes CollectFiles
// applies, so a build's own huge node_modules tree — when present — isn't
// individually watched entry by entry).
func newDevWatcher(dir string, includeNodeModules bool) (*fsnotify.Watcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	ignoreMatcher, err := LoadIgnoreMatcher(dir)
	if err != nil {
		w.Close()
		return nil, err
	}
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(dir, p)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if rel != "." && (isImplicitDirExclude(rel, includeNodeModules) || ignoreMatcher.Match(rel, true)) {
			return fs.SkipDir
		}
		return w.Add(p)
	})
	if err != nil {
		w.Close()
		return nil, err
	}
	return w, nil
}

// runDevReloadLoop watches for filesystem events and, after a debounce
// window, rebuilds the snapshot and swaps it into st. A rebuild failure
// (e.g. a syntax error introduced mid-edit) is reported to stderr and
// otherwise ignored: the previous, still-valid snapshot keeps serving
// rather than taking the dev server down.
func runDevReloadLoop(watcher *fsnotify.Watcher, dir string, includeNodeModules bool, st *devState, manager *runtime.Manager, stdout, stderr io.Writer, stop <-chan struct{}) {
	var timer *time.Timer
	reload := func() {
		snap, err := buildDevSnapshot(dir)
		if err != nil {
			fmt.Fprintf(stderr, "funcbox dev: reload failed, still serving previous version: %v\n", err)
			return
		}
		st.set(snap)
		manager.Invalidate(devKey)
		fmt.Fprintln(stdout, "funcbox dev: reloaded")
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Create) != 0 {
				if fi, err := os.Stat(event.Name); err == nil && fi.IsDir() {
					_ = watcher.Add(event.Name)
				}
			}
			if timer != nil {
				timer.Stop()
			}
			timer = time.AfterFunc(devReloadDebounce, reload)
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			fmt.Fprintf(stderr, "funcbox dev: watch error: %v\n", err)
		case <-stop:
			if timer != nil {
				timer.Stop()
			}
			return
		}
	}
}
