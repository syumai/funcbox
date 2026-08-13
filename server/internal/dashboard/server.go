package dashboard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-spidermonkey/compat/cfworkers"

	"github.com/syumai/funcbox/server/internal/api"
	"github.com/syumai/funcbox/server/internal/auth"
	fcrypto "github.com/syumai/funcbox/server/internal/crypto"
	"github.com/syumai/funcbox/server/internal/store"
)

// DefaultRequestTimeout bounds a dashboard-app invocation. A deadline-bearing context is not just a
// client-response nicety here either -- it is the only mechanism that
// frees a runaway pooled instance's slot (a synchronous infinite loop in
// dist/server.js would otherwise pin it forever). ServeHTTP therefore never
// calls the dashboard's pool without one, mirroring invoke.Invoker.Serve's
// own invariant.
const DefaultRequestTimeout = 15 * time.Second

const (
	dashboardPrefix = "/dashboard"
	assetsPrefix    = "/dashboard/assets/"
)

// Config is Server's configuration.
type Config struct {
	// Auth resolves the dashboard's session cookie (AuthenticateSessionCookie)
	// and builds the /auth/login redirect for an anonymous request. Required.
	Auth *auth.Auth
	// API is dispatched in-process by the INTERNAL_API binding
	// (internalapi.go), via its ServeInternal entry point. Required.
	API *api.Handler
	// SessionSecret (FUNCBOX_SESSION_SECRET) derives this package's
	// caller-token HMAC subkey, the same way internal/auth derives its CSRF
	// subkey and internal/api derives its env-var encryption key. Required.
	SessionSecret string
	// Logger defaults to slog.Default() if nil.
	Logger *slog.Logger
	// §9.3: "size from GOMAXPROCS or small fixed"). Zero means
	// min(GOMAXPROCS, 4) -- the dashboard is a single lightweight internal
	// app, not a tenant workload, so it doesn't need per-function-sized
	// pools.
	PoolSize int
	// RequestTimeout bounds each dashboard-app request. Zero means
	// DefaultRequestTimeout.
	RequestTimeout time.Duration
	// DistDir, set, serves dist/ from this directory on disk instead of
	// the embedded build (development: `pnpm watch` writes here, and every
	// request cheaply re-stats dist/server.js so an edit is picked up
	// 変更を検知して...Pool を invalidate". Also used by this package's own
	// tests to point at testdata/dist instead of requiring a real pnpm
	// build.
	DistDir string
}

// errAssetsNotBuilt is returned by Ready/ensurePool when dist/server.js is
// missing -- a pristine checkout that hasn't run `pnpm build` yet (only
// dist/.gitkeep exists; see embed.go's doc comment), or a DistDir pointed
// at an empty directory.
var errAssetsNotBuilt = errors.New("dashboard: assets not built -- run `make server` (see tmp/09-dashboard.md §9.6)")

// Server hosts funcbox's dashboard app (see this package's doc comment).
// Build one with New and mount it as internal/server's Deps.Dashboard.
type Server struct {
	cfg       Config
	logger    *slog.Logger
	tokenKey  []byte
	dist      fs.FS
	watchDisk bool // Config.DistDir was set: mtime-poll server.js per request

	mu           sync.Mutex
	pool         *cfworkers.Pool
	buildErr     error
	builtModTime time.Time
}

// New validates cfg and prepares a Server. It does NOT require
// dist/server.js to exist yet -- a Server for an unbuilt dashboard is
// valid and simply serves writeNotBuiltPage for every non-asset request
// until the assets show up (see Ready for the startup-time check a caller
// like cmd/funcbox-server can use to log a clear warning instead).
func New(cfg Config) (*Server, error) {
	if cfg.Auth == nil {
		return nil, errors.New("dashboard: Config.Auth is required")
	}
	if cfg.API == nil {
		return nil, errors.New("dashboard: Config.API is required")
	}
	if cfg.SessionSecret == "" {
		return nil, errors.New("dashboard: Config.SessionSecret is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	key, err := fcrypto.DeriveKey(cfg.SessionSecret, callerTokenKeyInfo)
	if err != nil {
		return nil, fmt.Errorf("dashboard: derive caller token key: %w", err)
	}

	var dist fs.FS
	watch := false
	if cfg.DistDir != "" {
		dist = os.DirFS(cfg.DistDir)
		watch = true
	} else {
		d, err := embeddedDistFS()
		if err != nil {
			return nil, fmt.Errorf("dashboard: load embedded assets: %w", err)
		}
		dist = d
	}

	return &Server{cfg: cfg, logger: logger, tokenKey: key, dist: dist, watchDisk: watch}, nil
}

// Ready reports whether the dashboard's built assets are present. Intended
// for a caller (cmd/funcbox-server) to log a clear, actionable warning at
// the server over it: function invocation and the management API have
// nothing to do with whether the dashboard happens to be built.
func (s *Server) Ready() error {
	if _, err := fs.Stat(s.dist, "server.js"); err != nil {
		return errAssetsNotBuilt
	}
	return nil
}

// Close shuts down the dashboard's pool, if one has been built. Safe to
// call even if the dashboard was never successfully started.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pool == nil {
		return nil
	}
	err := s.pool.Close()
	s.pool = nil
	return err
}

func (s *Server) poolSize() int {
	if s.cfg.PoolSize > 0 {
		return s.cfg.PoolSize
	}
	n := runtime.GOMAXPROCS(0)
	if n > 4 {
		n = 4
	}
	if n < 1 {
		n = 1
	}
	return n
}

func (s *Server) requestTimeout() time.Duration {
	if s.cfg.RequestTimeout > 0 {
		return s.cfg.RequestTimeout
	}
	return DefaultRequestTimeout
}

// ensurePool lazily builds the dashboard's cfworkers.Pool on first use,
// and -- only when Config.DistDir enabled disk-watch mode -- rebuilds it
// whenever dist/server.js's mtime changes, so a local `pnpm watch` rebuild
// is picked up by an already-running funcbox-server without a restart
func (s *Server) ensurePool() (*cfworkers.Pool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.watchDisk && s.pool != nil {
		if info, err := fs.Stat(s.dist, "server.js"); err == nil && !info.ModTime().Equal(s.builtModTime) {
			s.logger.Info("dashboard: server.js changed on disk, rebuilding pool")
			_ = s.pool.Close()
			s.pool = nil
			s.buildErr = nil
		}
	}
	if s.pool != nil {
		return s.pool, nil
	}
	if s.buildErr != nil {
		return nil, s.buildErr
	}

	source, err := fs.ReadFile(s.dist, "server.js")
	if err != nil {
		s.buildErr = errAssetsNotBuilt
		return nil, s.buildErr
	}
	var modTime time.Time
	if info, err := fs.Stat(s.dist, "server.js"); err == nil {
		modTime = info.ModTime()
	}

	pool, err := cfworkers.NewPool(cfworkers.PoolConfig{
		Size:   s.poolSize(),
		Source: string(source),
		Env: map[string]cfworkers.Binding{
			"INTERNAL_API": internalAPIBinding(s.cfg.API, s.tokenKey),
		},
	})
	if err != nil {
		s.buildErr = fmt.Errorf("dashboard: failed to start dashboard app: %w", err)
		return nil, s.buildErr
	}
	s.pool = pool
	s.buildErr = nil
	s.builtModTime = modTime
	return pool, nil
}

//	/dashboard/assets/*  -> served directly from dist (no VM, long cache)
//	every other /dashboard/* -> session check (redirect to /auth/login if
//	                            anonymous) -> the dashboard's own pool
//
// r arrives with its full original path (internal/server routes here
// without stripping the "/dashboard" prefix -- see routes.go's Deps.Dashboard
// doc comment), matching how the dashboard app's own routes are registered
// (Hono's basePath("/dashboard"), server.tsx).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path

	if p == dashboardPrefix+"/" {
		http.Redirect(w, r, dashboardPrefix, http.StatusMovedPermanently)
		return
	}
	if strings.HasPrefix(p, assetsPrefix) {
		s.serveAsset(w, r)
		return
	}

	actor, err := s.cfg.Auth.AuthenticateSessionCookie(r)
	if err != nil {
		http.Redirect(w, r, auth.LoginURL(r.URL.RequestURI()), http.StatusFound)
		return
	}

	// Pending-approval gate (tmp/13-public-mode.md §13.3): a
	// store.UserStatusPending actor authenticates successfully (see
	// internal/auth's loadActiveUser/validateAuthenticatable) but must see
	// ONLY the "access request pending" page, on every /dashboard/* route.
	// This is intercepted HERE, in Go, before the pool is ever built or
	// invoked -- not inside the hono/jsx app (server.tsx) -- for two
	// reasons: (1) it's the one place that already gates every route on
	// the session cookie, so there is no second route tree to keep in
	// sync; (2) it's the only place that can guarantee env.INTERNAL_API is
	// never reached for a pending user (api.Handler's own
	// requirePendingApproved middleware only guards the ServeHTTP/h.mux
	// path, not ServeInternal's in-process bridge -- see that function's
	// doc comment) -- if the guest pool ran at all, its SSR routes would
	// still make normal INTERNAL_API calls and render real data. The page
	// itself is Go-rendered bilingual static HTML (English+Japanese
	// together) rather than routed through the dashboard's own i18n
	// catalog (dashboard/src/i18n.ts), precisely because rendering it here
	// means there is no per-user/org effective-language resolution
	// available yet (that itself would be an API call) without extra
	// plumbing this minimal a page doesn't warrant.
	if actor.User.Status == store.UserStatusPending {
		s.writePendingApprovalPage(w, actor.User)
		return
	}

	pool, err := s.ensurePool()
	if err != nil {
		s.writeNotBuiltPage(w, err)
		return
	}

	// Deadline invariant (see DefaultRequestTimeout's doc comment): never
	// serve the pool without one.
	ctx, cancel := context.WithTimeout(r.Context(), s.requestTimeout())
	defer cancel()

	token, err := signCallerToken(s.tokenKey, callerClaims{
		UserID:   actor.User.ID,
		Email:    actor.User.Email,
		Name:     actor.User.Name,
		Role:     string(actor.User.Role),
		IssuedAt: time.Now().Unix(),
	})
	if err != nil {
		s.logger.Error("dashboard: sign caller token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Cookie is authorization-carrying and must never reach guest code,
	// §9.3: "ダッシュボード VM は信頼境界の内側だが...Cookie は渡さない
	// 設計を守る"). X-Funcbox-Caller-Token is this package's own trust
	// boundary: strip any client-supplied value before setting the
	// freshly-signed one, so a request can never smuggle a stale or forged
	// token in under our own header name.
	r.Header.Del("Cookie")
	r.Header.Del("X-Funcbox-Caller-Token")
	r.Header.Set("X-Funcbox-Caller-Token", token)

	pool.ServeHTTP(w, r.WithContext(ctx))
}

func (s *Server) serveAsset(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(r.URL.Path, dashboardPrefix+"/")
	f, err := s.dist.Open(rel)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	rs, ok := f.(io.ReadSeeker)
	if !ok {
		http.NotFound(w, r)
		return
	}
	// Every asset filename is content-hashed by esbuild (dashboard/build.ts),
	// so a given URL's content never changes: safe to cache "forever".
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	http.ServeContent(w, r, path.Base(rel), info.ModTime(), rs)
}

// writePendingApprovalPage renders the minimal "access request pending"
// page tmp/13-public-mode.md §13.3 specifies: account identity, request
// date (u.CreatedAt), and nothing else (no reason input, no notification
// controls -- see this method's caller for why it's Go-rendered here
// rather than by the dashboard's own hono/jsx app). It doubles as this
// mode's post-login notice: a newly-registered user's very first
// dashboard view after completing login IS this page, so it's also where
// they first learn their access request was submitted and is awaiting an
// administrator (see README.md's "Account approval mode" section for the
// decision not to additionally add a pre-login interstitial notice).
func (s *Server) writePendingApprovalPage(w http.ResponseWriter, u *store.User) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	identity := u.Name
	if identity == "" {
		identity = u.Email
	} else {
		identity += " (" + u.Email + ")"
	}
	escapedIdentity := htmlEscape(identity)
	escapedDate := htmlEscape(u.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	// Argument order must match pendingApprovalPageHTML's %s placeholders in
	// document order: English (identity, date), then Japanese (identity, date).
	fmt.Fprintf(w, pendingApprovalPageHTML, escapedIdentity, escapedDate, escapedIdentity, escapedDate)
}

const pendingApprovalPageHTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>funcbox -- access request pending / アクセスリクエスト申請中</title></head>
<body style="font-family:sans-serif;padding:40px;max-width:640px;margin:0 auto;line-height:1.6">
<h1>Access request pending</h1>
<p>You are signed in as <strong>%s</strong>. Your access request was
submitted on <strong>%s</strong> and is awaiting an organization
administrator's approval. You will be able to use funcbox as soon as it is
approved -- no further action is needed on your part; simply return to
this page later.</p>
<form method="POST" action="/auth/logout"><button type="submit">Log out</button></form>
<hr style="margin:32px 0">
<h1>アクセスリクエスト申請中</h1>
<p>現在 <strong>%s</strong> としてログインしています。%s
にアクセスリクエストを送信済みで、組織管理者の承認をお待ちください。
承認されると自動的に利用できるようになります。追加の操作は不要です。
しばらくしてから、このページに再度アクセスしてください。</p>
<form method="POST" action="/auth/logout"><button type="submit">ログアウト</button></form>
</body></html>`

func (s *Server) writeNotBuiltPage(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, `<!doctype html>
<html><head><meta charset="utf-8"><title>funcbox dashboard</title></head>
<body style="font-family:monospace;padding:40px;max-width:640px;margin:0 auto">
<h1>Dashboard is not available</h1>
<p>%s</p>
<p>Run <code>make server</code> from the repository root (it runs
<code>pnpm -C dashboard install --frozen-lockfile &amp;&amp; pnpm -C dashboard build</code>
before building the Go binary), then restart funcbox-server.</p>
</body></html>`, htmlEscape(err.Error()))
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}
