package invoke

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-spidermonkey/compat/cfworkers"

	"github.com/syumai/funcbox/manifest"
	"github.com/syumai/funcbox/policy"
	"github.com/syumai/funcbox/runtime"
	"github.com/syumai/funcbox/server/internal/auth"
	"github.com/syumai/funcbox/server/internal/blob"
	"github.com/syumai/funcbox/server/internal/metrics"
	"github.com/syumai/funcbox/server/internal/store"
)

// DefaultTimeout is used when Invoker.Timeout is unset.
const DefaultTimeout = 30 * time.Second

// Invoker resolves /{owner}/{func}[/...] to a function's active version and
// serves the request through its runtime.Manager-owned pool
type Invoker struct {
	Store   store.Store
	Blob    blob.Store
	Manager *runtime.Manager
	Logger  *slog.Logger

	// Auth resolves function-invoke callers for org/workspace-visibility
	// functions (ID token or, for GET/HEAD, session cookie) and verifies
	// any deployed function might need org/workspace visibility; a nil
	// Auth makes every non-public function permanently inaccessible
	// (fail closed) rather than panicking.
	Auth *auth.Auth

	// EnvKey decrypts function env vars at invoke time (see pool.go's
	// buildEnvBindings). May be nil if no function declares any env vars.
	EnvKey []byte

	// Metrics records invoke counts, invocation errors, and pool cold
	// method, including on a nil receiver, is a safe no-op); Invoker is
	// often constructed as a plain struct literal without it, e.g. in
	// tests.
	Metrics *metrics.Metrics

	// effectiveCache memoizes org/workspace fetch-policy resolution
	// across the (potentially many) outbound fetch calls a warm pool
	// serves; see effective.go.
	effectiveCache *effectiveCache
	cacheOnce      sync.Once

	// tracker demultiplexes captured guest console output and fetch
	// ALLOW/DENY decisions back to the invocation that produced them; see
	// logcapture.go. Lazily initialized the same way as effectiveCache.
	invocationTracker     *invocationTracker
	invocationTrackerOnce sync.Once

	// Timeout bounds every invocation (FUNCBOX_INVOKE_TIMEOUT default).
	// client-response nicety: it is the ONLY mechanism that frees a
	// runaway instance's pool slot, so Serve always wraps the request
	// context with it (narrowing further if the manifest declares a
	// shorter timeout) before calling the pool handler — never with an
	// undeadlined context. Zero means DefaultTimeout.
	Timeout time.Duration
}

// cache lazily initializes and returns the Invoker's shared effectiveCache
// (sync.Once rather than requiring callers to set it, since Invoker is
// often constructed as a plain struct literal — see cmd/funcbox-server).
func (inv *Invoker) cache() *effectiveCache {
	inv.cacheOnce.Do(func() { inv.effectiveCache = newEffectiveCache() })
	return inv.effectiveCache
}

// tracker lazily initializes and returns the Invoker's shared
// invocationTracker (see logcapture.go), the same way cache() does for
// effectiveCache.
func (inv *Invoker) tracker() *invocationTracker {
	inv.invocationTrackerOnce.Do(func() { inv.invocationTracker = newInvocationTracker() })
	return inv.invocationTracker
}

// Serve resolves owner/name (already split from the URL path by the
// caller — see server.route) and serves the invocation on w/r.
func (inv *Invoker) Serve(w http.ResponseWriter, r *http.Request, owner, name string) {
	ctx := r.Context()
	functionKey := owner + "/" + name

	h, err := inv.Store.Handles().ByHandle(ctx, owner)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			inv.Metrics.IncInvokeError(functionKey, "not_found")
			writeInvokeError(w, http.StatusNotFound, "not_found", "owner not found")
			return
		}
		inv.Metrics.IncInvokeError(functionKey, "internal")
		inv.logError(r, "resolve owner handle", err)
		writeInvokeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}

	fn, err := inv.Store.Functions().ByOwnerAndName(ctx, h.OwnerType, h.OwnerID, name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			inv.Metrics.IncInvokeError(functionKey, "not_found")
			writeInvokeError(w, http.StatusNotFound, "not_found", "function not found")
			return
		}
		inv.Metrics.IncInvokeError(functionKey, "internal")
		inv.logError(r, "resolve function", err)
		writeInvokeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if fn.ActiveVersionID == nil {
		inv.Metrics.IncInvokeError(functionKey, "not_found")
		writeInvokeError(w, http.StatusNotFound, "not_found", "function has no active version")
		return
	}

	v, err := inv.Store.Functions().Version(ctx, *fn.ActiveVersionID)
	if err != nil {
		inv.Metrics.IncInvokeError(functionKey, "internal")
		inv.logError(r, "load active version", err)
		writeInvokeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}

	var nm manifest.Normalized
	if err := json.Unmarshal(v.Manifest, &nm); err != nil {
		inv.Metrics.IncInvokeError(functionKey, "internal")
		inv.logError(r, "decode stored manifest", err)
		writeInvokeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}

	// effective visibility (manifest ∩ org/workspace max_visibility) and,
	// unless it's public, require and check a caller identity.
	callerEmail, ok := inv.authorize(w, r, fn, nm.Visibility)
	if !ok {
		inv.Metrics.IncInvokeError(functionKey, "unauthorized")
		return // authorize already wrote the response (401/403/redirect)
	}

	timeout := inv.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	// block — org limits are enforced at deploy validation, not here).
	if nm.Timeout != "" {
		if d, err := time.ParseDuration(nm.Timeout); err == nil && d > 0 && d < timeout {
			timeout = d
		}
	}

	invokeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	handler, err := inv.Manager.HandlerFor(invokeCtx, runtime.VersionSpec{
		Key: v.ID,
		Build: func(buildCtx context.Context) (*cfworkers.Pool, error) {
			// Build is only called by Manager.HandlerFor on a cache miss
			// (a new version, or one evicted/invalidated since it was last
			// served), which is exactly what "cold start" means here.
			inv.Metrics.IncPoolColdStart()
			return buildPool(buildCtx, inv.Blob, inv.Store, v, fn.OwnerType, fn.OwnerID, inv.EnvKey, inv.cache(), inv.tracker())
		},
	})
	if err != nil {
		inv.Metrics.IncInvokeError(functionKey, "internal")
		inv.logError(r, "build handler", err)
		writeInvokeError(w, http.StatusInternalServerError, "internal", "failed to start function")
		return
	}

	// Cookie is authorization-carrying and must never reach guest code
	// response/request-header namespace: strip anything the client
	// supplied under it before injecting our own caller-identity header,
	// so a request can never spoof its own caller email.
	r.Header.Del("Cookie")
	stripFuncboxHeaders(r.Header)
	if callerEmail != "" {
		r.Header.Set("X-Funcbox-Caller-Email", callerEmail)
	}

	capt := inv.tracker().begin()
	defer inv.tracker().end()

	start := time.Now()
	iw := &invokeResponseWriter{ResponseWriter: w, ctx: invokeCtx}
	handler.ServeHTTP(iw, r.WithContext(invokeCtx))
	duration := time.Since(start)

	if iw.isLikelyOOM() {
		// Conservative response to an observed OOM abort
		// that this exact instance recovered cleanly.
		inv.Manager.Invalidate(v.ID)
	}

	finalStatus := iw.finalStatus()
	inv.Metrics.ObserveInvoke(functionKey, finalStatus)
	inv.appendInvocationLog(fn.ID, v.ID, r.Method, r.URL.Path, finalStatus, duration, capt)
}

// appendInvocationLog writes the invocation's execution-log row (captured
// guest stdout/stderr and fetch ALLOW/DENY decisions; see logcapture.go)
// best-effort and off the request's own goroutine: by this point the
// response has already been fully written to the client, so this must
// never add latency to it or fail the request over a logging problem. It
// runs against a fresh, short-lived context rather than invokeCtx, which
// Serve's caller cancels (via defer) essentially immediately after Serve
// returns.
func (inv *Invoker) appendInvocationLog(functionID, versionID, method, path string, status int, duration time.Duration, capt *capture) {
	if inv.Store == nil {
		return
	}
	fetchDecisions, err := json.Marshal(capt.fetchDecisionsSnapshot())
	if err != nil {
		fetchDecisions = []byte(`[]`)
	}
	log := &store.InvocationLog{
		FunctionID:     functionID,
		VersionID:      versionID,
		Method:         method,
		Path:           path,
		Status:         status,
		DurationMS:     duration.Milliseconds(),
		Stdout:         capt.stdout.String(),
		Stderr:         capt.stderr.String(),
		FetchDecisions: fetchDecisions,
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := inv.Store.InvocationLogs().Append(ctx, log); err != nil && inv.Logger != nil {
			inv.Logger.Error("invoke: append invocation log", "function_id", functionID, "error", err)
		}
	}()
}

func (inv *Invoker) logError(r *http.Request, msg string, err error) {
	if inv.Logger == nil {
		return
	}
	inv.Logger.Error("invoke: "+msg, "path", r.URL.Path, "error", err)
}

func writeInvokeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}

// authorization: resolve the effective visibility for fn (manifest ∩
// org/workspace max_visibility), and for anything narrower than public,
// require and check a caller identity. On success it returns the caller's
// email (empty for a public function, where there is no caller check at
// all) and true. On failure it writes the appropriate response itself
// (401, 403, or a redirect to the login flow for an HTML browser request)
// and returns false — the only correct action left for Serve is to stop.
func (inv *Invoker) authorize(w http.ResponseWriter, r *http.Request, fn *store.Function, manifestVisibility string) (callerEmail string, ok bool) {
	ctx := r.Context()

	effVis, err := resolveVisibility(ctx, inv.Store, fn.OwnerType, fn.OwnerID, manifestVisibility)
	if err != nil {
		inv.logError(r, "resolve effective visibility", err)
		writeInvokeError(w, http.StatusInternalServerError, "internal", "internal error")
		return "", false
	}
	if effVis == policy.VisibilityPublic {
		return "", true
	}

	if inv.Auth == nil {
		// Fail closed: a non-public function with no auth service
		// configured must never be treated as effectively public.
		writeInvokeError(w, http.StatusForbidden, "forbidden", "this function requires authentication, which is not configured on this server")
		return "", false
	}

	caller, err := inv.Auth.ResolveInvokeCaller(r, inv.Auth.ExtraInvokeAudiences(ctx))
	if err != nil {
		if wantsHTMLRedirect(r) {
			http.Redirect(w, r, auth.LoginURL(r.URL.RequestURI()), http.StatusFound)
			return "", false
		}
		writeInvokeError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return "", false
	}

	if effVis == policy.VisibilityWorkspace {
		member, err := inv.isWorkspaceMember(ctx, fn, caller.ID)
		if err != nil {
			inv.logError(r, "check workspace membership", err)
			writeInvokeError(w, http.StatusInternalServerError, "internal", "internal error")
			return "", false
		}
		if !member {
			writeInvokeError(w, http.StatusForbidden, "forbidden", "not a member of this function's workspace")
			return "", false
		}
	}

	return caller.Email, true
}

// isWorkspaceMember reports whether userID may access a workspace-visibility
// function owned by fn. A user-owned function has no workspace to check
// membership against; its "workspace" audience is just the owner
// themselves (declaring visibility: workspace on a personal function is a
// slightly unusual manifest, but this keeps it meaningful instead of
// either always-deny or always-allow).
func (inv *Invoker) isWorkspaceMember(ctx context.Context, fn *store.Function, userID string) (bool, error) {
	if fn.OwnerType != store.OwnerTypeWorkspace {
		return userID == fn.OwnerID, nil
	}
	return checkWorkspaceMembership(ctx, inv.Store, fn.OwnerID, userID)
}

// wantsHTMLRedirect reports whether r looks like a human browsing
// トークンなし"), for which an authorization failure should redirect to
// the login flow instead of returning a JSON error a browser would just
// render as text.
func wantsHTMLRedirect(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// stripFuncboxHeaders removes every client-supplied X-Funcbox-* request
// injects its own.
func stripFuncboxHeaders(h http.Header) {
	for k := range h {
		if strings.HasPrefix(k, "X-Funcbox-") {
			h.Del(k)
		}
	}
}
