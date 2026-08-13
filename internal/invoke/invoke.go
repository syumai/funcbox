package invoke

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/goccy/go-spidermonkey/compat/cfworkers"

	"github.com/syumai/funcbox/internal/blob"
	"github.com/syumai/funcbox/internal/manifest"
	"github.com/syumai/funcbox/internal/runtime"
	"github.com/syumai/funcbox/internal/store"
)

// DefaultTimeout is used when Invoker.Timeout is unset.
const DefaultTimeout = 30 * time.Second

// Invoker resolves /{owner}/{func}[/...] to a function's active version and
// serves the request through its runtime.Manager-owned pool
// (tmp/02-architecture.md "関数呼び出し").
type Invoker struct {
	Store   store.Store
	Blob    blob.Store
	Manager *runtime.Manager
	Logger  *slog.Logger

	// Timeout bounds every invocation (FUNCBOX_INVOKE_TIMEOUT default).
	// Per tmp/phase0-findings.md item 4, this deadline is not just a
	// client-response nicety: it is the ONLY mechanism that frees a
	// runaway instance's pool slot, so Serve always wraps the request
	// context with it (narrowing further if the manifest declares a
	// shorter timeout) before calling the pool handler — never with an
	// undeadlined context. Zero means DefaultTimeout.
	Timeout time.Duration
}

// Serve resolves owner/name (already split from the URL path by the
// caller — see server.route) and serves the invocation on w/r.
func (inv *Invoker) Serve(w http.ResponseWriter, r *http.Request, owner, name string) {
	ctx := r.Context()

	h, err := inv.Store.Handles().ByHandle(ctx, owner)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeInvokeError(w, http.StatusNotFound, "not_found", "owner not found")
			return
		}
		inv.logError(r, "resolve owner handle", err)
		writeInvokeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}

	fn, err := inv.Store.Functions().ByOwnerAndName(ctx, h.OwnerType, h.OwnerID, name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeInvokeError(w, http.StatusNotFound, "not_found", "function not found")
			return
		}
		inv.logError(r, "resolve function", err)
		writeInvokeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if fn.ActiveVersionID == nil {
		writeInvokeError(w, http.StatusNotFound, "not_found", "function has no active version")
		return
	}

	v, err := inv.Store.Functions().Version(ctx, *fn.ActiveVersionID)
	if err != nil {
		inv.logError(r, "load active version", err)
		writeInvokeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}

	timeout := inv.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	// Effective timeout = min(manifest, org/workspace limit) per
	// tmp/04-manifest.md; Phase 1 has no org/workspace limit yet.
	if d, ok := manifestTimeoutOverride(v.Manifest); ok && d < timeout {
		timeout = d
	}

	invokeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	handler, err := inv.Manager.HandlerFor(invokeCtx, runtime.VersionSpec{
		Key: v.ID,
		Build: func(buildCtx context.Context) (*cfworkers.Pool, error) {
			return buildPool(buildCtx, inv.Blob, inv.Store, v)
		},
	})
	if err != nil {
		inv.logError(r, "build handler", err)
		writeInvokeError(w, http.StatusInternalServerError, "internal", "failed to start function")
		return
	}

	// Cookie is authorization-carrying and must never reach guest code
	// (tmp/07-http-api.md §7.2).
	r.Header.Del("Cookie")

	iw := &invokeResponseWriter{ResponseWriter: w, ctx: invokeCtx}
	handler.ServeHTTP(iw, r.WithContext(invokeCtx))

	if iw.isLikelyOOM() {
		// Conservative response to an observed OOM abort
		// (tmp/phase0-findings.md item 5): invalidate rather than trust
		// that this exact instance recovered cleanly.
		inv.Manager.Invalidate(v.ID)
	}
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

// manifestTimeoutOverride decodes a stored version's normalized manifest
// JSON just far enough to read its Timeout field.
func manifestTimeoutOverride(manifestJSON []byte) (time.Duration, bool) {
	var nm manifest.Normalized
	if err := json.Unmarshal(manifestJSON, &nm); err != nil || nm.Timeout == "" {
		return 0, false
	}
	d, err := time.ParseDuration(nm.Timeout)
	if err != nil || d <= 0 {
		return 0, false
	}
	return d, true
}
