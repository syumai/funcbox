package server

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/syumai/funcbox/server/internal/metrics"
)

// statusWriter wraps an http.ResponseWriter to capture the status
// code that was actually written, for logging.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// recoverMiddleware catches panics from the wrapped handler, logs
// them with a stack trace, and responds 500 instead of crashing the
// process. It must run inside loggingMiddleware (closer to the
// handler) so that a recovered panic's 500 status still gets logged.
func recoverMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error("panic recovered",
					"panic", rec,
					"method", r.Method,
					"path", r.URL.Path,
					"stack", string(debug.Stack()),
				)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs each request's method, path, status, and
// duration once it completes.
func loggingMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"duration", time.Since(start),
		)
	})
}

// metricsMiddleware records every request's route class, method, status,
// (metrics disabled, or a caller that never set Deps.Metrics) -- every
// *metrics.Metrics method is nil-receiver-safe, so this middleware is
// always installed unconditionally rather than only when metrics are
// enabled, keeping New's middleware chain the same shape either way.
func metricsMiddleware(mtr *metrics.Metrics, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		mtr.ObserveHTTPRequest(routeClass(r.URL.Path), r.Method, sw.status, time.Since(start))
	})
}

// routeClass buckets a request path into a coarse, fixed-cardinality label
// for metricsMiddleware: per-path labels would blow up cardinality across
// arbitrary function owner/name/subpaths (see Metrics.ObserveHTTPRequest's
// doc comment). Mirrors router.ServeHTTP's own dispatch logic in routes.go
// (kept as a small, deliberate duplication rather than threading a
// classification result out of the router, since the two must only agree
// on classification, not on any actual handling behavior).
func routeClass(path string) string {
	segments := pathSegments(path)
	if len(segments) == 0 {
		return "root"
	}
	switch segments[0] {
	case "api", "dashboard", "auth", "dev", "metrics":
		return segments[0]
	case "healthz":
		return "healthz"
	default:
		if len(segments) >= 2 {
			return "invoke"
		}
		return "other"
	}
}
