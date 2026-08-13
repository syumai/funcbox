// Package metrics implements funcbox-server's optional Prometheus
// only when FUNCBOX_METRICS=1 (internal/server mounts it; see that
// package's routes.go).
//
// This package is server-only: it is not imported by the funcbox CLI
// binary (cmd/funcbox) or any of the shared packages
// (manifest/bundle/policy/runtime).
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics is funcbox-server's Prometheus instrumentation. Every recording
// method is nil-receiver-safe and a no-op when disabled, so call sites
// never need their own "is metrics enabled" branch -- they just always
// call through *Metrics, including a nil one (tests that build
// server.Deps/invoke.Invoker without setting a Metrics field get a nil
// pointer, which behaves identically to New(false)).
type Metrics struct {
	enabled bool
	reg     *prometheus.Registry

	httpRequests   *prometheus.CounterVec
	httpDuration   *prometheus.HistogramVec
	invokeTotal    *prometheus.CounterVec
	invokeErrors   *prometheus.CounterVec
	poolColdStarts prometheus.Counter
}

// New builds a Metrics. When enabled is false (the FUNCBOX_METRICS=1 gate
// is off), it returns a fully functional no-op: every recording method
// does nothing and Handler returns nil, so cmd/funcbox-server never mounts
// GET /metrics at all rather than mounting an always-empty one.
func New(enabled bool) *Metrics {
	m := &Metrics{enabled: enabled}
	if !enabled {
		return m
	}

	reg := prometheus.NewRegistry()
	factory := promauto.With(reg)
	m.reg = reg

	m.httpRequests = factory.NewCounterVec(prometheus.CounterOpts{
		Name: "funcbox_http_requests_total",
		Help: "Total HTTP requests, by route class, method, and status class.",
	}, []string{"route", "method", "status"})

	m.httpDuration = factory.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "funcbox_http_request_duration_seconds",
		Help:    "HTTP request duration in seconds, by route class and method.",
		Buckets: prometheus.DefBuckets,
	}, []string{"route", "method"})

	m.invokeTotal = factory.NewCounterVec(prometheus.CounterOpts{
		Name: "funcbox_invoke_total",
		Help: "Total function invocations, by function (owner/name) and status class.",
	}, []string{"function", "status"})

	m.invokeErrors = factory.NewCounterVec(prometheus.CounterOpts{
		Name: "funcbox_invoke_errors_total",
		Help: "Total function invocation errors, by function (owner/name) and reason.",
	}, []string{"function", "reason"})

	m.poolColdStarts = factory.NewCounter(prometheus.CounterOpts{
		Name: "funcbox_pool_cold_starts_total",
		Help: "Total runtime pool cold starts (a function version's pool being built for the first time, or rebuilt after eviction/invalidation).",
	})

	// Standard process/Go runtime collectors (goroutines, GC, memory, file
	// descriptors, ...) -- the usual baseline every Prometheus-instrumented
	// Go service exposes, at negligible cost.
	reg.MustRegister(prometheus.NewGoCollector())
	reg.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	return m
}

// Handler returns the /metrics HTTP handler, or nil if metrics are
// disabled (New(false), or a nil *Metrics) -- callers must check for nil
// before mounting it (see internal/server/routes.go).
func (m *Metrics) Handler() http.Handler {
	if m == nil || !m.enabled {
		return nil
	}
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// ObserveHTTPRequest records one completed HTTP request against the
// funcbox_http_requests_total / funcbox_http_request_duration_seconds
// series. route is a coarse route class (e.g. "api", "dashboard",
// "invoke"), not the raw path -- a per-path label would be an unbounded
// cardinality explosion across arbitrary function owner/name/subpaths.
func (m *Metrics) ObserveHTTPRequest(route, method string, status int, dur time.Duration) {
	if m == nil || !m.enabled {
		return
	}
	m.httpRequests.WithLabelValues(route, method, statusClass(status)).Inc()
	m.httpDuration.WithLabelValues(route, method).Observe(dur.Seconds())
}

// ObserveInvoke records one completed function invocation against
// funcbox_invoke_total. functionKey is typically "owner/name".
func (m *Metrics) ObserveInvoke(functionKey string, status int) {
	if m == nil || !m.enabled {
		return
	}
	m.invokeTotal.WithLabelValues(functionKey, statusClass(status)).Inc()
}

// IncInvokeError records one invocation-path failure (not_found,
// unauthorized, forbidden, internal, ...) against funcbox_invoke_errors_total.
func (m *Metrics) IncInvokeError(functionKey, reason string) {
	if m == nil || !m.enabled {
		return
	}
	m.invokeErrors.WithLabelValues(functionKey, reason).Inc()
}

// IncPoolColdStart records one runtime.Manager pool cold start.
func (m *Metrics) IncPoolColdStart() {
	if m == nil || !m.enabled {
		return
	}
	m.poolColdStarts.Inc()
}

// statusClass buckets an HTTP status code into Prometheus's conventional
// "2xx"/"4xx"/... label value, keeping the status label's cardinality
// small and fixed.
func statusClass(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	case status >= 200:
		return "2xx"
	default:
		return "other"
	}
}
