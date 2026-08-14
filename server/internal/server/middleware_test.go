package server

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRecoverMiddleware_CatchesPanic(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	panicking := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})
	h := recoverMiddleware(logger, panicking)

	req := httptest.NewRequest(http.MethodGet, "/whatever", nil)
	rec := httptest.NewRecorder()

	// Must not panic out of ServeHTTP.
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(logBuf.String(), "panic recovered") {
		t.Fatalf("log output missing panic record: %q", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "boom") {
		t.Fatalf("log output missing panic value: %q", logBuf.String())
	}
}

func TestRecoverMiddleware_PassesThroughNormalResponses(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	h := recoverMiddleware(logger, ok)

	req := httptest.NewRequest(http.MethodGet, "/whatever", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", rec.Code)
	}
}

func TestLoggingMiddleware_RecordsStatus(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	h := loggingMiddleware(logger, next)

	req := httptest.NewRequest(http.MethodGet, "/teapot", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	out := logBuf.String()
	if !strings.Contains(out, "status=418") {
		t.Fatalf("log output missing status=418: %q", out)
	}
	if !strings.Contains(out, "path=/teapot") {
		t.Fatalf("log output missing path: %q", out)
	}
}

func TestLoggingMiddleware_DefaultsTo200WhenHandlerNeverWritesHeader(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("implicit 200"))
	})
	h := loggingMiddleware(logger, next)

	req := httptest.NewRequest(http.MethodGet, "/implicit", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("recorder status = %d, want 200", rec.Code)
	}
	if !strings.Contains(logBuf.String(), "status=200") {
		t.Fatalf("log output missing status=200: %q", logBuf.String())
	}
}

func TestLoggingMiddleware_RedactsInvokeCallbackQuery(t *testing.T) {
	var logBuf bytes.Buffer
	h := loggingMiddleware(slog.New(slog.NewTextHandler(&logBuf, nil)), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/.funcbox/auth/callback?code=top-secret", nil))
	out := logBuf.String()
	if strings.Contains(out, "top-secret") || !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("callback query was not redacted: %q", out)
	}
}

func TestLoopbackAliasRedirectTarget(t *testing.T) {
	req := func(host, method, path string) *http.Request {
		r := httptest.NewRequest(method, path, nil)
		r.Host = host
		return r
	}

	tests := []struct {
		name       string
		canonical  string
		req        *http.Request
		wantTarget string
		wantOK     bool
	}{
		{
			name:       "localhost aliases to 127.0.0.1",
			canonical:  "http://127.0.0.1:8093",
			req:        req("localhost:8093", http.MethodGet, "/dashboard/cli-auth?redirect=x"),
			wantTarget: "http://127.0.0.1:8093/dashboard/cli-auth?redirect=x",
			wantOK:     true,
		},
		{
			name:       "127.0.0.1 aliases to localhost",
			canonical:  "http://localhost:8093",
			req:        req("127.0.0.1:8093", http.MethodGet, "/auth/login"),
			wantTarget: "http://localhost:8093/auth/login",
			wantOK:     true,
		},
		{
			name:       "IPv6 loopback literal aliases to 127.0.0.1",
			canonical:  "http://127.0.0.1:8093",
			req:        req("[::1]:8093", http.MethodGet, "/dashboard"),
			wantTarget: "http://127.0.0.1:8093/dashboard",
			wantOK:     true,
		},
		{
			name:      "already canonical host is untouched",
			canonical: "http://127.0.0.1:8093",
			req:       req("127.0.0.1:8093", http.MethodGet, "/dashboard"),
			wantOK:    false,
		},
		{
			name:       "case-insensitive alias host still matches",
			canonical:  "http://127.0.0.1:8093",
			req:        req("LOCALHOST:8093", http.MethodGet, "/dashboard"),
			wantTarget: "http://127.0.0.1:8093/dashboard",
			wantOK:     true,
		},
		{
			name:      "mismatched port is left alone",
			canonical: "http://127.0.0.1:8093",
			req:       req("localhost:9999", http.MethodGet, "/dashboard"),
			wantOK:    false,
		},
		{
			name:      "non-loopback canonical host is never rewritten",
			canonical: "https://dashboard.example.com",
			req:       req("localhost", http.MethodGet, "/dashboard"),
			wantOK:    false,
		},
		{
			name:      "function-domain host is never a loopback alias",
			canonical: "http://127.0.0.1:8093",
			req:       req("report.run.funcbox.example.com", http.MethodGet, "/"),
			wantOK:    false,
		},
		{
			name:      "/api/v1 is exempt even on a mismatched alias",
			canonical: "http://127.0.0.1:8093",
			req:       req("localhost:8093", http.MethodPost, "/api/v1/cli/token"),
			wantOK:    false,
		},
		{
			name:      "bare /api is exempt too",
			canonical: "http://127.0.0.1:8093",
			req:       req("localhost:8093", http.MethodGet, "/api"),
			wantOK:    false,
		},
		{
			name:      "no canonical origin configured means no redirect",
			canonical: "",
			req:       req("localhost:8093", http.MethodGet, "/dashboard"),
			wantOK:    false,
		},
		{
			name:      "non-loopback request host is left alone",
			canonical: "http://127.0.0.1:8093",
			req:       req("evil.example.com:8093", http.MethodGet, "/dashboard"),
			wantOK:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, ok := loopbackAliasRedirectTarget(tt.canonical, tt.req)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (target=%q)", ok, tt.wantOK, target)
			}
			if ok && target != tt.wantTarget {
				t.Fatalf("target = %q, want %q", target, tt.wantTarget)
			}
		})
	}
}

func TestCanonicalOriginMiddleware_RedirectsAndPreservesMethodSemantics(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	deps := Deps{BaseURL: "http://127.0.0.1:8093"}
	h := canonicalOriginMiddleware(deps, next)

	t.Run("GET gets a 302", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/dashboard/cli-auth?x=1", nil)
		req.Host = "localhost:8093"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", rec.Code)
		}
		if got := rec.Header().Get("Location"); got != "http://127.0.0.1:8093/dashboard/cli-auth?x=1" {
			t.Fatalf("Location = %q", got)
		}
	})

	t.Run("POST gets a 307", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/dashboard/cli-auth/approve", nil)
		req.Host = "localhost:8093"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusTemporaryRedirect {
			t.Fatalf("status = %d, want 307", rec.Code)
		}
	})

	t.Run("already-canonical request passes through", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
		req.Host = "127.0.0.1:8093"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (passthrough)", rec.Code)
		}
	})
}

func TestCanonicalControlOrigin(t *testing.T) {
	if got := canonicalControlOrigin(Deps{ControlURL: "https://dashboard.example.com", BaseURL: "https://dashboard.example.com"}); got != "https://dashboard.example.com" {
		t.Fatalf("ControlURL set: got %q", got)
	}
	if got := canonicalControlOrigin(Deps{BaseURL: "http://127.0.0.1:8093"}); got != "http://127.0.0.1:8093" {
		t.Fatalf("ControlURL empty, BaseURL fallback: got %q", got)
	}
	if got := canonicalControlOrigin(Deps{}); got != "" {
		t.Fatalf("neither set: got %q, want empty", got)
	}
}
