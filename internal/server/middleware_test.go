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
