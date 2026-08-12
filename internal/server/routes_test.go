package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestHealthz(t *testing.T) {
	h := New(testLogger())
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Fatalf("body = %q, want %q", rec.Body.String(), "ok")
	}
}

func TestRootRedirectsToDashboard(t *testing.T) {
	h := New(testLogger())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Fatalf("Location = %q, want /dashboard", loc)
	}
}

func TestReservedRouteStubs(t *testing.T) {
	h := New(testLogger())
	for _, path := range []string{"/dashboard", "/dashboard/settings", "/api", "/api/v1/functions", "/auth/login", "/dev/oidc/jwks", "/assets/logo.png"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusNotImplemented {
				t.Fatalf("status = %d, want 501", rec.Code)
			}
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("response body is not JSON: %v (%q)", err, rec.Body.String())
			}
			if _, ok := body["error"]; !ok {
				t.Fatalf("response body missing \"error\" key: %q", rec.Body.String())
			}
		})
	}
}

func TestFunctionInvokeStub(t *testing.T) {
	h := New(testLogger())
	for _, path := range []string{"/alice/hello", "/alice/hello/sub/path", "/my-workspace/my-func"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusNotImplemented {
				t.Fatalf("status = %d, want 501", rec.Code)
			}
		})
	}
}

func TestFunctionInvokeStub_AllMethods(t *testing.T) {
	h := New(testLogger())
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/alice/hello", nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotImplemented {
				t.Fatalf("status = %d, want 501", rec.Code)
			}
		})
	}
}

func TestSingleSegmentNonReservedIs404(t *testing.T) {
	h := New(testLogger())
	req := httptest.NewRequest(http.MethodGet, "/onlyowner", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestPathSegments(t *testing.T) {
	tests := []struct {
		path string
		want []string
	}{
		{path: "/", want: nil},
		{path: "", want: nil},
		{path: "/foo", want: []string{"foo"}},
		{path: "/foo/bar", want: []string{"foo", "bar"}},
		{path: "/foo/bar/", want: []string{"foo", "bar"}},
		{path: "//foo//bar//", want: []string{"foo", "", "bar"}},
	}
	for _, tt := range tests {
		got := pathSegments(tt.path)
		if len(got) != len(tt.want) {
			t.Errorf("pathSegments(%q) = %v, want %v", tt.path, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("pathSegments(%q) = %v, want %v", tt.path, got, tt.want)
				break
			}
		}
	}
}
