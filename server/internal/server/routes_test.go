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
	h := New(Deps{Logger: testLogger()})
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
	h := New(Deps{Logger: testLogger()})
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
	h := New(Deps{Logger: testLogger()})
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
	h := New(Deps{Logger: testLogger()})
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
	h := New(Deps{Logger: testLogger()})
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
	h := New(Deps{Logger: testLogger()})
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

func TestHostRouting_ControlOnlyServesControlRoutes(t *testing.T) {
	h := New(Deps{
		Logger:         testLogger(),
		ControlURL:     "https://dashboard.funcbox.example.com",
		FunctionDomain: "run.funcbox.example.com",
	})

	req := httptest.NewRequest(http.MethodGet, "https://dashboard.funcbox.example.com/api/v1/functions", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("control status = %d, want 501", rec.Code)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != "frame-ancestors 'none'" {
		t.Fatalf("control CSP = %q", got)
	}

	req = httptest.NewRequest(http.MethodGet, "https://report.run.funcbox.example.com/api/v1/functions", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("function-host status = %d, want invocation stub 501", rec.Code)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != "" {
		t.Fatalf("function response inherited control CSP %q", got)
	}
}

func TestHostRouting_UnknownFailsClosed(t *testing.T) {
	h := New(Deps{Logger: testLogger(), ControlURL: "https://dashboard.example.com", FunctionDomain: "run.example.com"})
	for _, host := range []string{"unknown.example.net", "a.b.run.example.com", "run.example.com", "127.0.0.1"} {
		req := httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMisdirectedRequest {
			t.Errorf("host %q status = %d, want 421", host, rec.Code)
		}
	}
}

func TestHostRouting_LandingRedirect(t *testing.T) {
	h := New(Deps{Logger: testLogger(), ControlURL: "https://dashboard.example.com", FunctionDomain: "run.example.com", LandingURL: "https://example.com"})
	req := httptest.NewRequest(http.MethodGet, "https://example.com/docs?q=1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusPermanentRedirect || rec.Header().Get("Location") != "https://dashboard.example.com/docs?q=1" {
		t.Fatalf("landing response = %d Location %q", rec.Code, rec.Header().Get("Location"))
	}
	req = httptest.NewRequest(http.MethodPost, "https://example.com/docs", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("landing POST status = %d, want 421", rec.Code)
	}
}

func TestManagedFunctionName(t *testing.T) {
	for _, tt := range []struct{ host, domain, want string }{
		{"report.funcbox.example.com", "funcbox.example.com", "report"},
		{"report.run.funcbox.example.com", "run.funcbox.example.com", "report"},
		{"a.b.run.funcbox.example.com", "run.funcbox.example.com", ""},
		{"run.funcbox.example.com", "run.funcbox.example.com", ""},
	} {
		got, ok := managedFunctionName(tt.host, tt.domain)
		if got != tt.want || ok != (tt.want != "") {
			t.Errorf("managedFunctionName(%q, %q) = %q, %v", tt.host, tt.domain, got, ok)
		}
	}
}
