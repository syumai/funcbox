package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newFakeAPIServer wraps handler with automatic handling of POST
// /api/v1/cli/access-token: every Client request now mints (and caches) an
// access token first (client.go's ensureAccessToken/mintAccessToken), so
// any test standing up a fake management-API server needs to answer that
// call too, or the real request under test never gets attempted. This
// test double doesn't validate the presented CLI credential -- it isn't
// what these tests are about (see the auth package's and internal/api's
// own tests for that) -- it just unconditionally returns a fresh-looking
// token so handler sees exactly the request the test cares about.
func newFakeAPIServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/cli/access-token" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "fbxa_test-access-token",
				"expires_at":   time.Now().Add(time.Hour).Format(time.RFC3339),
			})
			return
		}
		handler(w, r)
	}))
}
