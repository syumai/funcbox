package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunListPrintsCanonicalFunctionURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"functions": []map[string]any{{
			"name": "report", "url": "https://report.run.funcbox.example.com/", "updated_at": "2026-08-14T00:00:00Z",
		}}})
	}))
	defer srv.Close()
	t.Setenv("FUNCBOX_SERVER", srv.URL)
	t.Setenv("FUNCBOX_API_TOKEN", "fbx_test")
	withXDGConfigHome(t)

	var stdout, stderr bytes.Buffer
	if err := RunList(nil, &stdout, &stderr); err != nil {
		t.Fatalf("RunList: %v", err)
	}
	if !strings.Contains(stdout.String(), "https://report.run.funcbox.example.com/") {
		t.Fatalf("stdout = %q, want canonical function URL", stdout.String())
	}
}
