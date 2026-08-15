package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunPrintAccessToken_PrintsOnlyTokenToStdout(t *testing.T) {
	withXDGConfigHome(t)

	var gotAuth, gotTTL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cli/access-token" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		var body struct {
			TTL string `json:"ttl"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotTTL = body.TTL
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fbxa_supersecret", "expires_at": "2026-01-01T00:15:00Z",
		})
	}))
	defer srv.Close()

	if err := SaveConfig(Config{Server: srv.URL, Credential: "fbxc_mycred"}); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if err := RunPrintAccessToken([]string{"--ttl", "5m"}, &stdout, &stderr); err != nil {
		t.Fatalf("RunPrintAccessToken: %v (stderr=%s)", err, stderr.String())
	}

	if gotAuth != "Bearer fbxc_mycred" {
		t.Errorf("Authorization header sent to /cli/access-token = %q", gotAuth)
	}
	if gotTTL != "5m0s" {
		t.Errorf("ttl sent to /cli/access-token = %q, want %q", gotTTL, "5m0s")
	}

	if got := strings.TrimRight(stdout.String(), "\n"); got != "fbxa_supersecret" {
		t.Errorf("stdout = %q, want exactly the token", stdout.String())
	}
	if strings.Count(stdout.String(), "\n") != 1 {
		t.Errorf("stdout should be exactly one line, got %q", stdout.String())
	}
	// The command intentionally prints nothing besides the token: stdout is
	// the token line and stderr stays empty on success, so `$(funcbox
	// print-access-token)` and piped usage never pick up extra noise.
	if stderr.Len() != 0 {
		t.Errorf("stderr should be empty on success, got %q", stderr.String())
	}
}

func TestRunPrintAccessToken_NotLoggedIn(t *testing.T) {
	withXDGConfigHome(t)

	var stdout, stderr bytes.Buffer
	if err := RunPrintAccessToken(nil, &stdout, &stderr); err == nil {
		t.Fatal("expected an error when not logged in")
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout should be empty on error, got %q", stdout.String())
	}
}

func TestRunPrintAccessToken_InvalidTTL(t *testing.T) {
	withXDGConfigHome(t)
	if err := SaveConfig(Config{Server: "https://example.com", Credential: "fbxc_x"}); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if err := RunPrintAccessToken([]string{"--ttl", "not-a-duration"}, &stdout, &stderr); err == nil {
		t.Fatal("expected an error for an invalid --ttl")
	}
}
