package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunLoginSavesConfigOnValidToken(t *testing.T) {
	withXDGConfigHome(t)

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "u1", "email": "user@example.com"})
	}))
	defer srv.Close()

	stdin := strings.NewReader("fbx_supersecret\n")
	var stdout, stderr bytes.Buffer
	err := RunLogin([]string{"--server", srv.URL}, stdin, &stdout, &stderr)
	if err != nil {
		t.Fatalf("RunLogin: %v (stderr=%s)", err, stderr.String())
	}
	if gotAuth != "Bearer fbx_supersecret" {
		t.Errorf("Authorization header sent to /api/v1/me = %q", gotAuth)
	}

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Token != "fbx_supersecret" {
		t.Errorf("saved token = %q, want fbx_supersecret", cfg.Token)
	}
	if cfg.Server != srv.URL {
		t.Errorf("saved server = %q, want %q", cfg.Server, srv.URL)
	}
}

func TestRunLoginRejectsInvalidToken(t *testing.T) {
	withXDGConfigHome(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "unauthorized", "message": "invalid token"}})
	}))
	defer srv.Close()

	stdin := strings.NewReader("fbx_bad\n")
	var stdout, stderr bytes.Buffer
	err := RunLogin([]string{"--server", srv.URL}, stdin, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected an error for a rejected token")
	}

	if _, loadErr := LoadConfig(); loadErr != nil {
		t.Fatalf("LoadConfig after failed login: %v", loadErr)
	}
	cfg, _ := LoadConfig()
	if cfg.Token != "" {
		t.Errorf("config should not be saved after a failed login, got token %q", cfg.Token)
	}
}
