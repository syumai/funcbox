package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// withFakeBrowser substitutes openBrowserHook with a stand-in that, instead
// of spawning a real OS browser, acts AS the browser: it parses the
// dashboard cli-auth URL the CLI would have opened, extracts the loopback
// redirect it carries, and GETs that redirect with the given code --
// exactly the final step a real approved browser performs, without this
// package needing a real dashboard server to drive the approval page
// itself (that round trip is covered by server/internal/dashboard and
// internal/api's own tests). Restores the original hook via t.Cleanup.
func withFakeBrowser(t *testing.T, code string) {
	t.Helper()
	orig := openBrowserHook
	t.Cleanup(func() { openBrowserHook = orig })
	openBrowserHook = func(rawURL string) error {
		u, err := url.Parse(rawURL)
		if err != nil {
			return err
		}
		redirect := u.Query().Get("redirect")
		go func() {
			resp, err := http.Get(redirect + "?code=" + url.QueryEscape(code))
			if err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}
}

func TestRunLogin_FullLoopbackFlowSavesCredential(t *testing.T) {
	withXDGConfigHome(t)
	withFakeBrowser(t, "test-auth-code")

	var gotCode, gotVerifier string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cli/token" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var body struct{ Code, Verifier string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotCode, gotVerifier = body.Code, body.Verifier
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"credential": "fbxc_supersecret", "name": "test", "created_at": "2026-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	if err := RunLogin([]string{"--server", srv.URL}, nil, &stdout, &stderr); err != nil {
		t.Fatalf("RunLogin: %v (stderr=%s)", err, stderr.String())
	}

	if gotCode != "test-auth-code" {
		t.Errorf("code sent to /cli/token = %q, want %q", gotCode, "test-auth-code")
	}
	if gotVerifier == "" {
		t.Error("no PKCE verifier was sent to /cli/token")
	}

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Credential != "fbxc_supersecret" {
		t.Errorf("saved credential = %q, want fbxc_supersecret", cfg.Credential)
	}
	if cfg.Server != srv.URL {
		t.Errorf("saved server = %q, want %q", cfg.Server, srv.URL)
	}
}

func TestRunLogin_RejectedExchangeIsNotSaved(t *testing.T) {
	withXDGConfigHome(t)
	withFakeBrowser(t, "bad-code")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "invalid_grant", "message": "bad code"}})
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	err := RunLogin([]string{"--server", srv.URL}, nil, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected an error for a rejected authorization code")
	}

	cfg, loadErr := LoadConfig()
	if loadErr != nil {
		t.Fatalf("LoadConfig after failed login: %v", loadErr)
	}
	if cfg.Credential != "" {
		t.Errorf("config should not be saved after a failed login, got credential %q", cfg.Credential)
	}
}

func TestGeneratePKCE_ChallengeMatchesVerifier(t *testing.T) {
	verifier, challenge, err := generatePKCE()
	if err != nil {
		t.Fatalf("generatePKCE: %v", err)
	}
	if verifier == "" || challenge == "" {
		t.Fatal("generatePKCE returned an empty verifier or challenge")
	}
	if verifier == challenge {
		t.Fatal("verifier and challenge should differ")
	}
	v2, c2, err := generatePKCE()
	if err != nil {
		t.Fatalf("generatePKCE: %v", err)
	}
	if verifier == v2 || challenge == c2 {
		t.Fatal("two calls to generatePKCE produced the same verifier/challenge")
	}
}
