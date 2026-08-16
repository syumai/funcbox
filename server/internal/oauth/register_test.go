package oauth

import (
	"net/http"
	"strings"
	"testing"
)

func TestRegister_HappyPath(t *testing.T) {
	env := newTestEnv(t)

	resp := env.registerClient(t, "Test MCP Client", []string{"https://client.example.com/callback"})
	if resp.ClientID == "" {
		t.Fatal("client_id is empty")
	}
	if resp.ClientName != "Test MCP Client" {
		t.Errorf("client_name = %q", resp.ClientName)
	}
	if resp.TokenEndpointAuthMethod != "none" {
		t.Errorf("token_endpoint_auth_method = %q, want %q (public client, no secret)", resp.TokenEndpointAuthMethod, "none")
	}
	if len(resp.RedirectURIs) != 1 || resp.RedirectURIs[0] != "https://client.example.com/callback" {
		t.Errorf("redirect_uris = %v", resp.RedirectURIs)
	}
	if resp.ClientIDIssuedAt == 0 {
		t.Error("client_id_issued_at is zero")
	}

	// The registered client must actually be persisted and retrievable.
	stored, err := env.store.OAuthClients().ByID(t.Context(), resp.ClientID)
	if err != nil {
		t.Fatalf("OAuthClients().ByID: %v", err)
	}
	if stored.Name != "Test MCP Client" {
		t.Errorf("stored.Name = %q", stored.Name)
	}
}

func TestRegister_AcceptsLoopbackHTTPRedirectURI(t *testing.T) {
	env := newTestEnv(t)
	resp := env.registerClient(t, "Native client", []string{"http://127.0.0.1:44123/callback"})
	if resp.ClientID == "" {
		t.Fatal("client_id is empty")
	}
}

func TestRegister_RejectsEmptyRedirectURIs(t *testing.T) {
	env := newTestEnv(t)
	body := mustJSON(t, registerRequest{ClientName: "Bad client", RedirectURIs: nil})
	resp, err := http.Post(env.server.URL+"/oauth/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	var oe oauthError
	if err := decodeJSON(resp.Body, &oe); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oe.Error != errInvalidClientMetadata {
		t.Errorf("error = %q, want %q", oe.Error, errInvalidClientMetadata)
	}
}

func TestRegister_RejectsOversizedClientName(t *testing.T) {
	env := newTestEnv(t)
	body := mustJSON(t, registerRequest{
		ClientName:   strings.Repeat("x", maxClientNameLength+1),
		RedirectURIs: []string{"https://client.example.com/callback"},
	})
	resp, err := http.Post(env.server.URL+"/oauth/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	var oe oauthError
	if err := decodeJSON(resp.Body, &oe); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oe.Error != errInvalidClientMetadata {
		t.Errorf("error = %q, want %q", oe.Error, errInvalidClientMetadata)
	}
}

func TestRegister_RejectsTooManyRedirectURIs(t *testing.T) {
	env := newTestEnv(t)
	uris := make([]string, maxRedirectURIs+1)
	for i := range uris {
		uris[i] = "https://client.example.com/callback"
	}
	body := mustJSON(t, registerRequest{ClientName: "Too many URIs", RedirectURIs: uris})
	resp, err := http.Post(env.server.URL+"/oauth/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	var oe oauthError
	if err := decodeJSON(resp.Body, &oe); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oe.Error != errInvalidClientMetadata {
		t.Errorf("error = %q, want %q", oe.Error, errInvalidClientMetadata)
	}
}

func TestRegister_RejectsOversizedRedirectURI(t *testing.T) {
	env := newTestEnv(t)
	huge := "https://client.example.com/" + strings.Repeat("x", maxRedirectURILength)
	body := mustJSON(t, registerRequest{ClientName: "Huge URI", RedirectURIs: []string{huge}})
	resp, err := http.Post(env.server.URL+"/oauth/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	var oe oauthError
	if err := decodeJSON(resp.Body, &oe); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oe.Error != errInvalidClientMetadata {
		t.Errorf("error = %q, want %q", oe.Error, errInvalidClientMetadata)
	}
}

// TestRegister_RateLimitTripsAfterBurst drives registerRateBurst+1 rapid
// registrations from the same source (every request in this test comes
// from the Go http.Client's own loopback connection, so they all share one
// clientIP) and confirms the one past the burst gets a 429 with a standard
// OAuth error body, while everything up to and including the burst
// succeeds.
func TestRegister_RateLimitTripsAfterBurst(t *testing.T) {
	env := newTestEnv(t)

	for i := 0; i < registerRateBurst; i++ {
		resp, err := http.Post(env.server.URL+"/oauth/register", "application/json",
			strings.NewReader(mustJSON(t, registerRequest{ClientName: "burst client", RedirectURIs: []string{"https://client.example.com/cb"}})))
		if err != nil {
			t.Fatalf("POST #%d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("POST #%d status = %d, want 201 (within burst)", i, resp.StatusCode)
		}
	}

	resp, err := http.Post(env.server.URL+"/oauth/register", "application/json",
		strings.NewReader(mustJSON(t, registerRequest{ClientName: "one too many", RedirectURIs: []string{"https://client.example.com/cb"}})))
	if err != nil {
		t.Fatalf("POST over burst: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
	var oe oauthError
	if err := decodeJSON(resp.Body, &oe); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if oe.Error != errTemporarilyUnavailable {
		t.Errorf("error = %q, want %q", oe.Error, errTemporarilyUnavailable)
	}
}

func TestRegister_RejectsInvalidRedirectURIs(t *testing.T) {
	env := newTestEnv(t)
	cases := [][]string{
		{"not-a-url"},
		{"ftp://example.com/callback"},
		{"http://evil.example.com/callback"},        // http, but not loopback
		{"https://client.example.com/cb#fragment"},  // fragment forbidden
		{"https://user:pass@client.example.com/cb"}, // userinfo forbidden
	}
	for _, uris := range cases {
		body := mustJSON(t, registerRequest{ClientName: "Bad client", RedirectURIs: uris})
		resp, err := http.Post(env.server.URL+"/oauth/register", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("redirect_uris=%v: status = %d, want 400", uris, resp.StatusCode)
		}
	}
}
