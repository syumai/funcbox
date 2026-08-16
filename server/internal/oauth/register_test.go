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
