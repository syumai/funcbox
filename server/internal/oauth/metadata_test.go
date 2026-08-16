package oauth

import (
	"net/http"
	"testing"
)

func TestAuthorizationServerMetadata_Shape(t *testing.T) {
	env := newTestEnv(t)

	resp, err := http.Get(env.server.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q", ct)
	}

	var meta authorizationServerMetadata
	if err := decodeJSON(resp.Body, &meta); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if meta.Issuer != env.server.URL {
		t.Errorf("issuer = %q, want %q", meta.Issuer, env.server.URL)
	}
	if meta.AuthorizationEndpoint != env.server.URL+"/oauth/authorize" {
		t.Errorf("authorization_endpoint = %q", meta.AuthorizationEndpoint)
	}
	if meta.TokenEndpoint != env.server.URL+"/oauth/token" {
		t.Errorf("token_endpoint = %q", meta.TokenEndpoint)
	}
	if meta.RegistrationEndpoint != env.server.URL+"/oauth/register" {
		t.Errorf("registration_endpoint = %q", meta.RegistrationEndpoint)
	}
	if len(meta.ResponseTypesSupported) != 1 || meta.ResponseTypesSupported[0] != "code" {
		t.Errorf("response_types_supported = %v, want [code]", meta.ResponseTypesSupported)
	}
	wantGrants := map[string]bool{"authorization_code": true, "refresh_token": true}
	if len(meta.GrantTypesSupported) != len(wantGrants) {
		t.Errorf("grant_types_supported = %v", meta.GrantTypesSupported)
	}
	for _, g := range meta.GrantTypesSupported {
		if !wantGrants[g] {
			t.Errorf("unexpected grant type %q", g)
		}
	}
	if len(meta.CodeChallengeMethodsSupported) != 1 || meta.CodeChallengeMethodsSupported[0] != "S256" {
		t.Errorf("code_challenge_methods_supported = %v, want [S256]", meta.CodeChallengeMethodsSupported)
	}
	if len(meta.TokenEndpointAuthMethodsSupported) != 1 || meta.TokenEndpointAuthMethodsSupported[0] != "none" {
		t.Errorf("token_endpoint_auth_methods_supported = %v, want [none] (every client here is public)", meta.TokenEndpointAuthMethodsSupported)
	}
}

func TestProtectedResourceMetadata_Shape(t *testing.T) {
	env := newTestEnv(t)

	resp, err := http.Get(env.server.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var meta protectedResourceMetadata
	if err := decodeJSON(resp.Body, &meta); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if meta.Resource != env.server.URL+"/mcp" {
		t.Errorf("resource = %q, want %q", meta.Resource, env.server.URL+"/mcp")
	}
	if len(meta.AuthorizationServers) != 1 || meta.AuthorizationServers[0] != env.server.URL {
		t.Errorf("authorization_servers = %v, want [%q]", meta.AuthorizationServers, env.server.URL)
	}
}
