package oauth

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/syumai/funcbox/server/internal/auth"
)

// authorizeParams builds the query string for a well-formed GET
// /oauth/authorize request.
func authorizeParams(clientID, redirectURI, challenge, state, resource string) url.Values {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	if state != "" {
		q.Set("state", state)
	}
	if resource != "" {
		q.Set("resource", resource)
	}
	return q
}

// getBody performs a GET with client and returns the response and its
// fully-read body (the response's own Body is already closed).
func getBody(t *testing.T, client *http.Client, rawURL string) (*http.Response, string) {
	t.Helper()
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(b)
}

// extractFieldValue extracts a hidden <input>'s value from a rendered
// HTML page, the same marker+substring technique
// internal/auth/approval_test.go's GitHub link-confirm test uses.
func extractFieldValue(t *testing.T, body, name string) string {
	t.Helper()
	marker := `name="` + name + `" value="`
	idx := strings.Index(body, marker)
	if idx < 0 {
		t.Fatalf("field %q not found in body:\n%s", name, body)
	}
	rest := body[idx+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatalf("malformed field %q in body:\n%s", name, body)
	}
	return rest[:end]
}

// extractHref extracts the href of the first <a> tag carrying class,
// unescaping HTML entities in the raw attribute value (the page escapes
// "&" as "&amp;" in the redirect URL's query string).
func extractHref(t *testing.T, body, class string) string {
	t.Helper()
	marker := `class="` + class + `"`
	idx := strings.Index(body, marker)
	if idx < 0 {
		t.Fatalf("no element with class %q in body:\n%s", class, body)
	}
	// The href attribute precedes class in this package's rendered markup
	// (`<a href="..." class="...">`); search backward from the class
	// marker for the preceding href="...".
	prefix := body[:idx]
	hrefIdx := strings.LastIndex(prefix, `href="`)
	if hrefIdx < 0 {
		t.Fatalf("no href before class %q in body:\n%s", class, body)
	}
	rest := prefix[hrefIdx+len(`href="`):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatalf("malformed href before class %q in body:\n%s", class, body)
	}
	return strings.NewReplacer("&amp;", "&", "&#34;", `"`, "&#39;", "'").Replace(rest[:end])
}

// driveConsent registers a client, logs in, GETs /oauth/authorize, and
// returns the consent page's parsed pieces: the signed state_token hidden
// field and the Cancel link's target URL. Shared by every test below that
// needs a rendered consent page before deciding whether to approve or
// cancel.
type consentFixture struct {
	serverURL   string
	client      *http.Client
	clientID    string
	redirectURI string
	verifier    string
	challenge   string
	stateToken  string
	cancelURL   string
	oauthState  string
}

func (env *testEnv) driveToConsent(t *testing.T, email, redirectURI, oauthState, resource string) consentFixture {
	t.Helper()
	reg := env.registerClient(t, "Test Client", []string{redirectURI})
	verifier, challenge := pkcePair()
	client := env.login(t, email)

	authURL := env.server.URL + "/oauth/authorize?" + authorizeParams(reg.ClientID, redirectURI, challenge, oauthState, resource).Encode()
	resp, body := getBody(t, client, authURL)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /oauth/authorize status = %d, body = %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `class="wp-card"`) {
		t.Fatalf("consent page does not use the shared webpage.Page shell; got: %s", body)
	}

	return consentFixture{
		serverURL: env.server.URL, client: client, clientID: reg.ClientID, redirectURI: redirectURI,
		verifier: verifier, challenge: challenge, oauthState: oauthState,
		stateToken: extractFieldValue(t, body, "state_token"),
		cancelURL:  extractHref(t, body, "wp-btn wp-btn-ghost"),
	}
}

// approve POSTs the consent decision and returns the final redirect
// Location.
func (f consentFixture) approve(t *testing.T) string {
	t.Helper()
	resp, err := f.client.PostForm(f.serverURL+"/oauth/authorize", url.Values{"state_token": {f.stateToken}})
	if err != nil {
		t.Fatalf("POST /oauth/authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST /oauth/authorize status = %d, want 302", resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

func TestAuthorize_UnauthenticatedRedirectsIntoLoginFlow(t *testing.T) {
	env := newTestEnv(t)
	reg := env.registerClient(t, "Test Client", []string{"https://client.example.com/callback"})
	_, challenge := pkcePair()

	client := noRedirectClient()
	authURL := env.server.URL + "/oauth/authorize?" + authorizeParams(reg.ClientID, "https://client.example.com/callback", challenge, "xyz", "").Encode()
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 (redirect into login)", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/auth/login?return_to=") {
		t.Fatalf("Location = %q, want a /auth/login redirect carrying return_to", loc)
	}
	if !strings.Contains(loc, url.QueryEscape("/oauth/authorize")) {
		t.Fatalf("Location = %q, does not carry the original /oauth/authorize request as return_to", loc)
	}
}

func TestAuthorize_UnknownClientID_DirectError(t *testing.T) {
	env := newTestEnv(t)
	client := env.login(t, "alice@example.com")
	resp, _ := getBody(t, client, env.server.URL+"/oauth/authorize?"+authorizeParams("no-such-client", "https://client.example.com/cb", "x", "s", "").Encode())
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAuthorize_RedirectURIMismatch_DirectError(t *testing.T) {
	env := newTestEnv(t)
	reg := env.registerClient(t, "Test Client", []string{"https://client.example.com/callback"})
	client := env.login(t, "alice@example.com")
	_, challenge := pkcePair()

	authURL := env.server.URL + "/oauth/authorize?" + authorizeParams(reg.ClientID, "https://attacker.example.com/callback", challenge, "s", "").Encode()
	resp, _ := getBody(t, client, authURL)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (redirect_uri not registered must NOT redirect anywhere)", resp.StatusCode)
	}
}

func TestAuthorize_MissingPKCEChallenge_RedirectsWithError(t *testing.T) {
	env := newTestEnv(t)
	reg := env.registerClient(t, "Test Client", []string{"https://client.example.com/callback"})
	client := env.login(t, "alice@example.com")

	q := authorizeParams(reg.ClientID, "https://client.example.com/callback", "not-a-valid-challenge", "s1", "")
	authURL := env.server.URL + "/oauth/authorize?" + q.Encode()
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 (redirect_uri IS registered, so errors redirect)", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if loc.Query().Get("error") != errInvalidRequest {
		t.Errorf("error = %q, want %q", loc.Query().Get("error"), errInvalidRequest)
	}
	if loc.Query().Get("state") != "s1" {
		t.Errorf("state = %q, want echoed %q", loc.Query().Get("state"), "s1")
	}
}

func TestAuthorize_Cancel_RedirectsWithAccessDenied(t *testing.T) {
	env := newTestEnv(t)
	f := env.driveToConsent(t, "alice@example.com", "https://client.example.com/callback", "state-123", "")

	loc, err := url.Parse(f.cancelURL)
	if err != nil {
		t.Fatalf("parse cancel URL: %v", err)
	}
	if loc.Scheme+"://"+loc.Host+loc.Path != "https://client.example.com/callback" {
		t.Errorf("cancel URL base = %q, want the client's redirect_uri", f.cancelURL)
	}
	if loc.Query().Get("error") != errAccessDenied {
		t.Errorf("error = %q, want %q", loc.Query().Get("error"), errAccessDenied)
	}
	if loc.Query().Get("state") != "state-123" {
		t.Errorf("state = %q, want echoed %q", loc.Query().Get("state"), "state-123")
	}
}

func TestAuthorizeToToken_FullFlowIssuesTokensWithMCPAudience(t *testing.T) {
	env := newTestEnv(t)
	// The resource indicator, when present, must exactly equal THIS
	// server's own protected resource identifier (ControlOrigin + "/mcp")
	// -- see authorize.go's RFC 8707 validation -- which for this test
	// harness is env.server.URL, not some other origin.
	f := env.driveToConsent(t, "alice@example.com", "https://client.example.com/callback", "state-abc", env.server.URL+"/mcp")

	loc := f.approve(t)
	redirLoc, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse approve redirect: %v", err)
	}
	if redirLoc.Scheme+"://"+redirLoc.Host+redirLoc.Path != f.redirectURI {
		t.Fatalf("approve redirect = %q, want it to target %q", loc, f.redirectURI)
	}
	code := redirLoc.Query().Get("code")
	if code == "" {
		t.Fatalf("approve redirect %q carries no code", loc)
	}
	if redirLoc.Query().Get("state") != f.oauthState {
		t.Errorf("state = %q, want echoed %q", redirLoc.Query().Get("state"), f.oauthState)
	}

	tok := env.exchangeCode(t, f.clientID, f.redirectURI, code, f.verifier)
	if !strings.HasPrefix(tok.AccessToken, "fbxa_") {
		t.Errorf("access_token = %q, want fbxa_ prefix", tok.AccessToken)
	}
	if !strings.HasPrefix(tok.RefreshToken, "fbxr_") {
		t.Errorf("refresh_token = %q, want fbxr_ prefix", tok.RefreshToken)
	}
	if tok.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", tok.TokenType)
	}
	if tok.ExpiresIn <= 0 {
		t.Errorf("expires_in = %d, want > 0", tok.ExpiresIn)
	}

	aud, ok := env.auth.AccessTokenAudience(tok.AccessToken)
	if !ok || aud != auth.AudienceMCP {
		t.Errorf("AccessTokenAudience = (%q, %v), want (%q, true)", aud, ok, auth.AudienceMCP)
	}
}

func TestAuthorize_WrongResourceRejectedWithInvalidTarget(t *testing.T) {
	env := newTestEnv(t)
	reg := env.registerClient(t, "Test Client", []string{"https://client.example.com/callback"})
	client := env.login(t, "alice@example.com")
	_, challenge := pkcePair()

	q := authorizeParams(reg.ClientID, "https://client.example.com/callback", challenge, "s1", "https://some-other-server.example.com/mcp")
	authURL := env.server.URL + "/oauth/authorize?" + q.Encode()
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 (redirect_uri IS registered, so errors redirect)", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if loc.Query().Get("error") != errInvalidTarget {
		t.Errorf("error = %q, want %q", loc.Query().Get("error"), errInvalidTarget)
	}
}

func TestAuthorize_DuplicateResourceRejectedWithInvalidTarget(t *testing.T) {
	env := newTestEnv(t)
	reg := env.registerClient(t, "Test Client", []string{"https://client.example.com/callback"})
	client := env.login(t, "alice@example.com")
	_, challenge := pkcePair()

	q := authorizeParams(reg.ClientID, "https://client.example.com/callback", challenge, "s1", "")
	q.Add("resource", env.server.URL+"/mcp")
	q.Add("resource", "https://attacker.example.com/mcp")
	authURL := env.server.URL + "/oauth/authorize?" + q.Encode()
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if loc.Query().Get("error") != errInvalidTarget {
		t.Errorf("error = %q, want %q", loc.Query().Get("error"), errInvalidTarget)
	}
}

func TestAuthorize_AbsentResourceStillWorks(t *testing.T) {
	env := newTestEnv(t)
	f := env.driveToConsent(t, "alice@example.com", "https://client.example.com/callback", "s", "")
	loc := f.approve(t)
	redirLoc, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse approve redirect: %v", err)
	}
	code := redirLoc.Query().Get("code")
	if code == "" {
		t.Fatalf("approve redirect %q carries no code", loc)
	}

	tok := env.exchangeCode(t, f.clientID, f.redirectURI, code, f.verifier)
	aud, ok := env.auth.AccessTokenAudience(tok.AccessToken)
	if !ok || aud != auth.AudienceMCP {
		t.Errorf("AccessTokenAudience = (%q, %v), want (%q, true) -- an absent resource must still default to the single protected resource", aud, ok, auth.AudienceMCP)
	}
}

func TestAuthorizeToToken_CodeReuseRejected(t *testing.T) {
	env := newTestEnv(t)
	f := env.driveToConsent(t, "alice@example.com", "https://client.example.com/callback", "s", "")
	loc := f.approve(t)
	redirLoc, _ := url.Parse(loc)
	code := redirLoc.Query().Get("code")

	env.exchangeCode(t, f.clientID, f.redirectURI, code, f.verifier)

	resp := env.postToken(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {f.verifier},
		"redirect_uri": {f.redirectURI}, "client_id": {f.clientID},
	})
	assertOAuthError(t, resp, http.StatusBadRequest, errInvalidGrant)
}

func TestAuthorizeToToken_PKCEMismatchRejected(t *testing.T) {
	env := newTestEnv(t)
	f := env.driveToConsent(t, "alice@example.com", "https://client.example.com/callback", "s", "")
	loc := f.approve(t)
	redirLoc, _ := url.Parse(loc)
	code := redirLoc.Query().Get("code")

	resp := env.postToken(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {"wrong-verifier-entirely"},
		"redirect_uri": {f.redirectURI}, "client_id": {f.clientID},
	})
	assertOAuthError(t, resp, http.StatusBadRequest, errInvalidGrant)
}

func TestAuthorizeToToken_RedirectURIMismatchRejected(t *testing.T) {
	env := newTestEnv(t)
	f := env.driveToConsent(t, "alice@example.com", "https://client.example.com/callback", "s", "")
	loc := f.approve(t)
	redirLoc, _ := url.Parse(loc)
	code := redirLoc.Query().Get("code")

	resp := env.postToken(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {f.verifier},
		"redirect_uri": {"https://client.example.com/OTHER-callback"}, "client_id": {f.clientID},
	})
	assertOAuthError(t, resp, http.StatusBadRequest, errInvalidGrant)
}
