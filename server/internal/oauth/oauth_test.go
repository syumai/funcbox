// oauth_test.go provides this package's test harness: a real httptest
// server mounting internal/auth's login routes (dev IdP) alongside this
// package's own Handler.Routes(), plus helpers to drive a full browser
// login and a full authorize/consent/token round trip -- mirroring
// internal/auth/login_devflow_test.go's own devLoginTestEnv exactly, since
// this package's flows sit directly on top of that one (GET
// /oauth/authorize hands an unauthenticated browser to the very same
// /auth/login this harness drives).
package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/syumai/funcbox/server/internal/auth"
	"github.com/syumai/funcbox/server/internal/browserjar"
	"github.com/syumai/funcbox/server/internal/store"
	"github.com/syumai/funcbox/server/internal/store/sqlite"
)

const testSessionSecret = "test-oauth-session-secret-value"

// testEnv wires a real httptest.Server mounting /auth/*, /dev/oidc/* (dev
// login), and this package's own Handler.Routes(), matching how
// server/internal/server will mount them all in production (route
// wiring itself is a later step -- see this package's doc comment -- but
// tests need the same shape to drive a real browser round trip).
type testEnv struct {
	t      *testing.T
	server *httptest.Server
	auth   *auth.Auth
	oauth  *Handler
	store  store.Store
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	st, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	a, err := auth.New(auth.Config{
		Mode: auth.ModeDev, BaseURL: srv.URL, ListenAddr: "127.0.0.1:0", SessionSecret: testSessionSecret,
	}, st)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	mux.Handle("/auth/", a.Routes())
	mux.Handle("/dev/oidc/", a.DevRoutes())

	h, err := New(Config{ControlOrigin: srv.URL, SessionSecret: testSessionSecret}, st, a)
	if err != nil {
		t.Fatalf("oauth.New: %v", err)
	}
	mux.Handle("/", h.Routes())

	return &testEnv{t: t, server: srv, auth: a, oauth: h, store: st}
}

// noRedirectClient returns an *http.Client with a real cookie jar
// (browserjar, not net/http/cookiejar -- see login_devflow_test.go's own
// doc comment on why: it's the "__Host-" cookie over plain-http regression
// coverage) that never auto-follows redirects, so tests can inspect each
// hop.
func noRedirectClient() *http.Client {
	return &http.Client{
		Jar: browserjar.New(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// login drives a full browser-less dev login for email through the real
// HTTP endpoints (identical mechanics to
// internal/auth/login_devflow_test.go's devLoginTestEnv.login), returning
// a client whose cookie jar now carries a valid session.
func (env *testEnv) login(t *testing.T, email string) *http.Client {
	t.Helper()
	client := noRedirectClient()

	resp, err := client.Get(env.server.URL + "/auth/login")
	if err != nil {
		t.Fatalf("GET /auth/login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET /auth/login status = %d, want 302", resp.StatusCode)
	}
	authorizeURL, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}

	form := url.Values{
		"client_id":    {authorizeURL.Query().Get("client_id")},
		"redirect_uri": {authorizeURL.Query().Get("redirect_uri")},
		"state":        {authorizeURL.Query().Get("state")},
		"nonce":        {authorizeURL.Query().Get("nonce")},
		"email":        {email},
	}
	resp, err = client.PostForm(env.server.URL+"/dev/oidc/authorize", form)
	if err != nil {
		t.Fatalf("POST /dev/oidc/authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST authorize status = %d, want 302", resp.StatusCode)
	}
	callbackURL := resp.Header.Get("Location")

	resp, err = client.Get(callbackURL)
	if err != nil {
		t.Fatalf("GET callback: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") == "" ||
		!strings.HasPrefix(resp.Header.Get("Location"), "/dashboard") {
		t.Fatalf("login callback did not complete successfully (Location = %q, status = %d)", resp.Header.Get("Location"), resp.StatusCode)
	}
	return client
}

// registerClient drives POST /oauth/register for redirectURIs, returning
// the parsed response.
func (env *testEnv) registerClient(t *testing.T, clientName string, redirectURIs []string) registerResponse {
	t.Helper()
	body := mustJSON(t, registerRequest{ClientName: clientName, RedirectURIs: redirectURIs})
	resp, err := http.Post(env.server.URL+"/oauth/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /oauth/register: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /oauth/register status = %d, body = %s", resp.StatusCode, b)
	}
	var out registerResponse
	if err := decodeJSON(resp.Body, &out); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	return out
}

// pkcePair returns a random PKCE verifier and its S256 challenge.
func pkcePair() (verifier, challenge string) {
	verifier = randomURLToken(32)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return string(b)
}

func decodeJSON(r io.Reader, v any) error {
	return json.NewDecoder(r).Decode(v)
}
