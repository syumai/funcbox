// Package funcbox_test exercises funcbox's end-to-end path: authenticate
// (dev-mode stub IdP), deploy a function through the management API, then
// (internal/auth, internal/service, internal/api, internal/invoke,
// internal/server) against real sqlite and filesystem-blob backends
// (in-memory / a temp dir, so no external state is needed to run it).
package funcbox_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/syumai/funcbox/bundle"
	"github.com/syumai/funcbox/runtime"
	"github.com/syumai/funcbox/server/internal/api"
	"github.com/syumai/funcbox/server/internal/auth"
	blobfs "github.com/syumai/funcbox/server/internal/blob/fs"
	"github.com/syumai/funcbox/server/internal/browserjar"
	fcrypto "github.com/syumai/funcbox/server/internal/crypto"
	"github.com/syumai/funcbox/server/internal/invoke"
	"github.com/syumai/funcbox/server/internal/server"
	"github.com/syumai/funcbox/server/internal/service"
	"github.com/syumai/funcbox/server/internal/settings"
	"github.com/syumai/funcbox/server/internal/store"
	"github.com/syumai/funcbox/server/internal/store/sqlite"
)

const testSessionSecret = "e2e-test-session-secret"

// testEnv is one fully-wired funcbox-server instance (real sqlite +
// filesystem blob + runtime.Manager + auth in dev mode), listening on an
// httptest.Server, torn down automatically at the end of the test.
//
// The organization's default_visibility is set to "public" so that the
// pre-existing deploy/invoke tests (which predate auth and exercise
// deploy/rollback/fetch-policy behavior, not authorization) keep working
// against anonymous requests without each needing an explicit
// "visibility: public" manifest line. TestE2E_Auth* below build their own
// env with "org" default_visibility where the point IS to test
// authorization.
type testEnv struct {
	baseURL string
	store   store.Store
	auth    *auth.Auth

	tokensMu sync.Mutex
	tokens   map[string]string // owner selector -> cached plaintext API token
}

func newTestEnv(t *testing.T) *testEnv {
	return newTestEnvWithVisibility(t, "public")
}

func newTestEnvWithVisibility(t *testing.T, defaultVisibility string) *testEnv {
	t.Helper()

	st, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	blobStore, err := blobfs.New(t.TempDir())
	if err != nil {
		t.Fatalf("blobfs.New: %v", err)
	}

	manager := runtime.NewManager()
	t.Cleanup(func() { manager.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// The dev IdP's issuer URL must be this same test server's own URL
	// (internal/auth's provider discovery is lazy specifically to make
	// this possible), so the mux is registered against an httptest.Server
	// that's already listening before auth.New is called, and the actual
	// route tree is attached afterward -- see internal/auth's
	// login_devflow_test.go for the same pattern.
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	authSvc, err := auth.New(auth.Config{
		Mode:          auth.ModeDev,
		BaseURL:       srv.URL,
		ListenAddr:    "127.0.0.1:0",
		SessionSecret: testSessionSecret,
	}, st)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}

	envKey, err := fcrypto.DeriveKey(testSessionSecret, "funcbox:env-vars")
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}

	deployer := &service.Deployer{Store: st, Blob: blobStore, Runtime: manager}
	functions := &service.Functions{Store: st, Runtime: manager, EnvKey: envKey}
	apiHandler := api.New(deployer, functions, st, authSvc, logger)

	invoker := &invoke.Invoker{
		Store:   st,
		Blob:    blobStore,
		Manager: manager,
		Logger:  logger,
		Timeout: 10 * time.Second,
		Auth:    authSvc,
		EnvKey:  envKey,
	}

	handler := server.New(server.Deps{
		Logger: logger, API: apiHandler, Invoker: invoker,
		Auth: authSvc.Routes(), DevOIDC: authSvc.DevRoutes(),
	})
	mux.Handle("/", handler)

	env := &testEnv{baseURL: srv.URL, store: st, auth: authSvc, tokens: map[string]string{}}
	env.bootstrap(t, defaultVisibility)
	return env
}

// bootstrap creates the organization's first (admin) user directly against
// the store -- exactly what BootstrapFirstUser does, which is what
// /auth/callback calls on the very first login -- claims them the "admin"
// public User ID, and configures org settings/login-rules so the rest of this
// file's tests don't need their own login flow just to get an
// authenticated actor. TestE2E_AuthDevLoginFlow below is the one test that
// exercises the actual HTTP login flow end-to-end instead of this
// shortcut.
func (e *testEnv) bootstrap(t *testing.T, defaultVisibility string) *store.User {
	t.Helper()
	ctx := context.Background()

	admin := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub-admin", Email: "admin@example.com", Name: "Admin"}
	if err := e.store.BootstrapFirstUser(ctx, admin, "Test Org"); err != nil {
		t.Fatalf("BootstrapFirstUser: %v", err)
	}
	if err := e.store.PublicUserIDs().Create(ctx, &store.PublicUserID{UserID: "admin-user", InternalUserID: admin.ID}); err != nil {
		t.Fatalf("PublicUserIDs().Create(admin): %v", err)
	}

	org, err := e.store.Organizations().Get(ctx)
	if err != nil {
		t.Fatalf("Organizations().Get: %v", err)
	}
	orgSet := settings.DefaultOrg()
	orgSet.DefaultVisibility = defaultVisibility
	// The pre-existing fetch-policy tests (TestE2E_FetchPolicy) predate
	// auth and expect the MANIFEST's allowlist to be the sole fetch gate,
	// would otherwise intersect with and override a permissive manifest
	// deny"). TestE2E_AuthOrgFetchPolicyNarrowsManifest below is the
	// dedicated test for that intersection actually narrowing things at
	// runtime; it configures org fetch_policy explicitly via the API
	// rather than relying on this default.
	orgSet.FetchPolicy = settings.FetchPolicy{Mode: "allow-all"}
	org.Settings = orgSet.JSON()
	org.SettingsGen++
	if err := e.store.Organizations().Update(ctx, org); err != nil {
		t.Fatalf("Organizations().Update: %v", err)
	}

	// NOTE: this is deliberately WIDER than the real login flow's bootstrap
	// seeding (internal/auth's Auth.seedBootstrapLoginRule, which only
	// allows the bootstrap admin's own exact email -- see
	// internal/auth/login_devflow_test.go for the tests covering that
	// production behavior specifically). Most of this file's tests need
	// several distinct @example.com test users to be able to log in
	// without each one requiring its own admin-issued rule change, so this
	// helper sets up a domain-wide allow rule as a realistic
	// already-configured-by-an-admin organization, not as a stand-in for
	// the bootstrap default. Individual tests further widen/narrow this
	// (e.g. to test a rule change locking a user out) via
	// replaceLoginRules.
	if err := e.store.Organizations().ReplaceLoginRules(ctx, []*store.LoginRule{
		{Ord: 0, RuleType: store.LoginRuleTypeEmailDomain, Value: "example.com", Action: store.LoginRuleActionAllow},
		{Ord: 1, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionDeny},
	}); err != nil {
		t.Fatalf("ReplaceLoginRules: %v", err)
	}
	return admin
}

func (e *testEnv) replaceLoginRules(t *testing.T, rules []*store.LoginRule) {
	t.Helper()
	if err := e.store.Organizations().ReplaceLoginRules(context.Background(), rules); err != nil {
		t.Fatalf("ReplaceLoginRules: %v", err)
	}
}

// tokenForOwner returns a cached (or freshly minted) access token (§14.5)
// belonging to owner's user, provisioning both the user and its public
// User ID on first use -- auto-provisioning, now done explicitly and up
// front (since Deploy no longer does it implicitly; see
// internal/service.Deployer.Deploy). The token is minted directly via the
// Auth service (Auth.IssueAccessToken) rather than driving the full
// loopback+PKCE login + credential-exchange HTTP flow --
// TestE2E_CLILoginFullFlow below is the dedicated test for that flow
// itself; every other test in this file just needs a working bearer
// credential.
func (e *testEnv) tokenForOwner(t *testing.T, owner string) string {
	t.Helper()
	e.tokensMu.Lock()
	defer e.tokensMu.Unlock()
	if tok, ok := e.tokens[owner]; ok {
		return tok
	}

	ctx := context.Background()
	var userID string
	if id, err := e.store.PublicUserIDs().ByUserID(ctx, owner); err == nil {
		userID = id.InternalUserID
	} else {
		u := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub-" + owner, Email: owner + "@example.com", Name: owner, Role: store.RoleMember, Status: store.UserStatusActive}
		if err := e.store.Users().Create(ctx, u); err != nil {
			t.Fatalf("Users().Create(%s): %v", owner, err)
		}
		if err := e.store.PublicUserIDs().Create(ctx, &store.PublicUserID{UserID: owner, InternalUserID: u.ID}); err != nil {
			t.Fatalf("PublicUserIDs().Create(%s): %v", owner, err)
		}
		userID = u.ID
	}

	token, _, err := e.auth.IssueAccessToken(ctx, userID, time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken(%s): %v", owner, err)
	}
	e.tokens[owner] = token
	return token
}

// mintIDToken drives the dev IdP's authorize+token endpoints directly
// (skipping the interactive browser form) to obtain a signed ID token for
// email, for tests that need a caller identity on the invoke path
func (e *testEnv) mintIDToken(t *testing.T, email string) string {
	t.Helper()
	redirectURI := "http://localhost/callback"
	form := url.Values{
		"client_id": {"funcbox-dev-client"}, "redirect_uri": {redirectURI},
		"state": {"s"}, "nonce": {"n"}, "email": {email},
	}
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.PostForm(e.baseURL+"/dev/oidc/authorize", form)
	if err != nil {
		t.Fatalf("POST authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("authorize redirect had no code: %s", resp.Header.Get("Location"))
	}

	tokenForm := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {redirectURI}, "client_id": {"funcbox-dev-client"},
	}
	resp2, err := http.PostForm(e.baseURL+"/dev/oidc/token", tokenForm)
	if err != nil {
		t.Fatalf("POST token: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("token status = %d, body = %s", resp2.StatusCode, body)
	}
	var body struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&body); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return body.IDToken
}

// loginViaHTTP drives the FULL /auth/login -> dev-IdP authorize -> token
// exchange -> /auth/callback flow over real HTTP against this env's own
// server, returning a cookie-jar-equipped client authenticated as email.
// Unlike mintIDToken (a raw ID token for the invoke path), this exercises
// the dashboard session/CSRF-cookie flow.
func (e *testEnv) loginViaHTTP(t *testing.T, email string) *http.Client {
	t.Helper()
	// browserjar.New (not net/http/cookiejar.New directly): this drives the
	// full server over the httptest server's plain-http origin, exactly the
	// deployment shape the README quick-start uses
	// (FUNCBOX_BASE_URL=http://127.0.0.1:...). A real browser silently
	// discards a "__Host-" prefixed Set-Cookie lacking Secure, which
	// net/http/cookiejar doesn't enforce -- see browserjar's doc comment
	// for why this is the regression test for that bug class.
	client := &http.Client{Jar: browserjar.New(), CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

	resp, err := client.Get(e.baseURL + "/auth/login")
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
	resp, err = client.PostForm(e.baseURL+"/dev/oidc/authorize", form)
	if err != nil {
		t.Fatalf("POST dev authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST dev authorize status = %d, want 302", resp.StatusCode)
	}
	callbackURL := resp.Header.Get("Location")

	resp, err = client.Get(callbackURL)
	if err != nil {
		t.Fatalf("GET callback: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET callback status = %d, want 302 (successful login)", resp.StatusCode)
	}

	return client
}

// csrfCookie returns the CSRF double-submit cookie's value from client's
// jar. It checks both candidate names (internal/auth's
// (*Auth).csrfCookieName picks between them based on secureCookies()) since
// this is an external test package with no access to that unexported
// method -- e.baseURL here is always plain http (httptest.NewServer), so in
// practice only "fbx_csrf_insecure" is ever actually present, but checking
// both keeps this helper correct if that ever changes.
func (e *testEnv) csrfCookie(t *testing.T, client *http.Client) string {
	t.Helper()
	u, _ := url.Parse(e.baseURL)
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == "__Host-fbx_csrf" || c.Name == "fbx_csrf_insecure" {
			return c.Value
		}
	}
	t.Fatal("no CSRF cookie present; was loginViaHTTP called?")
	return ""
}

// readDirFiles loads every file under dir into the map[string][]byte shape
// bundle.Pack expects, keyed by slash-separated path relative to dir.
func readDirFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	files := make(map[string][]byte)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = data
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return files
}

// deployOpts is the multipart form fields for POST /api/v1/functions.
type deployOpts struct {
	owner  string
	name   string
	note   string
	dryRun bool
	// token, if set, is used as the Authorization bearer token directly
	// instead of env.tokenForOwner(owner) -- needed when owner names a
	// workspace (tokenForOwner only knows how to mint tokens for personal
	// public User IDs) or when a test wants to deploy as someone other than
	// owner's own user (e.g. an org admin deploying under someone else's
	// public User ID).
	token string
}

// deploy packs files into a canonical bundle (reusing bundle.Pack, per this
// response and its decoded JSON body. It authenticates as opts.owner
// (minting/reusing an API token via env.tokenForOwner), which -- per
// internal/service.Deployer.Deploy's authorization rules -- is exactly who
// deploying under that public User ID requires.
func deploy(t *testing.T, env *testEnv, files map[string][]byte, opts deployOpts) (*http.Response, map[string]any) {
	t.Helper()
	packed, err := bundle.Pack(files)
	if err != nil {
		t.Fatalf("bundle.Pack: %v", err)
	}
	return deployRaw(t, env, packed, opts)
}

// deployRaw is like deploy but takes the raw (possibly non-canonical, or
// deliberately oversized) bundle bytes directly, for the validation-failure
// tests.
func deployRaw(t *testing.T, env *testEnv, bundleBytes []byte, opts deployOpts) (*http.Response, map[string]any) {
	t.Helper()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="bundle"; filename="bundle.tar.gz"`)
	h.Set("Content-Type", "application/gzip")
	pw, err := mw.CreatePart(h)
	if err != nil {
		t.Fatalf("CreatePart: %v", err)
	}
	if _, err := pw.Write(bundleBytes); err != nil {
		t.Fatalf("write bundle part: %v", err)
	}

	if opts.owner != "" {
		_ = mw.WriteField("owner", opts.owner)
	}
	if opts.name != "" {
		_ = mw.WriteField("name", opts.name)
	}
	if opts.note != "" {
		_ = mw.WriteField("note", opts.note)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	reqURL := env.baseURL + "/api/v1/functions"
	if opts.dryRun {
		reqURL += "?dry_run=true"
	}

	req, err := http.NewRequest(http.MethodPost, reqURL, &buf)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	switch {
	case opts.token != "":
		req.Header.Set("Authorization", "Bearer "+opts.token)
	case opts.owner != "":
		req.Header.Set("Authorization", "Bearer "+env.tokenForOwner(t, opts.owner))
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /api/v1/functions: %v", err)
	}
	defer resp.Body.Close()

	var body map[string]any
	raw, _ := io.ReadAll(resp.Body)
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("decode deploy response: %v (body: %q)", err, raw)
		}
	}
	return resp, body
}

func mustGetString(t *testing.T, body map[string]any, path ...string) string {
	t.Helper()
	var cur any = body
	for _, key := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("path %v: %v is not an object (body: %v)", path, key, body)
		}
		cur, ok = m[key]
		if !ok {
			t.Fatalf("path %v: missing key %q (body: %v)", path, key, body)
		}
	}
	s, ok := cur.(string)
	if !ok {
		t.Fatalf("path %v: value is not a string: %v", path, cur)
	}
	return s
}

// (a multi-file ESM function: index.js imports ./lib/x.js) via a multipart
// POST, then GET it over HTTP and check the response body and headers.
func TestE2E_DeployAndInvoke(t *testing.T) {
	env := newTestEnv(t)
	// module-owned) while this test moved into server/ with the rest of the
	// server module, hence "../testdata" rather than "testdata".
	files := readDirFiles(t, filepath.Join("..", "testdata", "hello"))

	resp, body := deploy(t, env, files, deployOpts{owner: "alice"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("deploy status = %d, body = %v", resp.StatusCode, body)
	}
	if warnings, ok := body["warnings"].([]any); !ok || len(warnings) != 0 {
		t.Errorf("warnings = %v, want empty (manifest is present and fully specified)", body["warnings"])
	}

	invokeResp, err := http.Get(env.baseURL + "/alice/hello/some/path")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer invokeResp.Body.Close()
	got, _ := io.ReadAll(invokeResp.Body)

	if invokeResp.StatusCode != http.StatusOK {
		t.Fatalf("invoke status = %d, body = %q", invokeResp.StatusCode, got)
	}
	if h := invokeResp.Header.Get("X-Test-Marker"); h != "hello" {
		t.Errorf("X-Test-Marker header = %q, want %q (non-reserved response headers pass through unmodified)", h, "hello")
	}
	want := "hello from funcbox path=/alice/hello/some/path"
	if string(got) != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

// fetchTestSource returns a worker that fetches ?target= and reports
// success/failure in the response body, mirroring
// runtime/hooks_test.go's pattern so a policy denial is asserted
// as a guest-visible error, not a hang or a Go-level failure.
func fetchTestSource() []byte {
	return []byte(`
		export default {
			async fetch(req) {
				const target = new URL(req.url).searchParams.get("target");
				try {
					const r = await fetch(target);
					return new Response("ok:" + (await r.text()));
				} catch (e) {
					return new Response("fail:" + String((e && e.message) || e), { status: 502 });
				}
			},
		};
	`)
}

// TestE2E_FetchPolicy deploys one function whose manifest allowlists only
// one of two httptest targets (by literal IP:port), then checks that
// fetching the allowlisted target succeeds while fetching the other one
// fails with a guest-visible error (not a hang, not a 5xx from funcbox
// itself misbehaving).
func TestE2E_FetchPolicy(t *testing.T) {
	env := newTestEnv(t)

	allowed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "allowed-upstream")
	}))
	t.Cleanup(allowed.Close)
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "blocked-upstream")
	}))
	t.Cleanup(blocked.Close)

	allowedHostPort := strings.TrimPrefix(allowed.URL, "http://")
	manifestYAML := fmt.Sprintf(`
name: fetchtest
permissions:
  fetch:
    mode: allowlist
    allow:
      - %q
`, allowedHostPort)

	files := map[string][]byte{
		"funcbox.yaml": []byte(manifestYAML),
		"index.js":     fetchTestSource(),
	}

	resp, body := deploy(t, env, files, deployOpts{owner: "bob"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("deploy status = %d, body = %v", resp.StatusCode, body)
	}

	t.Run("allowlisted host succeeds", func(t *testing.T) {
		u := env.baseURL + "/bob/fetchtest?target=" + allowed.URL
		r, err := http.Get(u)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer r.Body.Close()
		got, _ := io.ReadAll(r.Body)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, body = %q", r.StatusCode, got)
		}
		if string(got) != "ok:allowed-upstream" {
			t.Errorf("body = %q, want %q", got, "ok:allowed-upstream")
		}
	})

	t.Run("non-allowlisted host fails visibly to the guest", func(t *testing.T) {
		u := env.baseURL + "/bob/fetchtest?target=" + blocked.URL
		r, err := http.Get(u)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer r.Body.Close()
		got, _ := io.ReadAll(r.Body)
		if r.StatusCode != http.StatusBadGateway {
			t.Fatalf("status = %d, body = %q, want 502 (guest-caught fetch failure)", r.StatusCode, got)
		}
		if !strings.HasPrefix(string(got), "fail:") {
			t.Errorf("body = %q, want a \"fail:\" prefix (guest-visible error)", got)
		}
	})
}

// TestE2E_Rollback deploys two versions of the same function, checks the
// response changes between them, then activates the first version again
// (rollback) and checks the response reverts.
func TestE2E_Rollback(t *testing.T) {
	env := newTestEnv(t)

	v1Files := map[string][]byte{
		"funcbox.yaml": []byte("name: app\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("v1"); } };`),
	}
	v2Files := map[string][]byte{
		"funcbox.yaml": []byte("name: app\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("v2"); } };`),
	}

	resp1, body1 := deploy(t, env, v1Files, deployOpts{owner: "carol"})
	if resp1.StatusCode != http.StatusCreated {
		t.Fatalf("deploy v1 status = %d, body = %v", resp1.StatusCode, body1)
	}
	v1ID := mustGetString(t, body1, "version", "id")

	get := func() string {
		t.Helper()
		r, err := http.Get(env.baseURL + "/carol/app")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, body = %q", r.StatusCode, b)
		}
		return string(b)
	}

	if got := get(); got != "v1" {
		t.Fatalf("after deploy v1: body = %q, want %q", got, "v1")
	}

	resp2, body2 := deploy(t, env, v2Files, deployOpts{owner: "carol"})
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("deploy v2 status = %d, body = %v", resp2.StatusCode, body2)
	}

	if got := get(); got != "v2" {
		t.Fatalf("after deploy v2: body = %q, want %q", got, "v2")
	}

	activateURL := fmt.Sprintf("%s/api/v1/functions/carol/app/versions/%s/activate", env.baseURL, v1ID)
	activateReq, err := http.NewRequest(http.MethodPost, activateURL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	activateReq.Header.Set("Authorization", "Bearer "+env.tokenForOwner(t, "carol"))
	actResp, err := http.DefaultClient.Do(activateReq)
	if err != nil {
		t.Fatalf("activate POST: %v", err)
	}
	actBody, _ := io.ReadAll(actResp.Body)
	actResp.Body.Close()
	if actResp.StatusCode != http.StatusOK {
		t.Fatalf("activate status = %d, body = %q", actResp.StatusCode, actBody)
	}

	if got := get(); got != "v1" {
		t.Fatalf("after rollback to v1: body = %q, want %q", got, "v1")
	}
}

// TestE2E_DeployValidationFailures covers the deploy request's 4xx paths:
// an oversized bundle (413), a malformed manifest (400), and a reserved
// owner User ID (400).
func TestE2E_DeployValidationFailures(t *testing.T) {
	env := newTestEnv(t)

	t.Run("oversize bundle is 413", func(t *testing.T) {
		// A single, highly compressible 6 MiB file: small enough on the
		// wire to sail through the 5 MiB *compressed* MaxBytesReader cap,
		// but its decompressed size exceeds bundle.MaxUnpackedBytes (5
		// MiB) — exactly the "gzip bomb" shape bundle's guarded
		// unpack is meant to catch by counting decompressed bytes as they
		// stream, not by trusting the compressed size.
		big := map[string][]byte{
			"index.js": bytes.Repeat([]byte("x"), 6<<20),
		}
		packed, err := bundle.Pack(big)
		if err != nil {
			t.Fatalf("bundle.Pack: %v", err)
		}
		if len(packed) >= service.MaxCompressedBundleBytes {
			t.Fatalf("test bundle's compressed size (%d) isn't actually small; adjust the fixture", len(packed))
		}

		resp, body := deployRaw(t, env, packed, deployOpts{owner: "dave", name: "toobig"})
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, body = %v, want 413", resp.StatusCode, body)
		}
	})

	t.Run("malformed manifest is 400", func(t *testing.T) {
		files := map[string][]byte{
			"funcbox.yaml": []byte("name: [this is not valid: yaml: syntax\n"),
			"index.js":     []byte(`export default { fetch() { return new Response("x"); } };`),
		}
		resp, body := deploy(t, env, files, deployOpts{owner: "dave", name: "badmanifest"})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %v, want 400", resp.StatusCode, body)
		}
	})

	t.Run("reserved owner is 400", func(t *testing.T) {
		files := map[string][]byte{
			"index.js": []byte(`export default { fetch() { return new Response("x"); } };`),
		}
		resp, body := deploy(t, env, files, deployOpts{owner: "api", name: "whatever"})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %v, want 400", resp.StatusCode, body)
		}
	})
}

// TestE2E_AuthDevLoginFlow drives the complete dev-mode login flow over
// real HTTP (GET /auth/login -> dev IdP authorize form submission -> code
// exchange -> GET /auth/callback), confirming the very first login
// bootstraps the organization, promotes the user to admin, derives their
// User ID from the email local part, and issues a session usable against
// the management API -- including the CSRF double-submit requirement on a
func TestE2E_AuthDevLoginFlow(t *testing.T) {
	env := newTestEnvWithVisibility(t, "org")
	// bootstrap() already created "admin@example.com" directly against the
	// store for the OTHER e2e tests' convenience; here we drive an
	// independent, fresh login for a second identity to prove the HTTP
	// flow itself (not the store shortcut) works end-to-end and correctly
	// derives a User ID/session for a brand-new user allowed by the
	// bootstrap-seeded example.com domain rule.
	client := env.loginViaHTTP(t, "newuser@example.com")

	req, _ := http.NewRequest(http.MethodGet, env.baseURL+"/api/v1/me", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /api/v1/me: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/me status = %d, want 200 (session cookie should authenticate)", resp.StatusCode)
	}
	var me map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		t.Fatalf("decode /api/v1/me: %v", err)
	}
	if me["email"] != "newuser@example.com" {
		t.Errorf("me.email = %v, want %q", me["email"], "newuser@example.com")
	}
	if me["user_id"] != "newuser" {
		t.Errorf("me.user_id = %v, want %q (derived from email local part)", me["user_id"], "newuser")
	}
	if me["role"] != "member" {
		t.Errorf("me.role = %v, want %q (this was the SECOND user, not the bootstrap admin)", me["role"], "member")
	}

	// Mutating cookie-authenticated request without CSRF token: rejected.
	patchReq, _ := http.NewRequest(http.MethodPatch, env.baseURL+"/api/v1/me", strings.NewReader(`{"user_id":""}`))
	patchResp, err := client.Do(patchReq)
	if err != nil {
		t.Fatalf("PATCH /api/v1/me (no csrf): %v", err)
	}
	patchResp.Body.Close()
	if patchResp.StatusCode != http.StatusForbidden {
		t.Fatalf("PATCH /api/v1/me without X-CSRF-Token status = %d, want 403", patchResp.StatusCode)
	}

	// With the CSRF cookie's value echoed back in the header: succeeds.
	patchReq2, _ := http.NewRequest(http.MethodPatch, env.baseURL+"/api/v1/me", strings.NewReader(`{"user_id":""}`))
	patchReq2.Header.Set("X-CSRF-Token", env.csrfCookie(t, client))
	patchReq2.Header.Set("Origin", env.baseURL)
	patchResp2, err := client.Do(patchReq2)
	if err != nil {
		t.Fatalf("PATCH /api/v1/me (with csrf): %v", err)
	}
	patchResp2.Body.Close()
	if patchResp2.StatusCode != http.StatusOK {
		t.Fatalf("PATCH /api/v1/me with X-CSRF-Token status = %d, want 200", patchResp2.StatusCode)
	}
}

// TestE2E_AuthLoginReturnToOpenRedirectGuard covers §14.3 item 2's
// open-redirect guard, end-to-end through the real /auth/login -> dev IdP
// -> /auth/callback round trip (not just the validator function in
// isolation -- internal/auth's invokesso_test.go's TestValidLocalReturnTo
// covers that): every malicious return_to shape here must land the
// browser on "/dashboard" (the same fallback a missing return_to gets),
// never on the attacker-controlled target. A legitimate same-origin path
// is included for contrast, to prove the guard isn't just rejecting
// everything.
func TestE2E_AuthLoginReturnToOpenRedirectGuard(t *testing.T) {
	env := newTestEnvWithVisibility(t, "org")
	const dashboardFallback = "/dashboard" // mirrors internal/auth's unexported defaultReturnTo

	// finalRedirectTarget drives one full login round trip with return_to
	// set to returnTo (or omitted, if empty) and returns where
	// /auth/callback ultimately sends the browser.
	finalRedirectTarget := func(t *testing.T, returnTo string) string {
		t.Helper()
		// browserjar.New: this round trip depends on the OAuth state cookie
		// (also "__Host-" prefixed, also gated by secureCookies()) actually
		// being stored across the redirect to the dev IdP and back -- see
		// loginViaHTTP's doc comment for why net/http/cookiejar's default
		// behavior would hide that.
		client := &http.Client{Jar: browserjar.New(), CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

		loginURL := env.baseURL + "/auth/login"
		if returnTo != "" {
			loginURL += "?return_to=" + url.QueryEscape(returnTo)
		}
		resp, err := client.Get(loginURL)
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
			"email":        {"redirecttest@example.com"},
		}
		resp, err = client.PostForm(env.baseURL+"/dev/oidc/authorize", form)
		if err != nil {
			t.Fatalf("POST dev authorize: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("POST dev authorize status = %d, want 302", resp.StatusCode)
		}
		callbackURL := resp.Header.Get("Location")

		resp, err = client.Get(callbackURL)
		if err != nil {
			t.Fatalf("GET callback: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("GET callback status = %d, want 302", resp.StatusCode)
		}
		return resp.Header.Get("Location")
	}

	for _, tt := range []struct{ name, returnTo, want string }{
		{"absolute URL", "https://evil.example/steal", dashboardFallback},
		{"protocol-relative", "//evil.example/steal", dashboardFallback},
		{"mixed-case scheme", "HtTpS://evil.example/steal", dashboardFallback},
		{"backslash trick", "/\\evil.example/steal", dashboardFallback},
		{"no return_to", "", dashboardFallback},
		{"legitimate same-origin path", "/dashboard/some/page?x=1", "/dashboard/some/page?x=1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := finalRedirectTarget(t, tt.returnTo)
			if got != tt.want {
				t.Fatalf("return_to=%q -> final redirect = %q, want %q", tt.returnTo, got, tt.want)
			}
		})
	}
}

// TestE2E_DeployRequiresAuth confirms POST /api/v1/functions -- unlike
// owner/manifest processing happens.
func TestE2E_DeployRequiresAuth(t *testing.T) {
	env := newTestEnv(t)
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: noauth\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
	}
	packed, err := bundle.Pack(files)
	if err != nil {
		t.Fatalf("bundle.Pack: %v", err)
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	pw, err := mw.CreateFormFile("bundle", "bundle.tar.gz")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := pw.Write(packed); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	_ = mw.WriteField("owner", "nobody")
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	resp, err := http.Post(env.baseURL+"/api/v1/functions", mw.FormDataContentType(), &buf)
	if err != nil {
		t.Fatalf("POST /api/v1/functions: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (no Authorization header)", resp.StatusCode)
	}
}

// §5.2's org-visibility invoke authorization: anonymous access is
// rejected, and a caller presenting a valid ID token for an org member is
// admitted. Tokens are minted from the dev IdP over real HTTP.
func TestE2E_AuthOrgVisibilityFunction(t *testing.T) {
	env := newTestEnvWithVisibility(t, "org")
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: orgapp\n"), // no explicit visibility -> org default applies
		"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
	}
	resp, body := deploy(t, env, files, deployOpts{owner: "admin-user", name: "orgapp"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("deploy status = %d, body = %v", resp.StatusCode, body)
	}

	t.Run("anonymous rejected", func(t *testing.T) {
		// http.Get sends no Accept header at all, i.e. the curl/API-client
		// case §14.3 distinguishes from a browser navigation -- so this
		// must stay a 401 (not a redirect), and per §14.3 item 1 it now
		// carries WWW-Authenticate plus a message pointing a terminal user
		// at `funcbox print-access-token` (§14.5).
		r, err := http.Get(env.baseURL + "/admin-user/orgapp")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", r.StatusCode)
		}
		if got := r.Header.Get("WWW-Authenticate"); got != "Bearer" {
			t.Fatalf("WWW-Authenticate = %q, want %q", got, "Bearer")
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "print-access-token") {
			t.Fatalf("401 body = %q, want it to mention `funcbox print-access-token`", body)
		}
	})

	t.Run("valid org member ID token accepted", func(t *testing.T) {
		token := env.mintIDToken(t, "admin@example.com")
		req, _ := http.NewRequest(http.MethodGet, env.baseURL+"/admin-user/orgapp", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer r.Body.Close()
		if r.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(r.Body)
			t.Fatalf("status = %d, body = %q, want 200", r.StatusCode, body)
		}
	})
}

// TestE2E_PathBasedModeSameOriginInvokeAuth is the path-based/same-origin
// mode regression coverage this bug's fix needed: newTestEnvWithVisibility
// never configures FUNCBOX_FUNCTION_DOMAIN, exactly like the README
// quick-start (FUNCBOX_BASE_URL=http://127.0.0.1:8091 with no
// FUNCTION_DOMAIN) -- but that shape had escaped e2e coverage because the
// host-routing e2e suite (e2e_hostrouting_test.go) always sets
// FunctionDomain. It covers §14.3's full same-origin decision table for a
// GET against an org-visibility function:
//   - a logged-in dashboard session cookie is accepted directly (no SSO
//     handoff -- auth.SameOriginInvokeHost);
//   - an anonymous browser-like request redirects to the ordinary
//     same-origin /auth/login (not the cross-origin SSO handoff, which
//     would 400 here since there's no distinct managed function host) and
//     completing that round trip lands back on the function's own response;
//   - an anonymous curl-like request still gets a 401 with WWW-Authenticate
//     (unchanged from TestE2E_AuthOrgVisibilityFunction above -- reasserted
//     here for the record alongside its browser counterparts).
func TestE2E_PathBasedModeSameOriginInvokeAuth(t *testing.T) {
	env := newTestEnvWithVisibility(t, "org")
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: sameorigin\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("same-origin ok"); } };`),
	}
	resp, body := deploy(t, env, files, deployOpts{owner: "admin-user", name: "sameorigin"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("deploy status = %d, body = %v", resp.StatusCode, body)
	}
	const functionPath = "/admin-user/sameorigin"

	t.Run("logged-in session cookie GET succeeds", func(t *testing.T) {
		// loginViaHTTP uses browserjar.New, not net/http/cookiejar: the
		// session cookie is "__Host-" prefixed over this httptest server's
		// plain-http origin, which a real browser would refuse to store
		// without Secure -- see browserjar's doc comment.
		//
		// A DIFFERENT email than the bootstrap admin's ("admin@example.com",
		// created directly against the store by bootstrap() with a
		// hardcoded provider_subject that doesn't match what the dev IdP
		// derives from an email it signs in) -- logging in AS that same
		// email through the real dev-IdP flow would collide on the users
		// table's email uniqueness with a different provider_subject and
		// fail sign-in entirely. Still permitted by the seeded
		// email_domain=example.com allow rule.
		client := env.loginViaHTTP(t, "browseruser@example.com")
		r, err := client.Get(env.baseURL + functionPath)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer r.Body.Close()
		got, _ := io.ReadAll(r.Body)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, body = %q, want 200 (same-origin session cookie must authenticate the invoke path directly, no SSO handoff)", r.StatusCode, got)
		}
		if string(got) != "same-origin ok" {
			t.Errorf("body = %q, want %q", got, "same-origin ok")
		}
	})

	t.Run("anonymous browser-like GET redirects to same-origin login and round-trips back", func(t *testing.T) {
		client := &http.Client{Jar: browserjar.New(), CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

		req, _ := http.NewRequest(http.MethodGet, env.baseURL+functionPath, nil)
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", functionPath, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("status = %d, want 302 (redirected to login)", resp.StatusCode)
		}
		loginURL := resp.Header.Get("Location")
		if !strings.HasPrefix(loginURL, "/auth/login?") || !strings.Contains(loginURL, "return_to="+url.QueryEscape(functionPath)) {
			t.Fatalf("Location = %q, want a same-origin /auth/login redirect carrying return_to=%s (NOT the cross-origin /auth/invoke SSO handoff, which would 400 with no FunctionDomain configured)", loginURL, functionPath)
		}

		resp, err = client.Get(env.baseURL + loginURL)
		if err != nil {
			t.Fatalf("GET %s: %v", loginURL, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("GET %s status = %d, want 302 to the dev IdP", loginURL, resp.StatusCode)
		}
		authorizeURL, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			t.Fatalf("parse Location: %v", err)
		}
		form := url.Values{
			"client_id": {authorizeURL.Query().Get("client_id")}, "redirect_uri": {authorizeURL.Query().Get("redirect_uri")},
			"state": {authorizeURL.Query().Get("state")}, "nonce": {authorizeURL.Query().Get("nonce")},
			"email": {"browseruser2@example.com"}, // distinct from the bootstrap admin -- see the previous subtest's comment
		}
		resp, err = client.PostForm(env.baseURL+"/dev/oidc/authorize", form)
		if err != nil {
			t.Fatalf("POST dev authorize: %v", err)
		}
		resp.Body.Close()
		callbackURL := resp.Header.Get("Location")

		resp, err = client.Get(callbackURL)
		if err != nil {
			t.Fatalf("GET callback: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != functionPath {
			t.Fatalf("callback status/location = %d %q, want 302 to %s (the original destination, round-tripped through return_to)", resp.StatusCode, resp.Header.Get("Location"), functionPath)
		}

		// The SAME session cookie the login flow just set now authenticates
		// the function directly -- completing the round trip back to a real
		// 200 response, not just a correct-looking redirect chain.
		finalResp, err := client.Get(env.baseURL + functionPath)
		if err != nil {
			t.Fatalf("GET %s (final): %v", functionPath, err)
		}
		defer finalResp.Body.Close()
		finalBody, _ := io.ReadAll(finalResp.Body)
		if finalResp.StatusCode != http.StatusOK || string(finalBody) != "same-origin ok" {
			t.Fatalf("final GET %s = (%d, %q), want (200, %q)", functionPath, finalResp.StatusCode, finalBody, "same-origin ok")
		}
	})

	t.Run("anonymous curl-like GET still 401s with WWW-Authenticate", func(t *testing.T) {
		r, err := http.Get(env.baseURL + functionPath)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", r.StatusCode)
		}
		if got := r.Header.Get("WWW-Authenticate"); got != "Bearer" {
			t.Fatalf("WWW-Authenticate = %q, want %q", got, "Bearer")
		}
	})
}

// TestE2E_AuthWorkspaceVisibilityMembership covers workspace creation via
// the management API, membership management, and the invoke path's
// additional workspace-membership check for visibility: workspace
// functions.
func TestE2E_AuthWorkspaceVisibilityMembership(t *testing.T) {
	env := newTestEnvWithVisibility(t, "org")
	adminToken := env.tokenForOwner(t, "admin-user")

	// Create the workspace as admin.
	wsBody := `{"name":"Team"}`
	wsReq, _ := http.NewRequest(http.MethodPost, env.baseURL+"/api/v1/workspaces", strings.NewReader(wsBody))
	wsReq.Header.Set("Authorization", "Bearer "+adminToken)
	wsReq.Header.Set("Content-Type", "application/json")
	wsResp, err := http.DefaultClient.Do(wsReq)
	if err != nil {
		t.Fatalf("POST /api/v1/workspaces: %v", err)
	}
	defer wsResp.Body.Close()
	if wsResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(wsResp.Body)
		t.Fatalf("create workspace status = %d, body = %s", wsResp.StatusCode, body)
	}
	var workspace struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(wsResp.Body).Decode(&workspace); err != nil {
		t.Fatalf("decode workspace: %v", err)
	}

	// Deploy a workspace-visibility function under it, as admin (org
	// admins may always deploy to any workspace).
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: teamapp\nvisibility: workspace\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
	}
	resp, body := deploy(t, env, files, deployOpts{owner: workspace.ID, name: "teamapp", token: adminToken})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("deploy status = %d, body = %v", resp.StatusCode, body)
	}

	// A plain org member, NOT yet a workspace member, is denied.
	memberToken := env.tokenForOwner(t, "outsider")
	outsiderUser, err := env.store.PublicUserIDs().ByUserID(context.Background(), "outsider")
	if err != nil {
		t.Fatalf("PublicUserIDs().ByUserID(outsider): %v", err)
	}

	checkAccess := func(t *testing.T, token string) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, env.baseURL+"/"+workspace.ID+"/teamapp", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer r.Body.Close()
		return r.StatusCode
	}

	// The invoke path only accepts ID tokens (or a session cookie), not
	// fbx_ API tokens -- so mint an ID token for the outsider's email
	// instead of reusing memberToken (an API token) directly.
	outsiderIDToken := env.mintIDToken(t, "outsider@example.com")
	if got := checkAccess(t, outsiderIDToken); got != http.StatusForbidden {
		t.Fatalf("non-member access status = %d, want 403", got)
	}
	_ = memberToken

	// Add them as a member, then access succeeds.
	addReq, _ := http.NewRequest(http.MethodPut, env.baseURL+"/api/v1/workspaces/"+workspace.ID+"/members/"+outsiderUser.InternalUserID, strings.NewReader(`{"role":"member"}`))
	addReq.Header.Set("Authorization", "Bearer "+adminToken)
	addReq.Header.Set("Content-Type", "application/json")
	addResp, err := http.DefaultClient.Do(addReq)
	if err != nil {
		t.Fatalf("PUT member: %v", err)
	}
	addResp.Body.Close()
	if addResp.StatusCode != http.StatusOK {
		t.Fatalf("add member status = %d, want 200", addResp.StatusCode)
	}

	if got := checkAccess(t, outsiderIDToken); got != http.StatusOK {
		t.Fatalf("member access status = %d, want 200", got)
	}
}

// §5.6's central claim in action: the effective fetch policy is resolved
// AT INVOKE TIME, not frozen at deploy time. The manifest alone permits
// fetching upstream (an allowlist naming it explicitly, which is also
// what's needed to exempt it from the loopback/SSRF guard for this
// httptest.Server-backed test); the organization starts out unconstrained
// (allow-all) and gets narrowed to exclude upstream entirely via the admin
// API, with NO redeploy in between -- proving the change takes effect on
// an already-deployed, already pool-warmed function immediately rather
// than only on its next build.
func TestE2E_AuthOrgFetchPolicyNarrowsManifest(t *testing.T) {
	env := newTestEnv(t) // default_visibility public, org fetch_policy allow-all

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "upstream-ok")
	}))
	t.Cleanup(upstream.Close)
	upstreamHostPort := strings.TrimPrefix(upstream.URL, "http://")

	// The manifest allowlists upstream by its literal IP:port (same as
	// TestE2E_FetchPolicy -- this is also what exempts it from the
	// loopback/SSRF guard, policy.BlockedIP, since httptest.Server binds
	// 127.0.0.1). What makes THIS test interesting is the org level: it
	// starts allow-all (unconstrained) and gets narrowed below.
	manifestYAML := fmt.Sprintf("name: fetchapp\npermissions:\n  fetch:\n    mode: allowlist\n    allow:\n      - %q\n", upstreamHostPort)
	files := map[string][]byte{
		"funcbox.yaml": []byte(manifestYAML),
		"index.js": []byte(`
			export default {
				async fetch(req) {
					try {
						const r = await fetch(new URL(req.url).searchParams.get("target"));
						return new Response("ok:" + (await r.text()));
					} catch (e) {
						return new Response("fail:" + String((e && e.message) || e), { status: 502 });
					}
				},
			};
		`),
	}
	resp, body := deploy(t, env, files, deployOpts{owner: "admin-user", name: "fetchapp"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("deploy status = %d, body = %v", resp.StatusCode, body)
	}

	invokeURL := env.baseURL + "/admin-user/fetchapp?target=" + upstream.URL

	// First request: org fetch_policy is allow-all (from newTestEnv's
	// bootstrap), so the over-broad manifest is unconstrained -- this
	// request ALSO warms the function's runtime pool.
	r1, err := http.Get(invokeURL)
	if err != nil {
		t.Fatalf("GET (before narrowing): %v", err)
	}
	got1, _ := io.ReadAll(r1.Body)
	r1.Body.Close()
	if r1.StatusCode != http.StatusOK || string(got1) != "ok:upstream-ok" {
		t.Fatalf("before narrowing: status = %d, body = %q, want 200 \"ok:upstream-ok\"", r1.StatusCode, got1)
	}

	// Narrow the organization's fetch policy via the admin API to an
	// allowlist that does NOT include upstream's address.
	patchBody := `{"fetch_policy": {"mode": "allowlist", "allow": ["some-other-host.example.com"]}}`
	patchReq, _ := http.NewRequest(http.MethodPatch, env.baseURL+"/api/v1/org", strings.NewReader(patchBody))
	patchReq.Header.Set("Authorization", "Bearer "+env.tokenForOwner(t, "admin-user"))
	patchReq.Header.Set("Content-Type", "application/json")
	patchResp, err := http.DefaultClient.Do(patchReq)
	if err != nil {
		t.Fatalf("PATCH /api/v1/org: %v", err)
	}
	defer patchResp.Body.Close()
	if patchResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(patchResp.Body)
		t.Fatalf("PATCH /api/v1/org status = %d, body = %s", patchResp.StatusCode, b)
	}

	// Second request, against the SAME already-warmed pool: must now be
	// denied, with no redeploy in between.
	r2, err := http.Get(invokeURL)
	if err != nil {
		t.Fatalf("GET (after narrowing): %v", err)
	}
	got2, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	if r2.StatusCode != http.StatusBadGateway || !strings.HasPrefix(string(got2), "fail:") {
		t.Fatalf("after narrowing: status = %d, body = %q, want 502 \"fail:...\" (org fetch policy should now block %s)", r2.StatusCode, got2, upstreamHostPort)
	}
}

// TestE2E_AuthLoginRuleChangeLocksOutSession confirms
// ス拒否となる": an admin changing the login rules to exclude an
// already-logged-in user's domain locks that user's existing session out
// on their very next request, with no explicit session revocation needed.
func TestE2E_AuthLoginRuleChangeLocksOutSession(t *testing.T) {
	env := newTestEnvWithVisibility(t, "org")
	client := env.loginViaHTTP(t, "regular@example.com")

	meReq := func() *http.Response {
		req, _ := http.NewRequest(http.MethodGet, env.baseURL+"/api/v1/me", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET /api/v1/me: %v", err)
		}
		return resp
	}

	if resp := meReq(); resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("GET /api/v1/me before rule change = %d, want 200", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	// Admin tightens the login rules to exclude example.com entirely.
	rulesBody := `{"login_rules":[{"type":"email_exact","value":"admin@example.com","action":"allow"},{"type":"default","action":"deny"}]}`
	rulesReq, _ := http.NewRequest(http.MethodPut, env.baseURL+"/api/v1/org/login-rules", strings.NewReader(rulesBody))
	rulesReq.Header.Set("Authorization", "Bearer "+env.tokenForOwner(t, "admin-user"))
	rulesReq.Header.Set("Content-Type", "application/json")
	rulesResp, err := http.DefaultClient.Do(rulesReq)
	if err != nil {
		t.Fatalf("PUT login-rules: %v", err)
	}
	defer rulesResp.Body.Close()
	if rulesResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(rulesResp.Body)
		t.Fatalf("PUT login-rules status = %d, body = %s", rulesResp.StatusCode, b)
	}

	if resp := meReq(); resp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("GET /api/v1/me after rule change = %d, body = %s, want 401 (regular@example.com is no longer permitted)", resp.StatusCode, b)
	} else {
		resp.Body.Close()
	}
}

// TestE2E_ApprovalModeFullFlow drives account-approval mode end to end
// over real HTTP, exactly the scenario
// the task calls out: with require_approval on, a second user's login
// still succeeds but lands them in the pending state (every /api/v1/*
// request 403s with code pending_approval); an admin approves them via
// PATCH /api/v1/org/users/{id}; and the user's very next request reaches
// the normal, unrestricted management API (this harness doesn't wire
// internal/dashboard -- see internal/dashboard/server_test.go's
// TestDashboard_PendingUserSeesRequestPendingPage for the pending PAGE
// itself, and its post-approval counterpart implied by
// TestDashboard_AuthenticatedRequestReachesPoolAndInternalAPI once status
// is active -- so "reaches the real dashboard" is verified here via the
// same management API every dashboard page is itself built on).
func TestE2E_ApprovalModeFullFlow(t *testing.T) {
	env := newTestEnvWithVisibility(t, "org")

	// Turn require_approval on as the admin.
	patchOrgReq, _ := http.NewRequest(http.MethodPatch, env.baseURL+"/api/v1/org", strings.NewReader(`{"require_approval":true}`))
	patchOrgReq.Header.Set("Authorization", "Bearer "+env.tokenForOwner(t, "admin-user"))
	patchOrgReq.Header.Set("Content-Type", "application/json")
	patchOrgResp, err := http.DefaultClient.Do(patchOrgReq)
	if err != nil {
		t.Fatalf("PATCH /api/v1/org: %v", err)
	}
	patchOrgResp.Body.Close()
	if patchOrgResp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH /api/v1/org (require_approval) status = %d", patchOrgResp.StatusCode)
	}

	// Second user logs in for real (through the dev IdP HTTP round trip):
	// login succeeds (a session is issued) even though they land pending.
	client := env.loginViaHTTP(t, "newcomer@example.com")

	meReq, _ := http.NewRequest(http.MethodGet, env.baseURL+"/api/v1/me", nil)
	meResp, err := client.Do(meReq)
	if err != nil {
		t.Fatalf("GET /api/v1/me: %v", err)
	}
	meBody, _ := io.ReadAll(meResp.Body)
	meResp.Body.Close()
	if meResp.StatusCode != http.StatusForbidden {
		t.Fatalf("pending user's GET /api/v1/me status = %d, body = %s, want 403", meResp.StatusCode, meBody)
	}
	var errBody struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(meBody, &errBody); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if errBody.Error.Code != "pending_approval" {
		t.Fatalf("error.code = %q, want %q", errBody.Error.Code, "pending_approval")
	}

	newcomer, err := env.store.Users().ByEmail(context.Background(), "newcomer@example.com")
	if err != nil {
		t.Fatalf("Users().ByEmail: %v", err)
	}
	if newcomer.Status != store.UserStatusPending {
		t.Fatalf("newcomer's stored status = %q, want %q", newcomer.Status, store.UserStatusPending)
	}

	// Admin approves via the API.
	approveReq, _ := http.NewRequest(http.MethodPatch, env.baseURL+"/api/v1/org/users/"+newcomer.ID, strings.NewReader(`{"status":"active"}`))
	approveReq.Header.Set("Authorization", "Bearer "+env.tokenForOwner(t, "admin-user"))
	approveReq.Header.Set("Content-Type", "application/json")
	approveResp, err := http.DefaultClient.Do(approveReq)
	if err != nil {
		t.Fatalf("PATCH approve: %v", err)
	}
	approveResp.Body.Close()
	if approveResp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH approve status = %d", approveResp.StatusCode)
	}

	// The user's NEXT request, on the SAME session established at login,
	// now reaches the real management API -- no re-login needed.
	meReq2, _ := http.NewRequest(http.MethodGet, env.baseURL+"/api/v1/me", nil)
	meResp2, err := client.Do(meReq2)
	if err != nil {
		t.Fatalf("GET /api/v1/me (after approval): %v", err)
	}
	meBody2, _ := io.ReadAll(meResp2.Body)
	meResp2.Body.Close()
	if meResp2.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/me after approval = %d, body = %s, want 200", meResp2.StatusCode, meBody2)
	}
	var me map[string]any
	if err := json.Unmarshal(meBody2, &me); err != nil {
		t.Fatalf("decode /api/v1/me: %v", err)
	}
	if me["email"] != "newcomer@example.com" {
		t.Errorf("me.email = %v, want %q", me["email"], "newcomer@example.com")
	}
}

// TestE2E_FunctionLimitBlocksNewFunctionButNotUpdates hits the
// max_functions_per_user limit for real, over HTTP multipart deploys: at
// the limit succeeds, one past it 403s
// with function_limit_exceeded, dry-run reports the same thing as a
// warning instead of failing, and redeploying an EXISTING function name
// is never blocked even once the owner is at their limit.
func TestE2E_FunctionLimitBlocksNewFunctionButNotUpdates(t *testing.T) {
	env := newTestEnv(t)
	env.tokenForOwner(t, "quota-user") // provisions the public User ID up front

	patchOrgReq, _ := http.NewRequest(http.MethodPatch, env.baseURL+"/api/v1/org", strings.NewReader(`{"max_functions_per_user":1}`))
	patchOrgReq.Header.Set("Authorization", "Bearer "+env.tokenForOwner(t, "admin-user"))
	patchOrgReq.Header.Set("Content-Type", "application/json")
	patchOrgResp, err := http.DefaultClient.Do(patchOrgReq)
	if err != nil {
		t.Fatalf("PATCH /api/v1/org: %v", err)
	}
	patchOrgResp.Body.Close()
	if patchOrgResp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH /api/v1/org (max_functions_per_user) status = %d", patchOrgResp.StatusCode)
	}

	appFiles := func(name string) map[string][]byte {
		return map[string][]byte{
			"funcbox.yaml": []byte("name: " + name + "\n"),
			"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
		}
	}

	// First function: at the limit, succeeds.
	resp, body := deploy(t, env, appFiles("quota-app-0"), deployOpts{owner: "quota-user"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first deploy status = %d, body = %v", resp.StatusCode, body)
	}

	// A dry run for a SECOND (new) function, over the limit, must succeed
	// but carry a warning.
	dryResp, dryBody := deploy(t, env, appFiles("quota-app-1"), deployOpts{owner: "quota-user", dryRun: true})
	if dryResp.StatusCode != http.StatusOK {
		t.Fatalf("dry run over the limit status = %d, body = %v, want 200", dryResp.StatusCode, dryBody)
	}
	warnings, _ := dryBody["warnings"].([]any)
	foundWarning := false
	for _, w := range warnings {
		if s, ok := w.(string); ok && strings.Contains(s, "limit") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Errorf("dry-run warnings = %v, want one mentioning the function limit", warnings)
	}

	// A real deploy of that second (new) function is rejected.
	resp2, body2 := deploy(t, env, appFiles("quota-app-1"), deployOpts{owner: "quota-user"})
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("second (new) function deploy status = %d, body = %v, want 403", resp2.StatusCode, body2)
	}
	errObj, _ := body2["error"].(map[string]any)
	if errObj["code"] != "function_limit_exceeded" {
		t.Errorf("error.code = %v, want %q", errObj["code"], "function_limit_exceeded")
	}

	// Redeploying the FIRST (existing) function name is an update, not a
	// new function, and must succeed even at the limit.
	resp3, body3 := deploy(t, env, appFiles("quota-app-0"), deployOpts{owner: "quota-user", note: "redeploy"})
	if resp3.StatusCode != http.StatusCreated {
		t.Fatalf("redeploy of the existing function status = %d, body = %v, want 201", resp3.StatusCode, body3)
	}
}

// storage design end to end: PUT /api/v1/functions/{owner}/{name}/env/{key}
// encrypts the value (internal/service.Functions.SetEnv, AES-GCM via
// internal/crypto), and the invoke path decrypts it back
// (internal/invoke/pool.go's buildEnv) to expose it as import.meta.env.KEY --
// proving the two independent encrypt/decrypt call sites agree on the key
// derivation (both from FUNCBOX_SESSION_SECRET) and ciphertext format.
func TestE2E_EnvVarEncryptionRoundTrip(t *testing.T) {
	env := newTestEnv(t)
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: envapp\nenv:\n  - SECRET_KEY\n"),
		"index.js": []byte(`
			export default {
				fetch(req) {
					return new Response("secret=" + import.meta.env.SECRET_KEY);
				},
			};
		`),
	}
	resp, body := deploy(t, env, files, deployOpts{owner: "admin-user", name: "envapp"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("deploy status = %d, body = %v", resp.StatusCode, body)
	}

	putReq, _ := http.NewRequest(http.MethodPut,
		env.baseURL+"/api/v1/functions/admin-user/envapp/env/SECRET_KEY",
		strings.NewReader(`{"value":"sup3r-s3cr3t"}`))
	putReq.Header.Set("Authorization", "Bearer "+env.tokenForOwner(t, "admin-user"))
	putReq.Header.Set("Content-Type", "application/json")
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		t.Fatalf("PUT env: %v", err)
	}
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT env status = %d, want 204", putResp.StatusCode)
	}

	// Confirm the value is stored encrypted, not in plaintext.
	fn, err := env.store.Functions().ByOwnerAndName(context.Background(), store.OwnerTypeUser, mustPublicUserInternalID(t, env, "admin-user"), "envapp")
	if err != nil {
		t.Fatalf("Functions().ByOwnerAndName: %v", err)
	}
	stored, err := env.store.Functions().ListEnv(context.Background(), fn.ID)
	if err != nil {
		t.Fatalf("ListEnv: %v", err)
	}
	if string(stored["SECRET_KEY"]) == "sup3r-s3cr3t" {
		t.Fatal("env_vars.value_enc is stored as plaintext, want ciphertext")
	}

	r, err := http.Get(env.baseURL + "/admin-user/envapp")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer r.Body.Close()
	got, _ := io.ReadAll(r.Body)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %q", r.StatusCode, got)
	}
	if string(got) != "secret=sup3r-s3cr3t" {
		t.Fatalf("body = %q, want %q (decrypted env var value)", got, "secret=sup3r-s3cr3t")
	}
}

func mustPublicUserInternalID(t *testing.T, env *testEnv, userID string) string {
	t.Helper()
	id, err := env.store.PublicUserIDs().ByUserID(context.Background(), userID)
	if err != nil {
		t.Fatalf("PublicUserIDs().ByUserID(%s): %v", userID, err)
	}
	return id.InternalUserID
}

// cliPKCEPair returns a random RFC 7636 code_verifier and its S256
// challenge, exactly as internal/cli's real `funcbox login` generates
// them (this module boundary -- the CLI package lives in the separate
// root module and must never be imported from here, see cmd/funcbox's
// dep_separation_test.go -- is why this is reimplemented locally rather
// than shared).
func cliPKCEPair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// TestE2E_CLILoginFullFlow drives the complete §14.4/§14.5 CLI browser-auth
// pipeline against the real dev-mode server: PKCE code issuance (standing
// in for the dashboard's approval click -- this harness has no dashboard
// mounted, see newTestEnvWithVisibility's server.Deps; internal/dashboard
// and internal/api's own tests cover the real approval page and its
// session+CSRF protection), the unauthenticated code+verifier exchange for
// a CLI credential, minting an access token from that credential,
// deploying a function with it exactly like a real CLI deploy would, and
// invoking an org-visibility function with it as a plain
// "Authorization: Bearer" header -- the curl use case §14.5 exists for.
// Subtests cover the task's explicit negative cases: garbage/unknown
// access tokens, single-use authorization codes, PKCE mismatch, and a
// revoked device losing the ability to mint further access tokens.
func TestE2E_CLILoginFullFlow(t *testing.T) {
	env := newTestEnvWithVisibility(t, "org")
	adminToken := env.tokenForOwner(t, "admin-user")

	// Step 1+2: PKCE pair, then the dashboard approval click
	// (POST /api/v1/cli/authorize -- session/access-token authenticated,
	// exactly what the real dashboard's approve action itself calls).
	verifier, challenge := cliPKCEPair(t)
	authorizeReq, _ := http.NewRequest(http.MethodPost, env.baseURL+"/api/v1/cli/authorize",
		strings.NewReader(fmt.Sprintf(`{"redirect":"http://127.0.0.1:54321/callback","challenge":%q,"name":"e2e-laptop"}`, challenge)))
	authorizeReq.Header.Set("Authorization", "Bearer "+adminToken)
	authorizeReq.Header.Set("Content-Type", "application/json")
	authorizeResp, err := http.DefaultClient.Do(authorizeReq)
	if err != nil {
		t.Fatalf("POST /cli/authorize: %v", err)
	}
	defer authorizeResp.Body.Close()
	if authorizeResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(authorizeResp.Body)
		t.Fatalf("POST /cli/authorize status = %d, body = %s", authorizeResp.StatusCode, body)
	}
	var authorizeBody struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(authorizeResp.Body).Decode(&authorizeBody); err != nil {
		t.Fatalf("decode /cli/authorize response: %v", err)
	}

	// Step 3: the loopback callback's code+verifier exchange for a CLI
	// credential -- UNAUTHENTICATED, no Authorization header at all.
	tokenResp, err := http.Post(env.baseURL+"/api/v1/cli/token", "application/json",
		strings.NewReader(fmt.Sprintf(`{"code":%q,"verifier":%q}`, authorizeBody.Code, verifier)))
	if err != nil {
		t.Fatalf("POST /cli/token: %v", err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("POST /cli/token status = %d, body = %s", tokenResp.StatusCode, body)
	}
	var tokenBody struct {
		Credential string `json:"credential"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenBody); err != nil {
		t.Fatalf("decode /cli/token response: %v", err)
	}
	if !strings.HasPrefix(tokenBody.Credential, "fbxc_") {
		t.Fatalf("credential = %q, want fbxc_ prefix", tokenBody.Credential)
	}

	// Step 4: mint a short-lived access token from the credential --
	// authenticated by the credential itself, not a session or prior
	// access token.
	mintAccessToken := func(t *testing.T, credential string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, env.baseURL+"/api/v1/cli/access-token", strings.NewReader(`{"ttl":"15m"}`))
		req.Header.Set("Authorization", "Bearer "+credential)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST /cli/access-token: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return resp.StatusCode, ""
		}
		var out struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode /cli/access-token response: %v", err)
		}
		return resp.StatusCode, out.AccessToken
	}
	status, accessToken := mintAccessToken(t, tokenBody.Credential)
	if status != http.StatusOK || !strings.HasPrefix(accessToken, "fbxa_") {
		t.Fatalf("mint access token status = %d, token = %q", status, accessToken)
	}

	// Step 5: deploy a function with the minted access token, exactly like
	// a real `funcbox deploy` would.
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: clidemo\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("hello from cli login"); } };`),
	}
	deployResp, deployBody := deploy(t, env, files, deployOpts{owner: "admin-user", name: "clidemo", token: accessToken})
	if deployResp.StatusCode != http.StatusCreated {
		t.Fatalf("deploy status = %d, body = %v", deployResp.StatusCode, deployBody)
	}

	// Step 6: invoke the org-visibility function as a curl-equivalent --
	// plain "Authorization: Bearer", no cookies, no ID token. This is the
	// scenario §14.5 exists for.
	invokeReq, _ := http.NewRequest(http.MethodGet, env.baseURL+"/admin-user/clidemo", nil)
	invokeReq.Header.Set("Authorization", "Bearer "+accessToken)
	invokeResp, err := http.DefaultClient.Do(invokeReq)
	if err != nil {
		t.Fatalf("GET /admin-user/clidemo: %v", err)
	}
	defer invokeResp.Body.Close()
	invokeGotBody, _ := io.ReadAll(invokeResp.Body)
	if invokeResp.StatusCode != http.StatusOK || string(invokeGotBody) != "hello from cli login" {
		t.Fatalf("invoke with access token = (%d, %q), want (200, %q)", invokeResp.StatusCode, invokeGotBody, "hello from cli login")
	}

	t.Run("garbage or unknown access token rejected", func(t *testing.T) {
		for _, bad := range []string{"fbxa_garbage", "not-even-close-to-a-token", ""} {
			req, _ := http.NewRequest(http.MethodGet, env.baseURL+"/admin-user/clidemo", nil)
			if bad != "" {
				req.Header.Set("Authorization", "Bearer "+bad)
			}
			r, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			r.Body.Close()
			if r.StatusCode != http.StatusUnauthorized {
				t.Errorf("invoke with bearer %q status = %d, want 401", bad, r.StatusCode)
			}
		}
	})

	t.Run("authorization code is single-use", func(t *testing.T) {
		resp, err := http.Post(env.baseURL+"/api/v1/cli/token", "application/json",
			strings.NewReader(fmt.Sprintf(`{"code":%q,"verifier":%q}`, authorizeBody.Code, verifier)))
		if err != nil {
			t.Fatalf("POST /cli/token (replay): %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("replayed code exchange status = %d, want 400", resp.StatusCode)
		}
	})

	t.Run("PKCE mismatch is rejected", func(t *testing.T) {
		_, challenge2 := cliPKCEPair(t)
		authorizeReq2, _ := http.NewRequest(http.MethodPost, env.baseURL+"/api/v1/cli/authorize",
			strings.NewReader(fmt.Sprintf(`{"redirect":"http://127.0.0.1:1/callback","challenge":%q,"name":"x"}`, challenge2)))
		authorizeReq2.Header.Set("Authorization", "Bearer "+adminToken)
		authorizeReq2.Header.Set("Content-Type", "application/json")
		authorizeResp2, err := http.DefaultClient.Do(authorizeReq2)
		if err != nil {
			t.Fatalf("POST /cli/authorize: %v", err)
		}
		defer authorizeResp2.Body.Close()
		var authorizeBody2 struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(authorizeResp2.Body).Decode(&authorizeBody2); err != nil {
			t.Fatalf("decode /cli/authorize response: %v", err)
		}

		wrongVerifier, _ := cliPKCEPair(t)
		exchResp, err := http.Post(env.baseURL+"/api/v1/cli/token", "application/json",
			strings.NewReader(fmt.Sprintf(`{"code":%q,"verifier":%q}`, authorizeBody2.Code, wrongVerifier)))
		if err != nil {
			t.Fatalf("POST /cli/token (PKCE mismatch): %v", err)
		}
		defer exchResp.Body.Close()
		if exchResp.StatusCode != http.StatusBadRequest {
			t.Fatalf("PKCE-mismatched exchange status = %d, want 400", exchResp.StatusCode)
		}
	})

	t.Run("revoked device can no longer mint access tokens", func(t *testing.T) {
		listReq, _ := http.NewRequest(http.MethodGet, env.baseURL+"/api/v1/me/devices", nil)
		listReq.Header.Set("Authorization", "Bearer "+adminToken)
		listResp, err := http.DefaultClient.Do(listReq)
		if err != nil {
			t.Fatalf("GET /me/devices: %v", err)
		}
		defer listResp.Body.Close()
		var devicesBody struct {
			Devices []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"devices"`
		}
		if err := json.NewDecoder(listResp.Body).Decode(&devicesBody); err != nil {
			t.Fatalf("decode /me/devices response: %v", err)
		}
		var deviceID string
		for _, d := range devicesBody.Devices {
			if d.Name == "e2e-laptop" {
				deviceID = d.ID
			}
		}
		if deviceID == "" {
			t.Fatalf("GET /me/devices did not list e2e-laptop: %+v", devicesBody.Devices)
		}

		delReq, _ := http.NewRequest(http.MethodDelete, env.baseURL+"/api/v1/me/devices/"+deviceID, nil)
		delReq.Header.Set("Authorization", "Bearer "+adminToken)
		delResp, err := http.DefaultClient.Do(delReq)
		if err != nil {
			t.Fatalf("DELETE /me/devices/%s: %v", deviceID, err)
		}
		delResp.Body.Close()
		if delResp.StatusCode != http.StatusNoContent {
			t.Fatalf("DELETE /me/devices/%s status = %d, want 204", deviceID, delResp.StatusCode)
		}

		status, _ := mintAccessToken(t, tokenBody.Credential)
		if status != http.StatusUnauthorized {
			t.Fatalf("mint after revoke status = %d, want 401", status)
		}

		// The access token minted BEFORE revocation is still valid until
		// its own short natural expiry -- §14.5's documented design ("即時
		// 失効はしない").
		invokeAfterRevoke, _ := http.NewRequest(http.MethodGet, env.baseURL+"/admin-user/clidemo", nil)
		invokeAfterRevoke.Header.Set("Authorization", "Bearer "+accessToken)
		r, err := http.DefaultClient.Do(invokeAfterRevoke)
		if err != nil {
			t.Fatalf("GET after revoke: %v", err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Errorf("already-minted access token status after device revoke = %d, want 200 (still valid until natural expiry)", r.StatusCode)
		}
	})
}

// TestE2E_OpenModePublicConfiguration drives the recommended
// public-deployment combination (open_mode + require_approval) end to
// end over real HTTP, as a cross-cutting scenario:
//
//  1. A stranger's login still succeeds under the organization's already
//     permissive login rules (standing in for the default-allow rule set
//     production bootstrap would seed under FUNCBOX_OPEN_MODE=1 --
//     TestDevLoginFlow_OpenModeBootstrapSeedsDefaultAllowAndOrgSetting in
//     internal/auth covers that seeding itself) but lands pending.
//  2. An admin approves them.
//  3. They deploy under max_functions_per_user, and hit function_limit_exceeded
//     one past it.
//  4. Their dashboard function list shows only their own function, not the
//     admin's.
//  5. The admin's org-visibility function is still invocable by URL with a
//     valid ID token, exactly as in normal mode.
//  6. /api/v1/workspaces 404s.
//  7. The invoked function sees no X-Funcbox-Caller-Email until
//     expose_caller_identity is turned on, after which it does.
func TestE2E_OpenModePublicConfiguration(t *testing.T) {
	env := newTestEnvWithVisibility(t, "org")

	// Enable the recommended combination in one PATCH -- no workspace
	// exists yet, so the open_mode toggle guard passes.
	patchBody := `{"open_mode":true,"require_approval":true,"max_functions_per_user":1}`
	patchReq, _ := http.NewRequest(http.MethodPatch, env.baseURL+"/api/v1/org", strings.NewReader(patchBody))
	patchReq.Header.Set("Authorization", "Bearer "+env.tokenForOwner(t, "admin-user"))
	patchReq.Header.Set("Content-Type", "application/json")
	patchResp, err := http.DefaultClient.Do(patchReq)
	if err != nil {
		t.Fatalf("PATCH /api/v1/org: %v", err)
	}
	patchBodyBytes, _ := io.ReadAll(patchResp.Body)
	patchResp.Body.Close()
	if patchResp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH /api/v1/org status = %d, body = %s", patchResp.StatusCode, patchBodyBytes)
	}

	// The admin deploys an org-visibility function -- this is "another
	// user's org-visibility function" the stranger must still be able to
	// invoke by URL later, even though it never appears in their own
	// function list.
	adminFiles := map[string][]byte{
		"funcbox.yaml": []byte("name: adminapp\nvisibility: org\n"),
		"index.js": []byte(`
			export default {
				fetch(req) {
					return new Response("caller=" + (req.headers.get("X-Funcbox-Caller-Email") || "none"));
				},
			};
		`),
	}
	adminDeployResp, adminDeployBody := deploy(t, env, adminFiles, deployOpts{owner: "admin-user", name: "adminapp"})
	if adminDeployResp.StatusCode != http.StatusCreated {
		t.Fatalf("admin deploy status = %d, body = %v", adminDeployResp.StatusCode, adminDeployBody)
	}

	// Step 1: the stranger logs in for real. Login succeeds (a session is
	// issued) but they land pending, per require_approval.
	client := env.loginViaHTTP(t, "newbie@example.com")
	meReq, _ := http.NewRequest(http.MethodGet, env.baseURL+"/api/v1/me", nil)
	meResp, err := client.Do(meReq)
	if err != nil {
		t.Fatalf("GET /api/v1/me: %v", err)
	}
	meResp.Body.Close()
	if meResp.StatusCode != http.StatusForbidden {
		t.Fatalf("pending stranger's GET /api/v1/me status = %d, want 403", meResp.StatusCode)
	}
	newbie, err := env.store.Users().ByEmail(context.Background(), "newbie@example.com")
	if err != nil {
		t.Fatalf("Users().ByEmail(newbie): %v", err)
	}
	if newbie.Status != store.UserStatusPending {
		t.Fatalf("newbie's status = %q, want pending", newbie.Status)
	}

	// Step 2: the admin approves them.
	approveReq, _ := http.NewRequest(http.MethodPatch, env.baseURL+"/api/v1/org/users/"+newbie.ID, strings.NewReader(`{"status":"active"}`))
	approveReq.Header.Set("Authorization", "Bearer "+env.tokenForOwner(t, "admin-user"))
	approveReq.Header.Set("Content-Type", "application/json")
	approveResp, err := http.DefaultClient.Do(approveReq)
	if err != nil {
		t.Fatalf("PATCH approve: %v", err)
	}
	approveResp.Body.Close()
	if approveResp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH approve status = %d", approveResp.StatusCode)
	}

	// Step 3: newbie deploys their own function, at the max_functions_per_user
	// limit of 1 -- succeeds; a second (new) function is rejected.
	newbieToken := env.tokenForOwner(t, "newbie")
	newbieFiles := func(name string) map[string][]byte {
		return map[string][]byte{
			"funcbox.yaml": []byte("name: " + name + "\nvisibility: org\n"),
			"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
		}
	}
	firstDeployResp, firstDeployBody := deploy(t, env, newbieFiles("newbie-app"), deployOpts{owner: "newbie", token: newbieToken})
	if firstDeployResp.StatusCode != http.StatusCreated {
		t.Fatalf("newbie's first deploy status = %d, body = %v", firstDeployResp.StatusCode, firstDeployBody)
	}
	secondDeployResp, secondDeployBody := deploy(t, env, newbieFiles("newbie-app-2"), deployOpts{owner: "newbie", token: newbieToken})
	if secondDeployResp.StatusCode != http.StatusForbidden {
		t.Fatalf("newbie's second (new) function deploy status = %d, body = %v, want 403", secondDeployResp.StatusCode, secondDeployBody)
	}
	if errObj, _ := secondDeployBody["error"].(map[string]any); errObj["code"] != "function_limit_exceeded" {
		t.Errorf("error.code = %v, want %q", errObj["code"], "function_limit_exceeded")
	}

	// Step 4: newbie's own dashboard function list shows only their own
	// function, never the admin's -- even though it's org-visibility and
	// newbie could invoke it (step 5 below).
	listStatus, listBody := getOpenModeJSON(t, env.baseURL+"/api/v1/functions", newbieToken)
	if listStatus != http.StatusOK {
		t.Fatalf("GET /api/v1/functions status = %d, body = %v", listStatus, listBody)
	}
	fns, _ := listBody["functions"].([]any)
	if len(fns) != 1 {
		t.Fatalf("newbie's function list = %v, want exactly their own 1 function", listBody["functions"])
	}
	if got := fns[0].(map[string]any)["name"]; got != "newbie-app" {
		t.Errorf("newbie's function list[0].name = %v, want %q", got, "newbie-app")
	}

	// Step 5: the admin's org-visibility function is still invocable by
	// URL with a valid ID token, exactly as in normal mode -- open mode
	// only hides it from the LIST, per §13.1.
	newbieIDToken := env.mintIDToken(t, "newbie@example.com")
	invokeReq, _ := http.NewRequest(http.MethodGet, env.baseURL+"/admin-user/adminapp", nil)
	invokeReq.Header.Set("Authorization", "Bearer "+newbieIDToken)
	invokeResp, err := http.DefaultClient.Do(invokeReq)
	if err != nil {
		t.Fatalf("GET /admin-user/adminapp: %v", err)
	}
	invokeBody, _ := io.ReadAll(invokeResp.Body)
	invokeResp.Body.Close()
	if invokeResp.StatusCode != http.StatusOK {
		t.Fatalf("invoke admin's org-visibility function status = %d, body = %q, want 200", invokeResp.StatusCode, invokeBody)
	}

	// Step 7 (checked here, before turning expose_caller_identity on):
	// the caller's email must NOT have reached the guest.
	if string(invokeBody) != "caller=none" {
		t.Fatalf("invoke body = %q, want %q (no caller header without expose_caller_identity)", invokeBody, "caller=none")
	}

	// Step 6: the workspace API is completely disabled.
	wsResp, err := http.DefaultClient.Do(mustNewRequest(t, http.MethodGet, env.baseURL+"/api/v1/workspaces", env.tokenForOwner(t, "admin-user")))
	if err != nil {
		t.Fatalf("GET /api/v1/workspaces: %v", err)
	}
	wsResp.Body.Close()
	if wsResp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /api/v1/workspaces status = %d, want 404 (disabled by open mode)", wsResp.StatusCode)
	}

	// Step 7 continued: turning expose_caller_identity on restores the
	// header on the SAME already-deployed, already-invoked function --
	// resolved fresh per request, no redeploy needed (mirrors
	// TestE2E_AuthOrgFetchPolicyNarrowsManifest's "takes effect
	// immediately" pattern for org settings).
	exposeReq, _ := http.NewRequest(http.MethodPatch, env.baseURL+"/api/v1/org", strings.NewReader(`{"expose_caller_identity":true}`))
	exposeReq.Header.Set("Authorization", "Bearer "+env.tokenForOwner(t, "admin-user"))
	exposeReq.Header.Set("Content-Type", "application/json")
	exposeResp, err := http.DefaultClient.Do(exposeReq)
	if err != nil {
		t.Fatalf("PATCH expose_caller_identity: %v", err)
	}
	exposeResp.Body.Close()
	if exposeResp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH expose_caller_identity status = %d", exposeResp.StatusCode)
	}

	invokeReq2, _ := http.NewRequest(http.MethodGet, env.baseURL+"/admin-user/adminapp", nil)
	invokeReq2.Header.Set("Authorization", "Bearer "+newbieIDToken)
	invokeResp2, err := http.DefaultClient.Do(invokeReq2)
	if err != nil {
		t.Fatalf("GET /admin-user/adminapp (after expose_caller_identity): %v", err)
	}
	invokeBody2, _ := io.ReadAll(invokeResp2.Body)
	invokeResp2.Body.Close()
	if invokeResp2.StatusCode != http.StatusOK || string(invokeBody2) != "caller=newbie@example.com" {
		t.Fatalf("invoke body after expose_caller_identity = (%d, %q), want (200, %q)", invokeResp2.StatusCode, invokeBody2, "caller=newbie@example.com")
	}
}

// mustNewRequest is a tiny helper for the one-off authenticated GET in
// TestE2E_OpenModePublicConfiguration's workspace-404 check.
func mustNewRequest(t *testing.T, method, url, token string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

// getOpenModeJSON is getJSON's counterpart in this file (internal/api's
// own getJSON helper isn't reachable from this package): GETs url with a
// bearer token and decodes the JSON body.
func getOpenModeJSON(t *testing.T, url, token string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil && err != io.EOF {
		t.Fatalf("decode response: %v", err)
	}
	return resp.StatusCode, body
}
