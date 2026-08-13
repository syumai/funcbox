// Package funcbox_test exercises funcbox's end-to-end path: authenticate
// (dev-mode stub IdP), deploy a function through the management API, then
// (internal/auth, internal/service, internal/api, internal/invoke,
// internal/server) against real sqlite and filesystem-blob backends
// (in-memory / a temp dir, so no external state is needed to run it).
package funcbox_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
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

	admin := &store.User{GoogleSub: "sub-admin", Email: "admin@example.com", Name: "Admin"}
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

// tokenForOwner returns a cached (or freshly minted) API token belonging
// to owner's user, provisioning both the user and its public User ID on first use
// auto-provisioning, now done explicitly and up front (since Deploy no
// longer does it implicitly; see internal/service.Deployer.Deploy).
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
		u := &store.User{GoogleSub: "sub-" + owner, Email: owner + "@example.com", Name: owner, Role: store.RoleMember}
		if err := e.store.Users().Create(ctx, u); err != nil {
			t.Fatalf("Users().Create(%s): %v", owner, err)
		}
		if err := e.store.PublicUserIDs().Create(ctx, &store.PublicUserID{UserID: owner, InternalUserID: u.ID}); err != nil {
			t.Fatalf("PublicUserIDs().Create(%s): %v", owner, err)
		}
		userID = u.ID
	}

	plaintext, hash, err := auth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if err := e.store.Tokens().Create(ctx, &store.APIToken{
		UserID: userID, TokenHash: hash, Name: "e2e-test", ExpiresAt: time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("Tokens().Create(%s): %v", owner, err)
	}
	e.tokens[owner] = plaintext
	return plaintext
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
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

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

func (e *testEnv) csrfCookie(t *testing.T, client *http.Client) string {
	t.Helper()
	u, _ := url.Parse(e.baseURL)
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == "__Host-fbx_csrf" {
			return c.Value
		}
	}
	t.Fatal("no __Host-fbx_csrf cookie present; was loginViaHTTP called?")
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
		r, err := http.Get(env.baseURL + "/admin-user/orgapp")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", r.StatusCode)
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

// storage design end to end: PUT /api/v1/functions/{owner}/{name}/env/{key}
// encrypts the value (internal/service.Functions.SetEnv, AES-GCM via
// internal/crypto), and the invoke path decrypts it back
// (internal/invoke/pool.go's buildEnvBindings) to expose it as env.KEY --
// proving the two independent encrypt/decrypt call sites agree on the key
// derivation (both from FUNCBOX_SESSION_SECRET) and ciphertext format.
func TestE2E_EnvVarEncryptionRoundTrip(t *testing.T) {
	env := newTestEnv(t)
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: envapp\nenv:\n  - SECRET_KEY\n"),
		"index.js": []byte(`
			export default {
				fetch(req, env) {
					return new Response("secret=" + env.SECRET_KEY);
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
