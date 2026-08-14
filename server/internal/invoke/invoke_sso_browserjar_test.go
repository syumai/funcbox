// invoke_sso_browserjar_test.go is the browser-faithful regression test for
// the invoke path's browser SSO round trip (§14.3: an unauthenticated
// browser hitting a non-public function is bounced through the
// control-plane login, then handed a one-time code back to the function's
// own host, which mints a host-scoped invoke cookie). Unlike this
// package's other tests (which call Invoker.Serve/HandleInvokeCallback
// directly against an httptest.Recorder, or use a plain
// net/http/cookiejar), this one drives the ENTIRE flow over real HTTP,
// across two distinct virtual hosts sharing one httptest.Server, through
// server/internal/browserjar's cookie-prefix-enforcing jar -- exactly the
// mechanism server/internal/auth/login_devflow_test.go uses for the
// dashboard login flow, applied to the invoke-path's host-routed cousin.
//
// This is deliberately over PLAIN http, matching the README quick-start
// deployment (FUNCBOX_AUTH_MODE=dev, FUNCBOX_BASE_URL=http://...): the
// invoke SSO cookie ("__Host-fbx_invoke") has the identical
// Secure-attribute bug the dashboard session/CSRF cookies do (see
// browserjar's doc comment), and a real browser would silently drop it,
// permanently stranding the user in a redirect loop between the function
// host and the control plane. A plain cookiejar-based test would stay
// green through that bug -- which is the entire reason this file exists.
package invoke

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/syumai/funcbox/bundle"
	"github.com/syumai/funcbox/runtime"
	"github.com/syumai/funcbox/server/internal/auth"
	blobfs "github.com/syumai/funcbox/server/internal/blob/fs"
	"github.com/syumai/funcbox/server/internal/browserjar"
	"github.com/syumai/funcbox/server/internal/service"
	"github.com/syumai/funcbox/server/internal/store/sqlite"
)

// functionHostName mirrors internal/auth's managedFunctionHost: a managed
// function's browser-facing host is "<name>.<FunctionDomain>".
func functionHostName(name, domain string) string {
	return strings.ToLower(name + "." + domain)
}

// functionNameForHost is functionHostName's inverse, used by this test's
// own host-routing mux to decide whether an incoming request's Host is the
// control plane or a specific managed function -- the same decision a real
// funcbox-server's internal/server package makes from the actual Host
// header in production, simplified here to a single fixed FunctionDomain.
func functionNameForHost(host, domain string) (string, bool) {
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	}
	suffix := "." + strings.ToLower(domain)
	h = strings.ToLower(h)
	if !strings.HasSuffix(h, suffix) {
		return "", false
	}
	return strings.TrimSuffix(h, suffix), true
}

func TestInvokeSSOFlow_BrowserFaithfulOverPlainHTTP(t *testing.T) {
	const functionDomain = "run.example.test"

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

	// The httptest.Server needs to exist (and its port known) before
	// auth.New, since BaseURL/ControlOrigin bake the port in -- same
	// ordering trick server/internal/auth/login_devflow_test.go uses.
	//
	// The control host is this server's own REAL address (srv.URL), not a
	// virtual hostname: internal/auth's own OIDC discovery (provider.go)
	// makes a genuine outbound HTTP request to BaseURL+"/dev/oidc" using
	// the default transport, which has no idea about this test's fake DNS
	// trick below -- it can only ever resolve a real address. Only the
	// FUNCTION host needs to be virtual: it's never dialed by the server
	// itself, only by this test's own client (via the custom Transport
	// below), which fully controls where every hostname actually connects.
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener addr: %v", err)
	}
	baseURL := srv.URL

	authSvc, err := auth.New(auth.Config{
		Mode:           auth.ModeDev,
		BaseURL:        baseURL,
		FunctionDomain: functionDomain,
		ListenAddr:     "127.0.0.1:0",
		SessionSecret:  "invoke-sso-e2e-secret",
	}, st)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}

	inv := &Invoker{
		Store: st, Blob: blobStore, Manager: manager,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Timeout: 5 * time.Second, Auth: authSvc,
	}

	mux.Handle("/auth/", authSvc.Routes())
	mux.Handle("/dev/oidc/", authSvc.DevRoutes())
	mux.HandleFunc("/.funcbox/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		name, ok := functionNameForHost(r.Host, functionDomain)
		if !ok {
			http.NotFound(w, r)
			return
		}
		inv.ServeBrowserAuthCallback(w, r, name, r.Host)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if name, ok := functionNameForHost(r.Host, functionDomain); ok {
			inv.ServeByName(w, r, name)
			return
		}
		// Control-plane host: a stand-in for the real dashboard SSR (never
		// exercised here) so /auth/callback's post-login redirect has
		// somewhere to land.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("dashboard stand-in"))
	})

	// realAddr is the one real TCP endpoint both virtual hosts
	// (controlHost and every "*.<functionDomain>") resolve to -- standing
	// in for DNS/a wildcard record pointing every one of them at the same
	// funcbox-server process, which is how this actually works in
	// production.
	realAddr := srv.Listener.Addr().String()
	client := &http.Client{
		Jar: browserjar.New(),
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, realAddr)
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}

	// --- Step 1: bootstrap + log in as the admin at the control host ---
	loginResp, err := client.Get(baseURL + "/auth/login")
	if err != nil {
		t.Fatalf("GET /auth/login: %v", err)
	}
	if loginResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(loginResp.Body)
		loginResp.Body.Close()
		t.Fatalf("GET /auth/login status = %d, want 302, body = %s", loginResp.StatusCode, body)
	}
	loginResp.Body.Close()
	authorizeURL, err := url.Parse(loginResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	form := url.Values{
		"client_id":    {authorizeURL.Query().Get("client_id")},
		"redirect_uri": {authorizeURL.Query().Get("redirect_uri")},
		"state":        {authorizeURL.Query().Get("state")},
		"nonce":        {authorizeURL.Query().Get("nonce")},
		"email":        {"admin@example.com"},
	}
	authorizeResp, err := client.PostForm(baseURL+"/dev/oidc/authorize", form)
	if err != nil {
		t.Fatalf("POST dev authorize: %v", err)
	}
	authorizeResp.Body.Close()
	if authorizeResp.StatusCode != http.StatusFound {
		t.Fatalf("POST dev authorize status = %d, want 302", authorizeResp.StatusCode)
	}
	callbackResp, err := client.Get(authorizeResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("GET dev callback: %v", err)
	}
	callbackResp.Body.Close()
	if callbackResp.StatusCode != http.StatusFound {
		t.Fatalf("GET dev callback status = %d, want 302 (successful bootstrap login)", callbackResp.StatusCode)
	}

	admin, err := st.Users().ByEmail(context.Background(), "admin@example.com")
	if err != nil {
		t.Fatalf("Users().ByEmail(admin): %v", err)
	}
	adminPublicID, err := st.PublicUserIDs().ByOwner(context.Background(), admin.ID)
	if err != nil {
		t.Fatalf("PublicUserIDs().ByOwner(admin): %v", err)
	}

	// --- Step 2: deploy a non-public function ---
	deployer := &service.Deployer{Store: st, Blob: blobStore, Runtime: manager}
	packed, err := bundle.Pack(okHandlerFiles("visibility: org\n"))
	if err != nil {
		t.Fatalf("bundle.Pack: %v", err)
	}
	if _, err := deployer.Deploy(context.Background(), service.DeployParams{
		Bundle: bytes.NewReader(packed), Owner: adminPublicID.UserID, Name: "app", Actor: admin,
	}); err != nil {
		t.Fatalf("Deploy: %v", err)
	}

	// --- Step 3: an anonymous browser hits the function host; the invoke
	// path's HTML fallback (§14.3 item 1) redirects it to /auth/invoke ---
	functionOrigin := "http://" + functionHostName("app", functionDomain) + ":" + port
	firstReq, err := http.NewRequest(http.MethodGet, functionOrigin+"/", nil)
	if err != nil {
		t.Fatalf("build first request: %v", err)
	}
	firstReq.Header.Set("Accept", "text/html,application/xhtml+xml")
	firstResp, err := client.Do(firstReq)
	if err != nil {
		t.Fatalf("GET function host (anonymous): %v", err)
	}
	firstResp.Body.Close()
	if firstResp.StatusCode != http.StatusFound {
		t.Fatalf("anonymous function GET status = %d, want 302 (browser SSO handoff)", firstResp.StatusCode)
	}
	invokeLoginLoc := firstResp.Header.Get("Location")
	if !strings.Contains(invokeLoginLoc, "/auth/invoke?") {
		t.Fatalf("Location = %q, want a /auth/invoke handoff", invokeLoginLoc)
	}

	// --- Step 4: follow to the control host's /auth/invoke. The session
	// cookie from step 1 authenticates it, so it mints a one-time code and
	// redirects to the function host's own callback path ---
	invokeResp, err := client.Get(invokeLoginLoc)
	if err != nil {
		t.Fatalf("GET /auth/invoke: %v", err)
	}
	invokeResp.Body.Close()
	if invokeResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("GET /auth/invoke status = %d, want 303 (redirect to function host callback)", invokeResp.StatusCode)
	}
	callbackLoc := invokeResp.Header.Get("Location")
	if !strings.Contains(callbackLoc, "/.funcbox/auth/callback?code=") {
		t.Fatalf("Location = %q, want the function host's browser-callback path", callbackLoc)
	}

	// --- Step 5: follow to the function host's own callback. This is the
	// decisive hop: HandleInvokeCallback sets the "__Host-fbx_invoke"
	// cookie (or, once this bug is fixed, the insecure fallback name) here,
	// over a plain-http response -- exactly where browserjar enforces the
	// rule a real browser does and a plain cookiejar wouldn't ---
	callbackResp2, err := client.Get(callbackLoc)
	if err != nil {
		t.Fatalf("GET function host callback: %v", err)
	}
	callbackResp2.Body.Close()
	if callbackResp2.StatusCode != http.StatusSeeOther {
		t.Fatalf("function host callback status = %d, want 303 (redirect to return_to)", callbackResp2.StatusCode)
	}
	returnToLoc := callbackResp2.Header.Get("Location")

	cbURL, err := url.Parse(callbackLoc)
	if err != nil {
		t.Fatalf("parse callback URL: %v", err)
	}
	returnToRel, err := url.Parse(returnToLoc)
	if err != nil {
		t.Fatalf("parse return_to Location: %v", err)
	}
	finalURL := cbURL.ResolveReference(returnToRel)

	// --- Step 6: the browser follows return_to back to the function host.
	// If the invoke cookie from step 5 survived (browserjar accepted it),
	// this now authenticates and the function actually runs; if it didn't
	// (pre-fix: a real browser discarded a Secure-less "__Host-" cookie),
	// this request is unauthenticated all over again ---
	finalReq, err := http.NewRequest(http.MethodGet, finalURL.String(), nil)
	if err != nil {
		t.Fatalf("build final request: %v", err)
	}
	finalReq.Header.Set("Accept", "text/html,application/xhtml+xml")
	finalResp, err := client.Do(finalReq)
	if err != nil {
		t.Fatalf("GET function host (post-SSO): %v", err)
	}
	defer finalResp.Body.Close()
	if finalResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(finalResp.Body)
		t.Fatalf("final function GET status = %d, body = %q, want 200 -- the browser SSO invoke cookie should now authenticate this request "+
			"(a non-200 here, especially another 302 back to /auth/invoke, means the invoke cookie set in step 5 didn't survive a real browser's cookie-prefix rules)",
			finalResp.StatusCode, body)
	}
}
