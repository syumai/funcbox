package invoke

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/syumai/funcbox/bundle"
	"github.com/syumai/funcbox/runtime"
	blobfs "github.com/syumai/funcbox/server/internal/blob/fs"
	"github.com/syumai/funcbox/server/internal/service"
	"github.com/syumai/funcbox/server/internal/settings"
	"github.com/syumai/funcbox/server/internal/store"
	"github.com/syumai/funcbox/server/internal/store/sqlite"
)

// bootstrapTestOrg creates the singleton organization (with the given
// default_visibility) plus its first (admin) user via
// store.BootstrapFirstUser, exactly as the real /auth/callback flow does,
// and returns that user for use as a Deploy Actor.
func bootstrapTestOrg(t *testing.T, st store.Store, defaultVisibility string) *store.User {
	t.Helper()
	ctx := context.Background()
	u := &store.User{GoogleSub: "sub-admin", Email: "admin@example.com", Name: "Admin"}
	if err := st.BootstrapFirstUser(ctx, u, "Test Org"); err != nil {
		t.Fatalf("BootstrapFirstUser: %v", err)
	}
	if err := st.Handles().Create(ctx, &store.Handle{Handle: "admin", OwnerType: store.OwnerTypeUser, OwnerID: u.ID}); err != nil {
		t.Fatalf("Handles().Create: %v", err)
	}

	org, err := st.Organizations().Get(ctx)
	if err != nil {
		t.Fatalf("Organizations().Get: %v", err)
	}
	orgSet := settings.DefaultOrg()
	orgSet.DefaultVisibility = defaultVisibility
	org.Settings = orgSet.JSON()
	org.SettingsGen++
	if err := st.Organizations().Update(ctx, org); err != nil {
		t.Fatalf("Organizations().Update: %v", err)
	}

	// NOTE: this is deliberately a blanket allow-all rule, WIDER than the
	// real login flow's bootstrap seeding (internal/auth's
	// Auth.seedBootstrapLoginRule only allows the bootstrap admin's own
	// exact email, per the security fix covered in
	// internal/auth/login_devflow_test.go). Login-rule evaluation runs on
	// every authenticated request (including the invoke path's caller
	// resolution), and these invoke-package tests mint tokens for several
	// arbitrary test emails that were never involved in a real login flow,
	// so an allow-all rule here keeps that orthogonal to what's actually
	// under test (visibility/membership, not login rules).
	if err := st.Organizations().ReplaceLoginRules(ctx, []*store.LoginRule{
		{Ord: 0, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionAllow},
	}); err != nil {
		t.Fatalf("ReplaceLoginRules: %v", err)
	}
	return u
}

// newOwnerActor creates a user and claims handle for them, for tests that
// deploy under an owner other than the bootstrapped admin.
func newOwnerActor(t *testing.T, st store.Store, handle string) *store.User {
	t.Helper()
	ctx := context.Background()
	u := &store.User{GoogleSub: "sub-" + handle, Email: handle + "@example.com", Name: handle, Role: store.RoleMember}
	if err := st.Users().Create(ctx, u); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	if err := st.Handles().Create(ctx, &store.Handle{Handle: handle, OwnerType: store.OwnerTypeUser, OwnerID: u.ID}); err != nil {
		t.Fatalf("Handles().Create: %v", err)
	}
	return u
}

// newTestInvoker builds an Invoker backed by a real in-memory sqlite store
// and a temp-dir filesystem blob store, bootstraps an organization (with
// default_visibility "public" -- these tests are about timeout/cookie/404
// behavior, not authorization; see invoke_authz_test.go for the dedicated
// org/workspace-visibility tests), and deploys owner/name via
// service.Deployer so the invoke path is exercised exactly as it would be
// in production (blob-backed cold start, not a hand-built store fixture).
func newTestInvoker(t *testing.T, owner, name string, files map[string][]byte, timeout time.Duration) *Invoker {
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

	admin := bootstrapTestOrg(t, st, "public")
	actor := admin
	if owner != "admin" {
		actor = newOwnerActor(t, st, owner)
	}

	deployer := &service.Deployer{Store: st, Blob: blobStore, Runtime: manager}
	packed, err := bundle.Pack(files)
	if err != nil {
		t.Fatalf("bundle.Pack: %v", err)
	}
	result, err := deployer.Deploy(context.Background(), service.DeployParams{
		Bundle: bytes.NewReader(packed),
		Owner:  owner,
		Name:   name,
		Actor:  actor,
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if result.Function == nil || result.Version == nil {
		t.Fatalf("Deploy returned no function/version: %+v", result)
	}

	return &Invoker{
		Store:   st,
		Blob:    blobStore,
		Manager: manager,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Timeout: timeout,
	}
}

// the pool handler without a deadline-bound context, since that deadline is
// the ONLY mechanism that interrupts a runaway guest loop and frees its
// pool slot. It deploys a genuine `while (true) {}` handler with a very
// short manifest timeout, confirms the first request gets a 504 (not the
// library's raw 500 "handler failed: context deadline exceeded"), and then
// confirms a second request on the SAME pool (Size 1, so there is only one
// slot) succeeds promptly — proving the runaway request didn't permanently
// occupy it.
func TestInvokerTimeoutFreesPoolSlotAndReturns504(t *testing.T) {
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: looptest\ntimeout: 80ms\n"),
		"index.js": []byte(`
			export default {
				async fetch(req) {
					const url = new URL(req.url);
					if (url.searchParams.get("loop") === "1") {
						while (true) {}
					}
					return new Response("ok");
				},
			};
		`),
	}
	inv := newTestInvoker(t, "eve", "looptest", files, 5*time.Second)

	// First request: trips the manifest's 80ms timeout via a genuine
	// infinite loop.
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodGet, "/eve/looptest?loop=1", nil)
	start := time.Now()
	inv.Serve(w1, r1, "eve", "looptest")
	elapsed := time.Since(start)

	if w1.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, body = %q, want 504", w1.Code, w1.Body.String())
	}
	if elapsed > 3*time.Second {
		t.Fatalf("timeout took %s, want well under the 5s Invoker.Timeout (manifest timeout should have fired first at ~80ms)", elapsed)
	}

	// Second request: same function (same pool, cfworkers.PoolConfig.Size
	// default from DefaultPoolSize), no loop this time. If the first
	// request had permanently pinned its instance, this would eventually
	// fail with a pool-exhaustion 503 rather than succeeding.
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, "/eve/looptest", nil)
	inv.Serve(w2, r2, "eve", "looptest")

	if w2.Code != http.StatusOK {
		t.Fatalf("follow-up status = %d, body = %q, want 200 (pool slot should have been freed)", w2.Code, w2.Body.String())
	}
	if w2.Body.String() != "ok" {
		t.Fatalf("follow-up body = %q, want %q", w2.Body.String(), "ok")
	}
}

// TestInvokerCookieHeaderStripped confirms the Cookie header never reaches
func TestInvokerCookieHeaderStripped(t *testing.T) {
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: cookietest\n"),
		"index.js": []byte(`
			export default {
				async fetch(req) {
					return new Response(req.headers.get("Cookie") === null ? "no-cookie" : "leaked");
				},
			};
		`),
	}
	inv := newTestInvoker(t, "frank", "cookietest", files, 5*time.Second)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/frank/cookietest", nil)
	r.Header.Set("Cookie", "session=secret")
	inv.Serve(w, r, "frank", "cookietest")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", w.Code, w.Body.String())
	}
	if w.Body.String() != "no-cookie" {
		t.Fatalf("body = %q, want %q (Cookie header must not reach guest code)", w.Body.String(), "no-cookie")
	}
}

// TestInvokerResponseFuncboxHeaderStripped confirms guest code can never
// set or override a response header under the reserved X-Funcbox-*
// an ordinary custom header the guest sets passes through unmodified.
func TestInvokerResponseFuncboxHeaderStripped(t *testing.T) {
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: headertest\n"),
		"index.js": []byte(`
			export default {
				async fetch(req) {
					return new Response("ok", {
						headers: {
							"X-Funcbox-Caller-Email": "spoofed@evil.com",
							"X-Funcbox-Anything-Else": "also-spoofed",
							"X-Custom-Marker": "kept",
						},
					});
				},
			};
		`),
	}
	inv := newTestInvoker(t, "grace2", "headertest", files, 5*time.Second)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/grace2/headertest", nil)
	inv.Serve(w, r, "grace2", "headertest")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", w.Code, w.Body.String())
	}
	if h := w.Header().Get("X-Funcbox-Caller-Email"); h != "" {
		t.Errorf("X-Funcbox-Caller-Email = %q, want stripped (empty)", h)
	}
	if h := w.Header().Get("X-Funcbox-Anything-Else"); h != "" {
		t.Errorf("X-Funcbox-Anything-Else = %q, want stripped (empty)", h)
	}
	if h := w.Header().Get("X-Custom-Marker"); h != "kept" {
		t.Errorf("X-Custom-Marker = %q, want %q (non-reserved headers must pass through)", h, "kept")
	}
}

// TestInvokerUnknownOwnerAndFunctionAre404 covers the resolve-path 404s.
func TestInvokerUnknownOwnerAndFunctionAre404(t *testing.T) {
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: real\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
	}
	inv := newTestInvoker(t, "grace", "real", files, 5*time.Second)

	t.Run("unknown owner", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/nobody/real", nil)
		inv.Serve(w, r, "nobody", "real")
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", w.Code)
		}
	})

	t.Run("unknown function", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/grace/nope", nil)
		inv.Serve(w, r, "grace", "nope")
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", w.Code)
		}
	})
}
