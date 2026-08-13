package runtime

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	spidermonkey "github.com/goccy/go-spidermonkey"
	"github.com/goccy/go-spidermonkey/compat/cfworkers"
)

// allowlistPolicy is a tiny FetchPolicy for tests: it allows a fixed set of
// hosts (by exact match) and, separately, a fixed set of IPs — standing in
// for the future internal/policy package's host-pattern-match ∩ SSRF-guard
// split.
type allowlistPolicy struct {
	hosts map[string]bool
	ips   map[string]bool
}

func (p allowlistPolicy) AllowHost(host string, _ int) bool { return p.hosts[host] }
func (p allowlistPolicy) AllowIP(ip string) bool            { return p.ips[ip] }

func fetchHandlerSource() string {
	return `
		export default {
			async fetch(req, env, ctx) {
				const target = new URL(req.url).searchParams.get("target");
				try {
					const r = await fetch(target);
					return new Response("ok:" + (await r.text()));
				} catch (e) {
					return new Response("fail:" + String((e && e.message) || e), { status: 502 });
				}
			},
		};
	`
}

// TestHooksAllowAllowedHost is checklist item 2's happy path: fetch() to a
// host the policy allows (an httptest target on 127.0.0.1) succeeds.
func TestHooksAllowAllowedHost(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "upstream data")
	}))
	defer upstream.Close()

	policy := allowlistPolicy{
		hosts: map[string]bool{"127.0.0.1": true},
		ips:   map[string]bool{"127.0.0.1": true},
	}

	pool, err := cfworkers.NewPool(cfworkers.PoolConfig{
		Size: 1,
		Config: spidermonkey.Config{
			Resolve: ResolveHook(policy),
			Dial:    DialHook(policy),
		},
		Source: fetchHandlerSource(),
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	srv := httptest.NewServer(pool)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/?target=" + upstream.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%q, want 200", resp.StatusCode, body)
	}
	if string(body) != "ok:upstream data" {
		t.Errorf("body = %q, want %q", body, "ok:upstream data")
	}
}

// TestHooksDenyDisallowedHost is checklist item 2's denial path: fetch() to
// a host NOT in the policy's allowlist fails with a guest-visible error
// (not a Go panic, not a hang), and the failure is distinguishable from a
// generic network error.
func TestHooksDenyDisallowedHost(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "should never be reached")
	}))
	defer upstream.Close()

	// Policy allows nothing at all: an httptest server is always on
	// 127.0.0.1, so an empty allowlist reliably denies it without needing a
	// real disallowed host on the network.
	policy := allowlistPolicy{hosts: map[string]bool{}, ips: map[string]bool{}}

	pool, err := cfworkers.NewPool(cfworkers.PoolConfig{
		Size: 1,
		Config: spidermonkey.Config{
			Resolve: ResolveHook(policy),
			Dial:    DialHook(policy),
		},
		Source: fetchHandlerSource(),
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	srv := httptest.NewServer(pool)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/?target=" + upstream.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 502 {
		t.Fatalf("status = %d body=%q, want 502 (guest-caught denial)", resp.StatusCode, body)
	}
	if !strings.HasPrefix(string(body), "fail:") {
		t.Errorf("body = %q, want a guest-visible fail: message", body)
	}
	if !strings.Contains(string(body), "permission denied") {
		t.Errorf("body = %q, want a permission-denied style message", body)
	}
}

// TestHooksNilPolicyDeniesEverything is checklist item 2's fail-closed
// case: a nil FetchPolicy must deny every fetch, exactly like a nil
// Config.Dial/Resolve already does — ResolveHook(nil)/DialHook(nil) must
// not panic and must always return false.
func TestHooksNilPolicyDeniesEverything(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "should never be reached")
	}))
	defer upstream.Close()

	pool, err := cfworkers.NewPool(cfworkers.PoolConfig{
		Size: 1,
		Config: spidermonkey.Config{
			Resolve: ResolveHook(nil),
			Dial:    DialHook(nil),
		},
		Source: fetchHandlerSource(),
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	srv := httptest.NewServer(pool)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/?target=" + upstream.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 502 {
		t.Fatalf("status = %d body=%q, want 502 (nil policy must fail closed)", resp.StatusCode, body)
	}
	if !strings.HasPrefix(string(body), "fail:") {
		t.Errorf("body = %q, want a guest-visible fail: message", body)
	}
}

// TestHooksAllowIPGuardsEvenAnAllowedHost verifies AllowIP is consulted as a
// SECOND, independent gate even when AllowHost matches — the SSRF backstop
// DialHook documents: a host pattern allowlisting "127.0.0.1" must still be
// blockable at the IP layer.
func TestHooksAllowIPGuardsEvenAnAllowedHost(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "should never be reached")
	}))
	defer upstream.Close()

	// Host is allowed, but the IP-level guard denies everything — models a
	// policy's loopback/metadata-address backstop firing even though a
	// (misconfigured) host allowlist matched.
	policy := allowlistPolicy{
		hosts: map[string]bool{"127.0.0.1": true},
		ips:   map[string]bool{}, // deny all IPs
	}

	pool, err := cfworkers.NewPool(cfworkers.PoolConfig{
		Size: 1,
		Config: spidermonkey.Config{
			Resolve: ResolveHook(policy),
			Dial:    DialHook(policy),
		},
		Source: fetchHandlerSource(),
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	srv := httptest.NewServer(pool)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/?target=" + upstream.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 502 {
		t.Fatalf("status = %d body=%q, want 502 (AllowIP must still gate)", resp.StatusCode, body)
	}
}

// TestHooksResolveHookGatesNamedHost proves ResolveHook is actually
// consulted for a NAMED host (as opposed to the literal-IP dial the other
// tests exercise, where Resolve is skipped entirely per config.go): a
// request to "localhost" needs a real DNS lookup, so denying it at Resolve
// must fail the fetch before Dial is ever reached — an allow-everything
// Dial does not save it.
func TestHooksResolveHookGatesNamedHost(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "should never be reached")
	}))
	defer upstream.Close()
	// httptest.NewServer listens on 127.0.0.1:port; retarget the URL at
	// "localhost" so the guest's fetch performs a real name resolution.
	localhostURL := strings.Replace(upstream.URL, "127.0.0.1", "localhost", 1)

	policy := allowlistPolicy{
		hosts: map[string]bool{}, // deny at Resolve time regardless of Dial
		ips:   map[string]bool{"127.0.0.1": true, "::1": true},
	}
	dialAllowsEverything := func(network, host, ip string, port int) bool { return true }

	pool, err := cfworkers.NewPool(cfworkers.PoolConfig{
		Size: 1,
		Config: spidermonkey.Config{
			Resolve: ResolveHook(policy),
			Dial:    dialAllowsEverything,
		},
		Source: fetchHandlerSource(),
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	srv := httptest.NewServer(pool)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/?target=" + localhostURL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 502 {
		t.Fatalf("status = %d body=%q, want 502 (Resolve denial must block even though Dial allows everything)", resp.StatusCode, body)
	}
}
