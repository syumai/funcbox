package runtime

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	spidermonkey "github.com/goccy/go-spidermonkey"

	"github.com/syumai/funcbox/policy"
	"github.com/syumai/funcbox/runtime/enginepool"
)

// allowlistPolicy is a tiny FetchPolicy for tests: it allows a fixed set of
// hosts, each restricted to a fixed set of allowed ports — standing in for
// the future policy package's host-pattern-match ∩ SSRF-guard
// split, but WITHOUT ignoring the port argument.
//
// An earlier version of this fake had AllowHost(host, _ int) always ignore
// port, which let ResolveHook's port-0 "pre-check" call and DialHook's
// real-port call collapse into an identical answer. That masked exactly
// the class of bug that shipped in policy.Pattern.portMatches
// (port 0 requiring an exact 80/443 match instead of matching any
// pattern's default-allowed port), because a fake that can't tell "give me
// the resolve-time answer" from "give me the dial-time answer" apart can't
// fail differently between them. Port 0 here gets the same "host is
// allowed on some port" pre-check semantics FetchPolicy.AllowHost
// documents; a real, nonzero port is checked exactly against the allowed
// set, same as production.
type allowlistPolicy struct {
	hosts map[string][]int // host -> allowed ports (empty/absent = host not allowed at all)
	ips   map[string]bool
}

func (p allowlistPolicy) AllowHost(host string, port int) bool {
	ports := p.hosts[host]
	if len(ports) == 0 {
		return false
	}
	if port == 0 {
		return true
	}
	for _, allowed := range ports {
		if allowed == port {
			return true
		}
	}
	return false
}
func (p allowlistPolicy) AllowIP(ip string) bool { return p.ips[ip] }

// mustURLPort extracts the numeric port from an httptest.Server URL
// (always "http://host:port").
func mustURLPort(t *testing.T, rawURL string) int {
	t.Helper()
	u := strings.TrimPrefix(rawURL, "http://")
	_, portStr, err := net.SplitHostPort(u)
	if err != nil {
		t.Fatalf("split host:port from %q: %v", rawURL, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port from %q: %v", rawURL, err)
	}
	return port
}

func fetchHandlerSource() string {
	return `
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
		hosts: map[string][]int{"127.0.0.1": {mustURLPort(t, upstream.URL)}},
		ips:   map[string]bool{"127.0.0.1": true},
	}

	pool, err := enginepool.NewPool(enginepool.Config{
		Size: 1,
		Engine: spidermonkey.Config{
			Resolve: ResolveHook(policy),
			Dial:    DialHook(policy),
		},
		Entry:  "index.js",
		Loader: NewLoader(Bundle{"index.js": []byte(fetchHandlerSource())}),
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
	policy := allowlistPolicy{hosts: map[string][]int{}, ips: map[string]bool{}}

	pool, err := enginepool.NewPool(enginepool.Config{
		Size: 1,
		Engine: spidermonkey.Config{
			Resolve: ResolveHook(policy),
			Dial:    DialHook(policy),
		},
		Entry:  "index.js",
		Loader: NewLoader(Bundle{"index.js": []byte(fetchHandlerSource())}),
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

	pool, err := enginepool.NewPool(enginepool.Config{
		Size: 1,
		Engine: spidermonkey.Config{
			Resolve: ResolveHook(nil),
			Dial:    DialHook(nil),
		},
		Entry:  "index.js",
		Loader: NewLoader(Bundle{"index.js": []byte(fetchHandlerSource())}),
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
		hosts: map[string][]int{"127.0.0.1": {mustURLPort(t, upstream.URL)}},
		ips:   map[string]bool{}, // deny all IPs
	}

	pool, err := enginepool.NewPool(enginepool.Config{
		Size: 1,
		Engine: spidermonkey.Config{
			Resolve: ResolveHook(policy),
			Dial:    DialHook(policy),
		},
		Entry:  "index.js",
		Loader: NewLoader(Bundle{"index.js": []byte(fetchHandlerSource())}),
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
		hosts: map[string][]int{}, // deny at Resolve time regardless of Dial
		ips:   map[string]bool{"127.0.0.1": true, "::1": true},
	}
	dialAllowsEverything := func(network, host, ip string, port int) bool { return true }

	pool, err := enginepool.NewPool(enginepool.Config{
		Size: 1,
		Engine: spidermonkey.Config{
			Resolve: ResolveHook(policy),
			Dial:    dialAllowsEverything,
		},
		Entry:  "index.js",
		Loader: NewLoader(Bundle{"index.js": []byte(fetchHandlerSource())}),
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

// realPolicyFetchPolicy adapts a real policy.EffectivePolicy to
// the FetchPolicy interface, mirroring internal/invoke/policy.go's
// production fetchPolicyAdapter closely enough to exercise the actual
// Pattern/Decision port-matching logic end to end, unlike the allowlistPolicy
// fake above.
type realPolicyFetchPolicy struct {
	eff policy.EffectivePolicy
}

func (p realPolicyFetchPolicy) AllowHost(host string, port int) bool {
	return p.eff.Decision(host, port)
}

func (p realPolicyFetchPolicy) AllowIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	// "localhost" resolves to a loopback address, which policy.BlockedIP
	// flags as an SSRF risk in production. This test's whole point is
	// exercising the host-pattern (Resolve/Dial) path, not the SSRF guard
	// (already covered by TestHooksAllowIPGuardsEvenAnAllowedHost), so
	// loopback is allowed here.
	return parsed.IsLoopback()
}

// TestHooksResolveHookAllowsRealPolicyAllowlistedHost is the end-to-end
// regression test for the fetch-allowlist bug: policy.Pattern's
// portMatches used to require an exact port match even for ResolveHook's
// port-0 pre-check, so a hostname allowlist entry denied every DNS fetch
// at the Resolve step regardless of what the allowlist actually said.
// allowlistPolicy above is a hand-rolled fake and, even after being fixed
// to stop ignoring port entirely, encodes its own (correct) port-0
// semantics rather than exercising policy's — this test drives
// the real policy package instead, resolving an actual hostname
// ("localhost", which resolves without hitting the network) that is
// allowlisted by NAME — not by its resolved IP — so the full Resolve ->
// Dial path is exercised exactly as production's fetchPolicyAdapter does.
func TestHooksResolveHookAllowsRealPolicyAllowlistedHost(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "upstream data")
	}))
	defer upstream.Close()

	port := mustURLPort(t, upstream.URL)
	localhostURL := "http://localhost:" + strconv.Itoa(port)

	pat, err := policy.ParsePattern("localhost:" + strconv.Itoa(port))
	if err != nil {
		t.Fatalf("ParsePattern: %v", err)
	}
	eff := policy.Effective(policy.FetchPolicy{Mode: policy.FetchModeAllowlist, Allow: []policy.Pattern{pat}})
	fp := realPolicyFetchPolicy{eff: eff}

	pool, err := enginepool.NewPool(enginepool.Config{
		Size: 1,
		Engine: spidermonkey.Config{
			Resolve: ResolveHook(fp),
			Dial:    DialHook(fp),
		},
		Entry:  "index.js",
		Loader: NewLoader(Bundle{"index.js": []byte(fetchHandlerSource())}),
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
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%q, want 200 (an allowlisted hostname must resolve and dial successfully); this is the regression test for the port-0 fetch-allowlist bug", resp.StatusCode, body)
	}
	if string(body) != "ok:upstream data" {
		t.Errorf("body = %q, want %q", body, "ok:upstream data")
	}
}
