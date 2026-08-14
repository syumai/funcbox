// oauthstate_concurrent_test.go is the regression coverage for the bug
// report "funcbox login で OAuth state mismatch エラーが出る": the OAuth
// state cookie (login.go's setOAuthStateCookie/consumeOAuthStateCookie,
// shared by the OIDC/dev and GitHub login-start handlers) used to hold
// exactly ONE signed pending state, so a second GET /auth/login from the
// same browser (the same cookie jar) before the first had been completed
// silently overwrote it -- submitting the FIRST login form then failed at
// the callback with "OAuth state mismatch", even though nothing about that
// first login attempt was actually wrong.
//
// This happens routinely with `funcbox login`
// (internal/cli/login.go/loginViaBrowser): it both auto-opens the browser
// AND prints the URL to the terminal, so a user who clicks the printed
// link after the auto-opened tab already loaded (or who still has a
// pre-restart sign-in tab open) ends up with two parallel /auth/login
// starts sharing one cookie jar.
package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/syumai/funcbox/server/internal/browserjar"
)

// startDevLogin drives just the GET /auth/login -> dev-authorize redirect
// half of devLoginTestEnv.login, without completing the form -- so a test
// can start several logins on the same client before completing any of
// them.
func startDevLogin(t *testing.T, env *devLoginTestEnv, client *http.Client) url.Values {
	t.Helper()
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
	return authorizeURL.Query()
}

// completeDevLogin finishes a login started by startDevLogin: submits the
// dev authorize form for params (as returned by startDevLogin) with the
// given email, then follows through the callback. Returns the callback's
// final redirect Location.
func completeDevLogin(t *testing.T, env *devLoginTestEnv, client *http.Client, params url.Values, email string) string {
	t.Helper()
	form := url.Values{
		"client_id":    {params.Get("client_id")},
		"redirect_uri": {params.Get("redirect_uri")},
		"state":        {params.Get("state")},
		"nonce":        {params.Get("nonce")},
		"email":        {email},
	}
	resp, err := client.PostForm(env.server.URL+devOIDCPrefix+"/authorize", form)
	if err != nil {
		t.Fatalf("POST %s/authorize: %v", devOIDCPrefix, err)
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
	return resp.Header.Get("Location")
}

// TestOAuthState_TwoParallelLoginStartsBothComplete is the failing-first
// test the fix must turn green: two sequential /auth/login starts sharing
// one cookie jar (exactly what `funcbox login`'s auto-open-and-print-URL
// behavior, or a stale pre-restart tab, produces), then completing the
// FIRST start's form. Before the fix this fails at the callback with
// "OAuth state mismatch" because the second start's Set-Cookie silently
// overwrote the first start's pending state cookie.
func TestOAuthState_TwoParallelLoginStartsBothComplete(t *testing.T) {
	env := newDevLoginTestEnv(t)
	client := &http.Client{
		Jar: browserjar.New(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	first := startDevLogin(t, env, client)
	second := startDevLogin(t, env, client)
	if first.Get("state") == second.Get("state") {
		t.Fatalf("two independent /auth/login starts produced the same state %q -- test setup is broken", first.Get("state"))
	}

	location := completeDevLogin(t, env, client, first, "alice@example.com")
	if strings.Contains(location, "login_error") {
		t.Fatalf("completing the FIRST of two parallel login starts failed: redirect = %q, want /dashboard", location)
	}
	if !strings.HasPrefix(location, "/dashboard") {
		t.Fatalf("final redirect = %q, want a /dashboard location (successful login)", location)
	}
}

// TestOAuthState_TwoParallelLoginStartsSecondAlsoCompletes covers the other
// half of the parallel-starts scenario: as long as the FIRST start's
// pending state hasn't been consumed yet (i.e. its own callback was never
// completed), the SECOND start must independently be completable too --
// design (b) (per-state cookie names, see login.go's oauthStateCookieName)
// gives each concurrent login start its own cookie, so there is no shared
// state for one to consume or clobber.
func TestOAuthState_TwoParallelLoginStartsSecondAlsoCompletes(t *testing.T) {
	env := newDevLoginTestEnv(t)
	client := &http.Client{
		Jar: browserjar.New(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	first := startDevLogin(t, env, client)
	second := startDevLogin(t, env, client)

	// Both starts complete as the SAME identity (alice): the first
	// completion bootstraps her as admin (seedBootstrapLoginRule allows
	// exactly her own email -- see login.go), and the second is then just
	// an ordinary repeat login by the same, already-allowed user. Using two
	// different emails here would additionally exercise the login-rules
	// gate (a second, brand-new email is denied by default post-bootstrap),
	// which is irrelevant to what this test is checking: that the SECOND
	// start's own per-state cookie is independently usable at all.
	location := completeDevLogin(t, env, client, second, "alice@example.com")
	if strings.Contains(location, "login_error") {
		t.Fatalf("completing the SECOND of two parallel login starts failed: redirect = %q, want /dashboard", location)
	}
	if !strings.HasPrefix(location, "/dashboard") {
		t.Fatalf("final redirect = %q, want a /dashboard location (successful login)", location)
	}

	// The first start's cookie is untouched by the second's completion --
	// completing it too must still work.
	location = completeDevLogin(t, env, client, first, "alice@example.com")
	if strings.Contains(location, "login_error") {
		t.Fatalf("completing the FIRST start after the second had already completed failed: redirect = %q, want /dashboard", location)
	}
}

// TestOAuthState_UnknownStateStillFailsWithMismatch is the "no-match ->
// existing mismatch failure" requirement: a callback whose state query
// param was never issued by this server (no matching per-state cookie
// exists at all) must still land on the styled sign-in-failed page with
// the unchanged "OAuth state mismatch" wording, not silently succeed or
// panic.
func TestOAuthState_UnknownStateStillFailsWithMismatch(t *testing.T) {
	env := newDevLoginTestEnv(t)
	client := &http.Client{
		Jar: browserjar.New(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(env.server.URL + "/auth/callback?state=totally-unknown-state&code=whatever")
	if err != nil {
		t.Fatalf("GET callback: %v", err)
	}
	resp.Body.Close()
	location := resp.Header.Get("Location")
	if !strings.Contains(location, "login_error") {
		t.Fatalf("callback with an unknown state = %q, want a login_error redirect", location)
	}
}

// TestOAuthState_SetCookieMaxAge asserts the raw Set-Cookie header for a
// fresh login start still carries the unchanged oauthStateMaxAge, proving
// stale/abandoned parallel starts age out on their own rather than needing
// server-side pruning (design (b)'s answer to "expiry pruning / cookie-size
// cap": there is no server-side list to prune -- each per-state cookie is
// independent and simply expires).
func TestOAuthState_SetCookieMaxAge(t *testing.T) {
	env := newDevLoginTestEnv(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	rec := httptest.NewRecorder()
	env.auth.Routes().ServeHTTP(rec, req)

	var maxAge int
	var sawStateCookie bool
	for _, c := range rec.Result().Cookies() {
		if strings.HasPrefix(c.Name, env.auth.oauthStateCookieNamePrefix()) {
			sawStateCookie = true
			maxAge = c.MaxAge
		}
	}
	if !sawStateCookie {
		t.Fatalf("no per-state oauth cookie in Set-Cookie headers: %v", rec.Result().Cookies())
	}
	if maxAge <= 0 || maxAge > int(oauthStateMaxAge.Seconds()) {
		t.Fatalf("oauth state cookie MaxAge = %d, want a positive value <= %d (oauthStateMaxAge)", maxAge, int(oauthStateMaxAge.Seconds()))
	}
}

// TestOAuthState_ManyParallelStartsEachGetOwnCookieNoSharedContention pushes
// the parallel-starts scenario further than two: N starts on the same
// client must each get their own distinctly-named cookie (design (b) has no
// shared cookie to overwrite or cap), and completing them in an arbitrary
// (non-start) order must still succeed for every one of them.
func TestOAuthState_ManyParallelStartsEachGetOwnCookieNoSharedContention(t *testing.T) {
	env := newDevLoginTestEnv(t)
	client := &http.Client{
		Jar: browserjar.New(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	const n = 8
	starts := make([]url.Values, n)
	seenStates := map[string]bool{}
	for i := 0; i < n; i++ {
		starts[i] = startDevLogin(t, env, client)
		state := starts[i].Get("state")
		if seenStates[state] {
			t.Fatalf("duplicate state %q across parallel starts", state)
		}
		seenStates[state] = true
	}

	u, _ := url.Parse(env.server.URL)
	prefix := env.auth.oauthStateCookieNamePrefix()
	var stateCookieCount int
	for _, c := range client.Jar.Cookies(u) {
		if strings.HasPrefix(c.Name, prefix) {
			stateCookieCount++
		}
	}
	if stateCookieCount != n {
		t.Fatalf("jar holds %d oauth-state cookies after %d parallel starts, want %d (one per start, no shared/overwritten cookie)", stateCookieCount, n, n)
	}

	// Complete them in reverse order -- an arbitrary, non-start order --
	// each must independently succeed.
	for i := n - 1; i >= 0; i-- {
		location := completeDevLogin(t, env, client, starts[i], "user@example.com")
		if strings.Contains(location, "login_error") {
			t.Fatalf("completing parallel start #%d failed: redirect = %q, want /dashboard", i, location)
		}
	}
}
