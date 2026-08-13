// Package invoke implements the function-invocation path
// (/{owner}/{func}[/...], tmp/02-architecture.md "関数呼び出し"): resolve
// owner/function/active-version from the store, load the version's bundle
// from blob storage, obtain its runtime.Manager-owned pool, and serve the
// request through it.
//
// This package is server-only (not shared with the funcbox CLI binary), so
// it is free to depend on internal/store, internal/blob, and
// policy alongside the shared runtime package.
package invoke

import (
	"net"

	"github.com/syumai/funcbox/internal/store"
	"github.com/syumai/funcbox/policy"
)

// fetchPolicyAdapter implements runtime.FetchPolicy on top of a live
// policy.EffectivePolicy resolver + policy.BlockedIP, matching
// tmp/03-runtime.md 3.4's two-gate split: AllowHost consults the
// host-pattern policy, AllowIP applies the SSRF/metadata-address guard to
// whatever address is actually being dialed.
//
// resolve is called on EVERY AllowHost invocation rather than once at
// construction time. This is deliberate: a fetchPolicyAdapter is captured
// inside a runtime.Manager pool's Config at build time, and that pool is
// warmed once and reused across many requests
// (tmp/05-auth-and-permissions.md §5.6: "実効ポリシーは実行時に解決す
// る... 組織/WSの設定変更が即座に全関数へ波及することを保証するため").
// If AllowHost captured a frozen EffectivePolicy instead, an org/workspace
// fetch-policy change would only take effect the next time this
// function's pool happened to be rebuilt (e.g. after a redeploy or an
// idle-eviction), not immediately. See effective.go's effectiveCache for
// how resolve stays cheap despite being called on every outbound fetch.
type fetchPolicyAdapter struct {
	resolve    func() policy.EffectivePolicy
	literalIPs map[string]bool // canonical net.IP.String() form

	// tracker records every ALLOW/DENY decision against the calling
	// goroutine's currently-in-flight invocation, for the execution log
	// (tmp/10-roadmap.md Phase 4); see logcapture.go. May be nil (tests
	// construct fetchPolicyAdapter directly without one), in which case
	// decisions simply aren't recorded.
	tracker *invocationTracker
}

func newFetchPolicyAdapter(resolve func() policy.EffectivePolicy, manifestAllow []policy.Pattern, tracker *invocationTracker) *fetchPolicyAdapter {
	literalIPs := make(map[string]bool)
	for _, p := range manifestAllow {
		if ip := patternLiteralIP(p); ip != nil {
			literalIPs[ip.String()] = true
		}
	}
	return &fetchPolicyAdapter{resolve: resolve, literalIPs: literalIPs, tracker: tracker}
}

// AllowHost implements runtime.FetchPolicy.
func (a *fetchPolicyAdapter) AllowHost(host string, port int) bool {
	allowed := a.resolve().Decision(host, port)
	a.record(host, port, allowed, "resolve")
	return allowed
}

// AllowIP implements runtime.FetchPolicy.
func (a *fetchPolicyAdapter) AllowIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		// Fail closed on an address we can't even parse.
		a.record(ip, 0, false, "dial")
		return false
	}
	if a.literalIPs[parsed.String()] {
		a.record(ip, 0, true, "dial")
		return true
	}
	allowed := !policy.BlockedIP(parsed)
	a.record(ip, 0, allowed, "dial")
	return allowed
}

// record appends a fetch decision to whichever invocation is currently
// executing on the calling goroutine, if any (see invocationTracker's doc
// comment for why goroutine-keyed attribution is safe here).
func (a *fetchPolicyAdapter) record(host string, port int, allowed bool, stage string) {
	if a.tracker == nil {
		return
	}
	if c := a.tracker.current(); c != nil {
		c.recordFetch(store.FetchDecision{Host: host, Port: port, Allowed: allowed, Stage: stage})
	}
}

// patternLiteralIP reports the IP address p names, if p's host text is
// itself a literal IP address rather than a DNS name or wildcard pattern.
func patternLiteralIP(p policy.Pattern) net.IP {
	host := p.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return net.ParseIP(host)
}
