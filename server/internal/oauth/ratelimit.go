// ratelimit.go implements the in-memory, per-source token bucket guarding
// POST /oauth/register (security review finding A: an unauthenticated
// caller can otherwise mint oauth_clients rows without limit). It is
// intentionally simple -- no external dependency, no persistence, one
// process-lifetime map -- since it is one layer of defense-in-depth
// alongside register.go's input bounds and cleanup.go's TTL sweep, not a
// hard security boundary on its own.
package oauth

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// registerRateBurst/registerRateRefillInterval configure the token bucket
// clientIP allows(): each source starts with registerRateBurst tokens (so
// a legitimate client's own retry-on-failure loop, or a handful of
// distinct MCP clients briefly starting up behind the same NAT/IP, isn't
// punished immediately) and refills at one token every
// registerRateRefillInterval thereafter (10/minute sustained per source) --
// generous for any real client (DCR is normally a once-per-install
// operation) while bounding how many oauth_clients rows a single source
// can create per unit time.
const (
	registerRateBurst          = 20
	registerRateRefillInterval = 6 * time.Second
)

// registerBucketIdleEvict bounds how long an idle source's bucket is kept
// before ipRateLimiter.allow opportunistically evicts it, so a process
// fielding traffic from many distinct source IPs over its lifetime doesn't
// grow this map without bound.
const registerBucketIdleEvict = 30 * time.Minute

// ipRateLimiter is a per-key (in practice, per-source-IP; see clientIP's
// doc comment) token bucket.
type ipRateLimiter struct {
	burst    float64
	interval time.Duration

	mu      sync.Mutex
	buckets map[string]*bucket
	calls   int // opportunistic-eviction counter, see allow
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

func newIPRateLimiter(burst int, interval time.Duration) *ipRateLimiter {
	return &ipRateLimiter{burst: float64(burst), interval: interval, buckets: make(map[string]*bucket)}
}

// allow reports whether key may proceed right now, consuming one token if
// so. Every 1000th call also sweeps buckets idle longer than
// registerBucketIdleEvict, bounding this limiter's memory to
// "distinct sources active within the last half hour" rather than
// "every distinct source this process has ever seen".
func (l *ipRateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst}
		l.buckets[key] = b
	} else {
		elapsed := now.Sub(b.lastSeen)
		b.tokens = min(l.burst, b.tokens+elapsed.Seconds()/l.interval.Seconds())
	}
	b.lastSeen = now

	l.calls++
	if l.calls%1000 == 0 {
		for k, v := range l.buckets {
			if now.Sub(v.lastSeen) > registerBucketIdleEvict {
				delete(l.buckets, k)
			}
		}
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// clientIP extracts the source address ipRateLimiter keys on: the host
// part of r.RemoteAddr, deliberately NOT any client-supplied header like
// X-Forwarded-For. X-Forwarded-For (and similar) is trivially spoofable by
// any caller, and this package has no configured-trusted-proxy convention
// to validate it against, so trusting it here would let a single attacker
// defeat the whole rate limit by sending a fresh forged value on every
// request. The honest tradeoff this implies: deployed behind a reverse
// proxy that does NOT itself rewrite the connection's source address to
// the real client's (Go's own net/http/httputil.ReverseProxy does not,
// by default), every request will appear to share the proxy's own IP, and
// the limit becomes "N/interval for the whole proxied fleet" rather than
// "N/interval per real client" -- an operator fronting funcbox with such a
// proxy needs it to preserve the real client address into the connection
// funcbox-server accepts (e.g. PROXY protocol, or a front door that dials
// upstream from the original client's address) for this limiter to behave
// as intended.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
