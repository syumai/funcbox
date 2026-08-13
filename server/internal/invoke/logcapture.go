package invoke

import (
	"bytes"
	"io"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/syumai/funcbox/internal/store"
)

// maxCapturedOutputBytes bounds how much of a single invocation's guest
// stdout/stderr is retained per stream, so a runaway console.log loop
// can't inflate an invocation_logs row (or a DynamoDB item, which has its
// own hard 400KB size ceiling) without bound.
const maxCapturedOutputBytes = 32 * 1024

// maxCapturedFetchDecisions bounds how many fetch ALLOW/DENY decisions a
// single invocation records, for the same reason.
const maxCapturedFetchDecisions = 200

// boundedBuffer is a bytes.Buffer capped at maxCapturedOutputBytes; writes
// past the cap are silently truncated rather than erroring, since guest
// I/O must never fail or block on log-capture bookkeeping.
type boundedBuffer struct {
	buf bytes.Buffer
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len() >= maxCapturedOutputBytes {
		return len(p), nil
	}
	remaining := maxCapturedOutputBytes - b.buf.Len()
	if len(p) > remaining {
		p = p[:remaining]
	}
	b.buf.Write(p)
	return len(p), nil
}

func (b *boundedBuffer) String() string { return b.buf.String() }

// capture accumulates one invocation's guest console output and fetch
// ALLOW/DENY decisions. Exactly one goroutine (the request's own) ever
// touches a given capture's stdout/stderr buffers; fetchDecisions is
// mutex-guarded defensively in case a future guest fetch implementation
// ever parallelizes fetches within one request.
type capture struct {
	stdout boundedBuffer
	stderr boundedBuffer

	mu             sync.Mutex
	fetchDecisions []store.FetchDecision
}

func (c *capture) recordFetch(d store.FetchDecision) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.fetchDecisions) >= maxCapturedFetchDecisions {
		return
	}
	c.fetchDecisions = append(c.fetchDecisions, d)
}

func (c *capture) fetchDecisionsSnapshot() []store.FetchDecision {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]store.FetchDecision(nil), c.fetchDecisions...)
}

// invocationTracker demultiplexes a shared, pool-wide io.Writer
// (cfworkers.Pool's Config.Stdout/Stderr, fixed once at pool-BUILD time in
// pool.go's buildPool and then reused by every request the warmed pool
// serves -- see spidermonkey.Config's doc comment: "Stdin, Stdout, Stderr
// are for HOST FUNCTIONS") back into per-invocation buffers, and does the
// same for fetchPolicyAdapter's per-call ALLOW/DENY decisions (policy.go).
// Both are keyed by the calling goroutine's id.
//
// This relies on cfworkers's documented "goroutine-per-request" execution
// model (see that package's doc comment): one request's entire lifecycle
// -- including every guest console write and outbound fetch decision --
// runs synchronously on the single goroutine that called ServeHTTP, never
// handed off elsewhere. A goroutine-id-keyed map therefore correctly
// attributes output/decisions back to the request that produced them, with
// no cross-talk between the many requests a warmed pool may be serving
// concurrently on other goroutines at the same time.
type invocationTracker struct {
	mu    sync.Mutex
	byGID map[uint64]*capture
}

func newInvocationTracker() *invocationTracker {
	return &invocationTracker{byGID: make(map[uint64]*capture)}
}

// begin registers the calling goroutine with a fresh capture and returns
// it; the caller must call end() (typically via defer, immediately after)
// once the invocation is complete, from the SAME goroutine.
func (t *invocationTracker) begin() *capture {
	c := &capture{}
	gid := curGoroutineID()
	t.mu.Lock()
	t.byGID[gid] = c
	t.mu.Unlock()
	return c
}

func (t *invocationTracker) end() {
	gid := curGoroutineID()
	t.mu.Lock()
	delete(t.byGID, gid)
	t.mu.Unlock()
}

// current returns the calling goroutine's registered capture, or nil if
// none is registered -- e.g. guest module-level top-level code executing
// outside any request's begin/end window, which isn't attributable to a
// specific invocation.
func (t *invocationTracker) current() *capture {
	gid := curGoroutineID()
	t.mu.Lock()
	c := t.byGID[gid]
	t.mu.Unlock()
	return c
}

// stdoutWriter and stderrWriter adapt an invocationTracker into the
// io.Writer shape spidermonkey.Config.Stdout/Stderr need. A Write with no
// currently-registered capture is discarded, matching Config's documented
// behavior for an unset stream ("discarded output").
type stdoutWriter struct{ t *invocationTracker }
type stderrWriter struct{ t *invocationTracker }

func (w stdoutWriter) Write(p []byte) (int, error) {
	if c := w.t.current(); c != nil {
		return c.stdout.Write(p)
	}
	return len(p), nil
}

func (w stderrWriter) Write(p []byte) (int, error) {
	if c := w.t.current(); c != nil {
		return c.stderr.Write(p)
	}
	return len(p), nil
}

var (
	_ io.Writer = stdoutWriter{}
	_ io.Writer = stderrWriter{}
)

// curGoroutineID extracts the calling goroutine's id by parsing the first
// line of runtime.Stack's output ("goroutine 123 [running]:..."). The id
// is not part of any public API, but its presence in runtime.Stack's
// output is a long-stable implementation detail several well-known
// debugging/tracing libraries already rely on the same way; it avoids
// adding an external dependency just for this.
func curGoroutineID() uint64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	s := strings.TrimPrefix(string(buf[:n]), "goroutine ")
	if i := strings.IndexByte(s, ' '); i >= 0 {
		s = s[:i]
	}
	id, _ := strconv.ParseUint(s, 10, 64)
	return id
}
