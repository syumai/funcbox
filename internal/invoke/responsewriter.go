package invoke

import (
	"bytes"
	"context"
	"net/http"
	"strings"
)

// sniffLimit bounds how many response-body bytes invokeResponseWriter
// buffers for its "was this an out-of-memory abort" heuristic
// (tmp/phase0-findings.md item 5): enough to contain the fixed string
// cfworkers writes ("worker error: out of memory\n") without buffering an
// entire (possibly streamed) response body.
const sniffLimit = 64

// invokeResponseWriter wraps the real http.ResponseWriter for one
// invocation to implement two Phase 0-derived invariants without breaking
// streaming responses on the common (non-error) path:
//
//  1. Timeout -> 504. cfworkers' worker.serve writes an ordinary 500
//     ("handler failed: context deadline exceeded") when the deadline
//     ctx's watchdog interrupts a runaway handler
//     (tmp/phase0-findings.md item 4) — indistinguishable, at the HTTP
//     layer, from any other guest error. tmp/07-http-api.md wants a 504
//     for a genuine timeout instead. That specific 500 is written
//     synchronously, as a direct consequence of ctx already having
//     expired, so checking "is this the FIRST WriteHeader call, is the
//     code 500, and has ctx already expired" at the exact moment
//     WriteHeader is invoked reliably identifies it — an unrelated 500
//     essentially never coincides with ctx already being expired — and
//     lets us swap in 504 before anything reaches the client. A response
//     that has already started streaming real bytes is left alone: by
//     definition, status and headers are already committed to the client
//     by that point, so there is nothing left to swap (and rightly so —
//     the guest did produce a real, if slow, response).
//  2. OOM detection. Peek at the first sniffLimit bytes of a 500 response
//     body for the literal substring "out of memory" so the caller can
//     decide whether to Manager.Invalidate the version's pool
//     (tmp/phase0-findings.md item 5: detection is message-text matching
//     only — there is no structured signal to test against instead).
type invokeResponseWriter struct {
	http.ResponseWriter
	ctx context.Context

	wroteHeader bool
	swapped     bool // true once a ctx-timeout 500 has been rewritten to 504
	status      int  // the ORIGINAL status the handler attempted to write
	sniff       []byte
}

func (w *invokeResponseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = code

	// X-Funcbox-* is reserved response-header namespace (tmp/07-http-api.md
	// §7.2: "X-Funcbox-* は上書き禁止"): strip anything guest code set
	// under it before the response is ever committed to the client, so a
	// function can never spoof a funcbox-controlled header.
	for k := range w.ResponseWriter.Header() {
		if strings.HasPrefix(k, "X-Funcbox-") {
			w.ResponseWriter.Header().Del(k)
		}
	}

	if code == http.StatusInternalServerError && w.ctx.Err() != nil {
		w.swapped = true
		w.ResponseWriter.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.ResponseWriter.WriteHeader(http.StatusGatewayTimeout)
		_, _ = w.ResponseWriter.Write([]byte(`{"error":{"code":"timeout","message":"function invocation timed out"}}`))
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *invokeResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if len(w.sniff) < sniffLimit {
		n := sniffLimit - len(w.sniff)
		if n > len(b) {
			n = len(b)
		}
		w.sniff = append(w.sniff, b[:n]...)
	}
	if w.swapped {
		// The real 504 body was already written from WriteHeader; discard
		// whatever the (now-superseded) 500 handler tries to write.
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

// Flush forwards to the underlying ResponseWriter's http.Flusher, if any,
// so streaming responses (tmp/phase0-findings.md item 8) still deliver
// incrementally through this wrapper.
func (w *invokeResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// isLikelyOOM reports whether the response looks like the
// "worker error: out of memory" shape cfworkers produces for a
// MaxMemoryBytes abort.
func (w *invokeResponseWriter) isLikelyOOM() bool {
	return w.status == http.StatusInternalServerError && bytes.Contains(w.sniff, []byte("out of memory"))
}
