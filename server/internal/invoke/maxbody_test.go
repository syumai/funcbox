package invoke

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// echoBodyLengthFiles deploys a public function that reads its whole
// request body and echoes back the byte count -- enough to prove a
// within-limit body reaches the guest intact.
var echoBodyLengthFiles = map[string][]byte{
	"funcbox.yaml": []byte("name: maxbodytest\n"),
	"index.js": []byte(`
		export default {
			async fetch(req) {
				const buf = await req.arrayBuffer();
				return new Response(String(buf.byteLength));
			},
		};
	`),
}

// TestInvokerMaxRequestBody covers the request-body size limit end to end
// (Finding 2): FUNCBOX_MAX_REQUEST_BYTES is set to a small value so the
// tests run fast, then a within-limit request, a Content-Length-declared
// over-limit request, and a Content-Length-less (chunked-shaped) over-limit
// request are each exercised against the same deployed function.
func TestInvokerMaxRequestBody(t *testing.T) {
	const limit = 4096
	t.Setenv(maxRequestBytesEnvVar, strconv.Itoa(limit))

	inv := newTestInvoker(t, "ivan", "maxbodytest", echoBodyLengthFiles, 5*time.Second)

	t.Run("within limit reaches the guest", func(t *testing.T) {
		body := bytes.Repeat([]byte("a"), limit-1)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/ivan/maxbodytest", bytes.NewReader(body))
		inv.Serve(w, r, "ivan", "maxbodytest")

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %q, want 200", w.Code, w.Body.String())
		}
		if w.Body.String() != strconv.Itoa(len(body)) {
			t.Fatalf("body = %q, want %q (guest must see the full within-limit body)", w.Body.String(), strconv.Itoa(len(body)))
		}
	})

	t.Run("over limit with a declared Content-Length is rejected before dispatch", func(t *testing.T) {
		body := bytes.Repeat([]byte("a"), limit*2)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/ivan/maxbodytest", bytes.NewReader(body))
		if r.ContentLength != int64(len(body)) {
			t.Fatalf("test setup: ContentLength = %d, want %d (declared)", r.ContentLength, len(body))
		}
		inv.Serve(w, r, "ivan", "maxbodytest")

		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, body = %q, want 413", w.Code, w.Body.String())
		}
	})

	t.Run("over limit with no declared Content-Length fails cleanly, not with a hang or OOM", func(t *testing.T) {
		body := bytes.Repeat([]byte("a"), limit*4)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/ivan/maxbodytest", bytes.NewReader(body))
		// Simulate a chunked/unknown-length request: the Content-Length
		// pre-check in serveFunction can't reject this up front (it isn't
		// "> limit" -- it's unknown), so this exercises the worker's own
		// http.MaxBytesReader cap on the actual read instead (see
		// runtime/enginepool/worker.go's serve). The request completing at
		// all (rather than the test timing out) demonstrates the read is
		// bounded rather than buffering the whole oversized body.
		r.ContentLength = -1
		inv.Serve(w, r, "ivan", "maxbodytest")

		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, body = %q, want 413", w.Code, w.Body.String())
		}
	})
}
