// bounded_test.go unit-tests boundedInvokeRecorder (see tools_functions.go)
// in isolation: the Finding-3 fix for invoke_function buffering an entire
// guest response before applying its cap. These are white-box (package
// mcpserver) tests specifically because boundedInvokeRecorder is
// unexported -- e2e_mcp_test.go's own
// TestE2E_MCPInvokeFunctionAuthzAndCap/"response body is capped and
// flagged truncated" subtest covers the same fix through the full MCP+HTTP
// pipeline; these tests instead pin the recorder's own byte-accounting
// contract directly, including that it never retains more than cap bytes
// regardless of how much is written to it.
package mcpserver

import (
	"net/http"
	"strings"
	"testing"
)

// TestBoundedInvokeRecorderTruncatesAndCountsFully writes far more than cap
// bytes and checks: (1) every Write call is reported as fully accepted
// (mirrors http.ResponseWriter's own contract), (2) the retained body is
// EXACTLY cap bytes, never more, (3) total tracks everything written, even
// past cap, and (4) truncated() reports true once total exceeds cap.
func TestBoundedInvokeRecorderTruncatesAndCountsFully(t *testing.T) {
	const cap = 1024
	rec := newBoundedInvokeRecorder(cap)
	rec.WriteHeader(http.StatusCreated)

	chunk := strings.Repeat("a", 4096)
	const writes = 10 // 10 * 4096 = 40960 bytes, far more than cap
	for i := 0; i < writes; i++ {
		n, err := rec.Write([]byte(chunk))
		if err != nil {
			t.Fatalf("Write #%d: unexpected error %v", i, err)
		}
		if n != len(chunk) {
			t.Fatalf("Write #%d returned n=%d, want %d -- a bounded recorder must never short-report to its caller", i, n, len(chunk))
		}
	}

	if got := rec.body.Len(); got != cap {
		t.Fatalf("body.Len() = %d, want exactly %d (the cap) -- this recorder must never buffer more than cap bytes, however much the guest writes", got, cap)
	}
	if got, want := rec.total, writes*len(chunk); got != want {
		t.Fatalf("total = %d, want %d (every written byte counted, even past cap)", got, want)
	}
	if !rec.truncated() {
		t.Fatalf("truncated() = false, want true (total %d > cap %d)", rec.total, cap)
	}
	if rec.status != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.status, http.StatusCreated)
	}
}

// TestBoundedInvokeRecorderUnderCapNotTruncated is the complementary case:
// a body strictly under cap is retained in full and NOT flagged truncated,
// and an implicit (never explicitly called) WriteHeader defaults to 200,
// matching both net/http's own ResponseWriter contract and the previous
// httptest.NewRecorder-based implementation's default.
func TestBoundedInvokeRecorderUnderCapNotTruncated(t *testing.T) {
	rec := newBoundedInvokeRecorder(1024)
	const want = "hello, world"
	n, err := rec.Write([]byte(want))
	if err != nil {
		t.Fatalf("Write: unexpected error %v", err)
	}
	if n != len(want) {
		t.Fatalf("Write returned n=%d, want %d", n, len(want))
	}
	if got := rec.body.String(); got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
	if rec.truncated() {
		t.Fatalf("truncated() = true, want false for a body under cap")
	}
	if rec.status != http.StatusOK {
		t.Fatalf("default status = %d, want %d (implicit 200, no WriteHeader call)", rec.status, http.StatusOK)
	}
}

// TestBoundedInvokeRecorderExactCapNotTruncated is the boundary case:
// writing EXACTLY cap bytes must retain all of them and NOT be flagged
// truncated -- truncated must mean "the guest wrote more than we kept",
// not "we happened to fill the buffer".
func TestBoundedInvokeRecorderExactCapNotTruncated(t *testing.T) {
	const cap = 16
	rec := newBoundedInvokeRecorder(cap)
	if _, err := rec.Write([]byte(strings.Repeat("x", cap))); err != nil {
		t.Fatalf("Write: unexpected error %v", err)
	}
	if rec.body.Len() != cap {
		t.Fatalf("body.Len() = %d, want %d", rec.body.Len(), cap)
	}
	if rec.truncated() {
		t.Fatalf("truncated() = true, want false when the guest wrote EXACTLY cap bytes")
	}
}

// TestBoundedInvokeRecorderHeaderIndependentOfBody confirms Header() is a
// normal, independently usable http.Header (invokeFunctionHandler reads
// Content-Type off it) unaffected by the body cap.
func TestBoundedInvokeRecorderHeaderIndependentOfBody(t *testing.T) {
	rec := newBoundedInvokeRecorder(4)
	rec.Header().Set("Content-Type", "application/json")
	if _, err := rec.Write([]byte("way more than four bytes")); err != nil {
		t.Fatalf("Write: unexpected error %v", err)
	}
	if got := rec.header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type header = %q, want %q", got, "application/json")
	}
}
