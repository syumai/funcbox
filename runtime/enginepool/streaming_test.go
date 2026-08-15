package enginepool

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// firstByteAndTotal GETs url and reports the time-to-first-byte, the total
// time until EOF, and the full body. Ported from runtime/streaming_test.go.
func firstByteAndTotal(t *testing.T, url string) (ttfb, total time.Duration, body string) {
	t.Helper()
	start := time.Now()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	var all []byte
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if ttfb == 0 {
				ttfb = time.Since(start)
			}
			all = append(all, buf[:n]...)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			t.Fatalf("reading body: %v", rerr)
		}
	}
	return ttfb, time.Since(start), string(all)
}

// TestStreamingResponseDeliversIncrementally is checklist item 8: a guest
// Response wrapping a ReadableStream must reach the client chunk-by-chunk,
// not buffered as a whole.
func TestStreamingResponseDeliversIncrementally(t *testing.T) {
	loader := singleFileLoader(map[string]string{
		"index.js": `
			export default {
				async fetch(req) {
					const stream = new ReadableStream({
						start(c) {
							c.enqueue(new TextEncoder().encode("first-chunk;"));
							setTimeout(() => {
								c.enqueue(new TextEncoder().encode("second-chunk;"));
								c.close();
							}, 300);
						},
					});
					return new Response(stream, { headers: { "content-type": "text/plain" } });
				},
			};
		`,
	})
	pool, err := NewPool(Config{Size: 1, Entry: "index.js", Loader: loader})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	srv := httptest.NewServer(pool)
	t.Cleanup(srv.Close)

	ttfb, total, body := firstByteAndTotal(t, srv.URL+"/")
	if body != "first-chunk;second-chunk;" {
		t.Fatalf("body = %q, want first-chunk;second-chunk;", body)
	}
	if total < 300*time.Millisecond {
		t.Fatalf("total = %v; the stream's 300ms gap between chunks should dominate", total)
	}
	if ttfb >= 200*time.Millisecond {
		t.Errorf("TTFB = %v (total %v); the first chunk must arrive well before the stream completes", ttfb, total)
	}
	t.Logf("streaming response: ttfb=%v total=%v", ttfb, total)
}
