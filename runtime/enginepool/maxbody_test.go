package enginepool

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// echoBodyLengthLoader is a minimal function that reads its whole request
// body and echoes back the byte count, for asserting a within-limit body
// reaches the guest intact.
var echoBodyLengthLoader = singleFileLoader(map[string]string{
	"index.js": `
		export default {
			async fetch(request) {
				const buf = await request.arrayBuffer();
				return new Response(String(buf.byteLength));
			},
		};
	`,
})

// TestMaxRequestBody covers Config.MaxRequestBody (Finding 2): a request
// body at or under the configured cap reaches the guest handler intact, and
// one over the cap is rejected with 413 rather than being buffered in full
// -- both for an explicit Config.MaxRequestBody and for the zero-value
// default (DefaultMaxRequestBody).
func TestMaxRequestBody(t *testing.T) {
	t.Run("explicit limit", func(t *testing.T) {
		const limit = 1024
		pool, err := NewPool(Config{Size: 1, Entry: "index.js", Loader: echoBodyLengthLoader, MaxRequestBody: limit})
		if err != nil {
			t.Fatalf("NewPool: %v", err)
		}
		t.Cleanup(func() { pool.Close() })
		srv := httptest.NewServer(pool)
		t.Cleanup(srv.Close)

		t.Run("within limit", func(t *testing.T) {
			body := bytes.Repeat([]byte("a"), limit-1)
			resp, err := http.Post(srv.URL+"/", "application/octet-stream", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			defer resp.Body.Close()
			got, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, body = %q, want 200", resp.StatusCode, got)
			}
			if string(got) != "1023" {
				t.Fatalf("body = %q, want %q", got, "1023")
			}
		})

		t.Run("over limit", func(t *testing.T) {
			body := bytes.Repeat([]byte("a"), limit*2)
			resp, err := http.Post(srv.URL+"/", "application/octet-stream", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want 413", resp.StatusCode)
			}
		})
	})

	t.Run("zero value falls back to DefaultMaxRequestBody", func(t *testing.T) {
		pool, err := NewPool(Config{Size: 1, Entry: "index.js", Loader: echoBodyLengthLoader})
		if err != nil {
			t.Fatalf("NewPool: %v", err)
		}
		t.Cleanup(func() { pool.Close() })
		srv := httptest.NewServer(pool)
		t.Cleanup(srv.Close)

		body := bytes.Repeat([]byte("a"), DefaultMaxRequestBody+1)
		resp, err := http.Post(srv.URL+"/", "application/octet-stream", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413 (a body over DefaultMaxRequestBody must still be rejected with no explicit Config.MaxRequestBody)", resp.StatusCode)
		}
	})
}
