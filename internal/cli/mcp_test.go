package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// newEchoMCPHandler builds a Streamable HTTP handler for a trivial MCP
// server exposing a single "echo" tool, standing in for
// server/internal/mcpserver in these tests (which only care that the
// proxy forwards JSON-RPC messages and the Authorization header
// correctly, not about any real tool's behavior).
func newEchoMCPHandler() *mcp.StreamableHTTPHandler {
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		s := mcp.NewServer(&mcp.Implementation{Name: "stub", Version: "0.0.1"}, nil)
		s.AddTool(&mcp.Tool{
			Name:        "echo",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"text":{"type":"string"}}}`),
		}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var args struct{ Text string }
			if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
				return nil, err
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: args.Text}}}, nil
		})
		return s
	}, nil)
}

// mcpProxyTestTimeout bounds every round trip driven through the proxy in
// this file's tests.
const mcpProxyTestTimeout = 10 * time.Second

// startProxyAndClient wires runMCPProxy's stdin/stdout to a fresh MCP SDK
// client over an io.Pipe pair (mirroring what a real local MCP client
// process would do, minus the actual subprocess boundary -- see mcp.go's
// package doc comment on why mcp.IOTransport rather than
// mcp.StdioTransport makes this possible), starts the proxy in a
// background goroutine, and returns the connected client session plus a
// cleanup func that closes the session, waits for the proxy goroutine to
// return, and fails the test if it returned a non-nil error.
func startProxyAndClient(t *testing.T, ctx context.Context, client *Client) *mcp.ClientSession {
	t.Helper()

	proxyStdinR, proxyStdinW := io.Pipe()
	proxyStdoutR, proxyStdoutW := io.Pipe()

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- runMCPProxy(ctx, client, proxyStdinR, proxyStdoutW)
	}()

	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	cs, err := mcpClient.Connect(ctx, &mcp.IOTransport{Reader: proxyStdoutR, Writer: proxyStdinW}, nil)
	if err != nil {
		t.Fatalf("connect through proxy: %v", err)
	}

	t.Cleanup(func() {
		_ = cs.Close()
		select {
		case err := <-proxyErr:
			if err != nil {
				t.Errorf("runMCPProxy returned an error: %v", err)
			}
		case <-time.After(mcpProxyTestTimeout):
			t.Error("timed out waiting for runMCPProxy to exit after client Close")
		}
	})
	return cs
}

// TestRunMCPProxyRoundTrip drives initialize (implicit in Connect) +
// tools/list + tools/call through the proxy's stdio and asserts the
// responses come back correctly and that every request the stub /mcp
// server saw carried the minted access token as its Authorization header.
func TestRunMCPProxyRoundTrip(t *testing.T) {
	echoHandler := newEchoMCPHandler()

	// authHeaders is appended to from the httptest server's handler
	// goroutine(s): after initialize, the client also opens a concurrent
	// standalone SSE GET alongside its POST calls, so a mutex guards every
	// access (the race detector would otherwise flag this intermittently).
	var mu sync.Mutex
	var authHeaders []string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		mu.Unlock()
		echoHandler.ServeHTTP(w, r)
	})
	defer srv.Close()

	client := NewClient(Config{Server: srv.URL, Credential: "fbxc_test"})

	// t.Cleanup(cancel) is registered before startProxyAndClient's own
	// cleanup, so it runs AFTER it (t.Cleanup is last-added-first-called):
	// the client session must be closed and the proxy goroutine given a
	// chance to exit on a clean io.EOF/ErrConnectionClosed before ctx is
	// cancelled out from under it.
	ctx, cancel := context.WithTimeout(context.Background(), mcpProxyTestTimeout)
	t.Cleanup(cancel)

	cs := startProxyAndClient(t, ctx, client)

	toolsResult, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(toolsResult.Tools) != 1 || toolsResult.Tools[0].Name != "echo" {
		t.Fatalf("ListTools = %+v, want a single \"echo\" tool", toolsResult.Tools)
	}

	callResult, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "echo",
		Arguments: map[string]any{"text": "hello proxy"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	text, ok := callResult.Content[0].(*mcp.TextContent)
	if !ok || text.Text != "hello proxy" {
		t.Fatalf("CallTool result = %+v, want text content %q", callResult.Content, "hello proxy")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(authHeaders) == 0 {
		t.Fatal("no request reached the stub /mcp server")
	}
	for _, h := range authHeaders {
		if h != "Bearer fbxa_test-access-token" {
			t.Errorf("Authorization header = %q, want the minted access token", h)
		}
	}
}

// TestRunMCPProxyReMintsOnceAfter401 makes the stub /mcp server reject the
// very first request with 401 (simulating a token that the server no
// longer accepts, e.g. revoked between mint and use) and accept every
// request after that. It asserts the proxy recovers transparently -- the
// initial request's caller still gets a correct result -- and that a
// second, distinct access token was minted and used for the retry.
func TestRunMCPProxyReMintsOnceAfter401(t *testing.T) {
	echoHandler := newEchoMCPHandler()

	var mintCount atomic.Int32
	var mcpRequestCount atomic.Int32

	// authHeaders is appended to from the httptest server's handler
	// goroutine(s); a mutex guards every access (see the identical comment
	// in TestRunMCPProxyRoundTrip).
	var mu sync.Mutex
	var authHeaders []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/cli/access-token" && r.Method == http.MethodPost:
			n := mintCount.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "fbxa_test-access-token-" + strconv.Itoa(int(n)),
				"expires_at":   time.Now().Add(time.Hour).Format(time.RFC3339),
			})
		case r.URL.Path == "/mcp":
			mu.Lock()
			authHeaders = append(authHeaders, r.Header.Get("Authorization"))
			mu.Unlock()
			if mcpRequestCount.Add(1) == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			echoHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := NewClient(Config{Server: srv.URL, Credential: "fbxc_test"})

	// t.Cleanup(cancel) is registered before startProxyAndClient's own
	// cleanup, so it runs AFTER it (t.Cleanup is last-added-first-called):
	// the client session must be closed and the proxy goroutine given a
	// chance to exit on a clean io.EOF/ErrConnectionClosed before ctx is
	// cancelled out from under it.
	ctx, cancel := context.WithTimeout(context.Background(), mcpProxyTestTimeout)
	t.Cleanup(cancel)

	cs := startProxyAndClient(t, ctx, client)

	toolsResult, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(toolsResult.Tools) != 1 || toolsResult.Tools[0].Name != "echo" {
		t.Fatalf("ListTools = %+v, want a single \"echo\" tool", toolsResult.Tools)
	}

	if mintCount.Load() < 2 {
		t.Fatalf("access token was minted %d time(s), want at least 2 (initial + re-mint after 401)", mintCount.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(authHeaders) < 2 {
		t.Fatalf("only %d request(s) reached /mcp, want at least 2 (rejected + retried)", len(authHeaders))
	}
	if authHeaders[0] == authHeaders[1] {
		t.Fatalf("retry after 401 reused the same Authorization header %q, want a freshly minted token", authHeaders[0])
	}
}

// TestRunMCPNotLoggedIn asserts `funcbox mcp` fails with the same
// actionable "run funcbox login" style error as every other subcommand
// when no server/credential is configured, without ever touching the
// network.
func TestRunMCPNotLoggedIn(t *testing.T) {
	withXDGConfigHome(t)
	t.Setenv("FUNCBOX_SERVER", "")
	t.Setenv("FUNCBOX_CREDENTIAL", "")

	stdinR, stdinW := io.Pipe()
	defer stdinW.Close()
	stdoutR, stdoutW := io.Pipe()
	defer stdoutR.Close()

	err := RunMCP(nil, stdinR, stdoutW, io.Discard)
	if err == nil {
		t.Fatal("RunMCP returned nil error when not logged in")
	}
	if got := err.Error(); got == "" {
		t.Fatal("RunMCP returned an empty error message")
	} else if !strings.Contains(got, "funcbox login") {
		t.Fatalf("RunMCP error = %q, want it to mention `funcbox login`", got)
	}
}
