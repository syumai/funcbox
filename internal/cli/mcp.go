// mcp.go implements `funcbox mcp`: a stdio<->Streamable HTTP proxy so a
// local MCP client configured with
//
//	{ "command": "funcbox", "args": ["mcp"] }
//
// can reach a funcbox-server's /mcp endpoint (server/internal/mcpserver)
// using the credential `funcbox login` already saved, without going
// through a browser-based OAuth flow -- a supplementary connection path
// (§16.3 of the design doc; remote clients are expected to use the OAuth
// flow directly against /mcp instead).
//
// # Bridge design
//
// The proxy is a raw JSON-RPC message pump, not a paired mcp.Client +
// mcp.Server. Two [mcp.Transport]s are connected -- [mcp.IOTransport] on
// the local (stdio) side, [mcp.StreamableClientTransport] on the remote
// side -- and every [jsonrpc.Message] read from one [mcp.Connection] is
// written verbatim to the other (see pump below). Nothing is decoded into
// typed request/response structs, no tool list is cached or mirrored, and
// no method is individually re-implemented. This keeps the proxy
// completely protocol-transparent: any tool, capability, or MCP method
// server/internal/mcpserver adds later passes through unchanged, with zero
// code changes here.
//
// The alternative -- an mcp.Client talking to the remote plus an
// mcp.Server on stdio that lists the remote's tools on "initialize" and
// forwards tools/call by name -- was considered and rejected: it would
// still need to separately hand-relay every other method a real MCP
// session can carry (resources, prompts, completion, logging level,
// progress notifications, cancellation, ...) since the SDK's typed
// Client/Server pair doesn't expose a generic "forward anything" hook, all
// for no benefit over just forwarding the wire messages directly.
//
// [mcp.IOTransport] (not [mcp.StdioTransport]) is used on the local side:
// both use identical newline-delimited-JSON wire behavior over a
// io.ReadWriteCloser, but StdioTransport hardcodes os.Stdin/os.Stdout,
// making it impossible to drive from a test without a real subprocess.
// IOTransport takes an explicit io.ReadCloser/io.WriteCloser pair instead
// -- cmd/funcbox/main.go passes os.Stdin/os.Stdout for real use, and this
// package's tests pass an io.Pipe.
//
// # Authorization
//
// The remote http.Client's RoundTripper (authRoundTripper) mints an
// access token from the saved CLI credential -- reusing Client's existing
// cache (ensureAccessToken, the same mechanism deploy/list/logs/... use)
// -- and attaches it as "Authorization: Bearer ..." to every outgoing
// request. Since the Streamable HTTP transport issues one HTTP request per
// outgoing JSON-RPC message (plus one long-lived GET for the standalone
// SSE stream), this transparently keeps a long-running proxy process
// working across the access token's ~15 minute lifetime: each request
// re-checks the cache and only mints fresh when the cached token is close
// to expiring. A 401 response additionally forces one immediate re-mint
// (bypassing the cache, in case the token was revoked or expired sooner
// than expected) and retries that one request; a second 401 is reported as
// a clear "authentication failed after re-minting an access token" error
// rather than retried again.
//
// # stdout discipline
//
// stdout is exclusively the proxied MCP stdio channel -- nothing else is
// ever written there. Every diagnostic (connection failures, the 401
// re-mint's own failure, "not logged in", ...) goes to stderr.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// mcpEndpointPath is the path Streamable HTTP is mounted at on every
// funcbox-server (server/internal/mcpserver.Config's doc comment: "/mcp",
// control origin, no trailing slash).
const mcpEndpointPath = "/mcp"

// RunMCP implements `funcbox mcp`. stdin/stdout carry the local MCP stdio
// session verbatim (see this file's package doc comment); stderr is the
// only place diagnostics are written.
func RunMCP(args []string, stdin io.ReadCloser, stdout io.WriteCloser, stderr io.Writer) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if _, err := parseFlagsInterspersed(fs, args); err != nil {
		return err
	}

	cfg, err := RequireConfig()
	if err != nil {
		return err
	}
	client := NewClient(cfg)

	return runMCPProxy(context.Background(), client, stdin, stdout)
}

// runMCPProxy connects both transports and pumps messages between them
// until either side ends the session or a fatal error occurs. It is
// separated from RunMCP so tests can supply a *Client pointed at an
// httptest server instead of going through RequireConfig/flag parsing.
func runMCPProxy(ctx context.Context, client *Client, stdin io.ReadCloser, stdout io.WriteCloser) error {
	local := &mcp.IOTransport{Reader: stdin, Writer: stdout}
	remote := &mcp.StreamableClientTransport{
		Endpoint: client.Server + mcpEndpointPath,
		HTTPClient: &http.Client{
			// No timeout: the Streamable HTTP transport holds a long-lived GET
			// (the standalone SSE stream) open for the whole session, which a
			// fixed client-wide timeout would kill.
			Transport: &authRoundTripper{client: client, base: http.DefaultTransport},
		},
	}

	localConn, err := local.Connect(ctx)
	if err != nil {
		return fmt.Errorf("mcp: connect local stdio transport: %w", err)
	}
	remoteConn, err := remote.Connect(ctx)
	if err != nil {
		_ = localConn.Close()
		return fmt.Errorf("mcp: connect to %s: %w", remote.Endpoint, err)
	}

	return pump(ctx, localConn, remoteConn)
}

// pump forwards every JSON-RPC message read from either connection
// verbatim to the other, until one side's Read fails -- then it closes
// both connections and returns. A clean end of session (io.EOF, e.g. the
// local client closed stdin, or ErrConnectionClosed from an explicit
// Close on either side) is not reported as an error; anything else is.
func pump(ctx context.Context, a, b mcp.Connection) error {
	errCh := make(chan error, 2)
	forward := func(from, to mcp.Connection) {
		for {
			msg, err := from.Read(ctx)
			if err != nil {
				errCh <- err
				return
			}
			if err := to.Write(ctx, msg); err != nil {
				errCh <- err
				return
			}
		}
	}
	go forward(a, b)
	go forward(b, a)

	err := <-errCh
	_ = a.Close()
	_ = b.Close()
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, mcp.ErrConnectionClosed) {
		return fmt.Errorf("mcp: proxy stopped: %w", err)
	}
	return nil
}

// authRoundTripper attaches "Authorization: Bearer <access token>" to
// every outgoing request, minting (or reusing a cached) access token from
// client's saved CLI credential. See this file's package doc comment for
// the 401 re-mint-and-retry behavior.
type authRoundTripper struct {
	client *Client
	base   http.RoundTripper
}

func (t *authRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.client.ensureAccessToken(req.Context())
	if err != nil {
		return nil, err
	}
	resp, err := t.roundTripWithToken(req, token)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}

	// One re-mint, bypassing the cache (the cached token may have been
	// revoked, or simply have expired sooner server-side than our own
	// refresh margin assumed), and one retry of this same request.
	_ = resp.Body.Close()
	t.client.mu.Lock()
	t.client.accessToken = ""
	t.client.mu.Unlock()
	token, err = t.client.ensureAccessToken(req.Context())
	if err != nil {
		return nil, fmt.Errorf("mcp: re-mint access token after 401: %w", err)
	}
	resp, err = t.roundTripWithToken(req, token)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("mcp: authentication failed after re-minting an access token (server returned 401 again for %s)", req.URL.Path)
	}
	return resp, nil
}

// roundTripWithToken sends a clone of req (http.RoundTripper's contract
// forbids mutating or reusing the original request across calls) carrying
// the given bearer token, rewinding the body via req.GetBody when present
// so the same logical request can be retried after a 401. The Streamable
// HTTP transport always builds its POST bodies from bytes.Reader
// (streamableClientConn.Write), which makes net/http populate GetBody
// automatically (http.NewRequestWithContext); GET/DELETE requests carry no
// body and therefore no GetBody, which is fine since there is nothing to
// rewind.
func (t *authRoundTripper) roundTripWithToken(req *http.Request, token string) (*http.Response, error) {
	clone := req.Clone(req.Context())
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, fmt.Errorf("mcp: rewind request body for retry: %w", err)
		}
		clone.Body = body
	}
	clone.Header.Set("Authorization", "Bearer "+token)
	return t.base.RoundTrip(clone)
}
