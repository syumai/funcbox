package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/syumai/funcbox/server/internal/api"
	"github.com/syumai/funcbox/server/internal/auth"
	"github.com/syumai/funcbox/server/internal/blob"
	"github.com/syumai/funcbox/server/internal/invoke"
	"github.com/syumai/funcbox/server/internal/settings"
	"github.com/syumai/funcbox/server/internal/store"
)

// serverVersion is this MCP server implementation's own version string,
// reported in the "initialize" response's serverInfo -- not funcbox's own
// release version (funcbox has none yet; see server/go.mod's own
// placeholder-version comment), just a marker for this protocol surface.
const serverVersion = "0.1.0"

// Config is Handler's configuration.
type Config struct {
	// ControlOrigin is the exact scheme+authority this server is reachable
	// at, used to build the 401 response's WWW-Authenticate
	// resource_metadata URL (RFC 9728 §5.1) -- must match
	// server/internal/oauth's own Config.ControlOrigin exactly, since both
	// packages advertise the SAME protected-resource / authorization-server
	// pairing. No trailing slash. Required.
	ControlOrigin string
}

// Handler serves the Streamable HTTP /mcp endpoint. Build one with New and
// mount it directly (it implements http.Handler) -- this package does not
// mount itself onto any router, and does not itself gate on mcp_enabled
// (see Enabled and this package's doc comment).
type Handler struct {
	cfg     Config
	store   store.Store
	auth    *auth.Auth
	api     *api.Handler
	invoker *invoke.Invoker
	blob    blob.Store

	sdk *mcp.StreamableHTTPHandler
}

// New builds a Handler. st/a/apiHandler must be non-nil -- apiHandler is
// the SAME *api.Handler the /api/v1 REST API is built from (one instance,
// server-wide), so this package's tool handlers reuse its exported
// use-case methods (e.g. PatchUser) rather than duplicating them. invoker
// is the SAME *invoke.Invoker the real /{owner}/{name} HTTP invocation
// path is built from (server/internal/server's Deps.Invoker) -- the
// functions tool group's invoke_function tool dispatches through it
// in-process (see tools_functions.go's invokeFunctionHandler), so a
// function invoked via MCP goes through the exact same visibility
// authorization, caller-identity header injection, execution logging, and
// metrics as a normal HTTP invocation. blobStore is the SAME blob.Store
// backing service.Deployer.Blob -- get_function_files reads a version's
// canonical bundle directly from it (service.BundleBlobKey) and unpacks it
// with bundle.Unpack, the identical safe streaming unpacker Deploy itself
// uses. invoker/blobStore may be nil (e.g. a caller with no runtime/blob
// configured, such as some tests), in which case invoke_function /
// get_function_files are simply never registered (see
// registerFunctionsTools).
func New(cfg Config, st store.Store, a *auth.Auth, apiHandler *api.Handler, invoker *invoke.Invoker, blobStore blob.Store) (*Handler, error) {
	if cfg.ControlOrigin == "" {
		return nil, fmt.Errorf("mcpserver: Config.ControlOrigin is required")
	}
	cfg.ControlOrigin = strings.TrimSuffix(cfg.ControlOrigin, "/")

	h := &Handler{cfg: cfg, store: st, auth: a, api: apiHandler, invoker: invoker, blob: blobStore}
	h.sdk = mcp.NewStreamableHTTPHandler(h.getServer, nil)
	return h, nil
}

// ServeHTTP authenticates the request with funcbox's own access-token
// verification -- NEVER a session cookie, per this package's doc comment
// -- attaches the resolved actor to the request context (mirroring
// internal/auth.Auth.Middleware's shape, so getServer below can read it
// exactly like an /api/v1 handler reads its own actor), and only then
// hands the request to the SDK's own Streamable HTTP handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	act, err := h.authenticate(r)
	if err != nil {
		h.write401(w)
		return
	}
	h.sdk.ServeHTTP(w, r.WithContext(auth.WithActor(r.Context(), act)))
}

// authenticate resolves r's actor from "Authorization: Bearer fbxa_..."
// alone: an access token with an empty aud claim (a general-purpose token,
// e.g. from `funcbox print-access-token`) or aud=="mcp" (minted by
// server/internal/oauth's /oauth/token) are BOTH accepted here -- the
// widest acceptance rule of any credential-checking path in funcbox, since
// /mcp is the ONE endpoint both audiences share (see auth.AudienceMCP's
// doc comment). Any other aud, a malformed/expired/unknown token, a
// missing Authorization header, or a disabled/no-longer-permitted user are
// all rejected identically (auth.ErrUnauthenticated), matching this
// package's general refusal to let a caller fingerprint *why* a credential
// failed. A pending (awaiting approval) user is rejected too -- mirroring
// internal/api's requirePendingApproved middleware, since every MCP tool
// group so far is admin-only or otherwise privileged, and a pending user
// has no legitimate use for any of them.
func (h *Handler) authenticate(r *http.Request) (*auth.Actor, error) {
	hdr := r.Header.Get("Authorization")
	raw, ok := strings.CutPrefix(hdr, "Bearer ")
	if !ok || !strings.HasPrefix(raw, auth.AccessTokenPrefix) {
		return nil, auth.ErrUnauthenticated
	}
	aud, ok := h.auth.AccessTokenAudience(raw)
	if !ok || (aud != "" && aud != auth.AudienceMCP) {
		return nil, auth.ErrUnauthenticated
	}
	act, err := h.auth.AuthenticateAccessToken(r.Context(), raw)
	if err != nil {
		return nil, err
	}
	if act.User.Status == store.UserStatusPending {
		return nil, auth.ErrUnauthenticated
	}
	return act, nil
}

// write401 writes the 401 response an unauthenticated/rejected /mcp
// request gets: WWW-Authenticate names this deployment's RFC 9728
// protected-resource metadata document, in the exact
// `Bearer resource_metadata="..."` shape MCP clients auto-discover the
// OAuth flow from (RFC 9728 §5.1) -- see server/internal/oauth's
// handleProtectedResourceMetadata, which serves that document from the
// same ControlOrigin this package is configured with.
func (h *Handler) write401(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, h.cfg.ControlOrigin))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": "unauthorized", "message": "authentication required"},
	})
}

// getServer is passed to mcp.NewStreamableHTTPHandler as its getServer
// hook: the SDK calls this exactly once per new MCP session, on the
// request that carries no Mcp-Session-Id header yet (normally the
// "initialize" call) -- see the go-sdk's StreamableHTTPHandler.
// serveStatefulPOST. Every later request against that SAME session reuses
// the mcp.Server this returns without calling getServer again, so the tool
// set (and therefore tools/list) registered here for actor's role is fixed
// for the session's whole lifetime; a mid-session role change or token
// revocation takes effect on the actor's NEXT new session, not the current
// one -- an accepted tradeoff given this package's short-lived (<=1h)
// access tokens.
func (h *Handler) getServer(r *http.Request) *mcp.Server {
	act := auth.ActorFromContext(r.Context())
	if act == nil {
		// ServeHTTP's own authenticate call rejects every unauthenticated
		// request with 401 before the SDK handler (and therefore this
		// function) is ever reached -- this should be unreachable in
		// practice, but returning nil (rather than panicking) makes the SDK
		// itself respond 400 Bad Request, per NewStreamableHTTPHandler's own
		// doc comment, instead of crashing the process.
		return nil
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "funcbox", Version: serverVersion}, nil)
	h.registerTools(server, act.User)
	return server
}

// registerTools adds every tool group u's role may call to server -- the
// mechanism behind role-filtered tools/list (see this package's doc
// comment): a tool never registered for this session is simply absent
// from tools/list, and (per this package's design) every tool handler
// ALSO independently re-checks u's authorization before touching any
// state, so a client that calls an unlisted tool by name anyway (a
// malicious or simply out-of-sync client) still gets a clean refusal
// rather than ever reaching the underlying use case.
func (h *Handler) registerTools(server *mcp.Server, u *store.User) {
	h.registerUsersTools(server, u)
	h.registerFunctionsTools(server, u)
	h.registerWorkspacesTools(server, u)
	h.registerOrgTools(server, u)
	h.registerAuditTools(server, u)
	h.registerDevicesTools(server, u)
}

// Enabled reports the organization's current mcp_enabled setting (default
// true; see settings.Org.McpEnabled's own doc comment), failing closed
// (false) if the organization or its settings can't be loaded -- the
// shared gate server/internal/server's router consults, per request,
// before dispatching to /mcp or any of server/internal/oauth's endpoints
// (mirrors internal/api's openModeEnabled helper's fail-closed shape for
// the analogous open_mode gate).
func Enabled(ctx context.Context, st store.Store) bool {
	org, err := st.Organizations().Get(ctx)
	if err != nil {
		return false
	}
	orgSet, err := settings.ParseOrg(org.Settings)
	if err != nil {
		return false
	}
	return orgSet.McpEnabled
}
