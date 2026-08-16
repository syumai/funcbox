package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
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

// mcpSessionIdleTimeout bounds how long an MCP session may sit idle (no
// requests at all, per go-sdk's own StreamableHTTPOptions.SessionTimeout
// semantics) before the SDK's Streamable HTTP transport auto-closes it.
// Previously New passed nil options, which per that field's own doc
// comment ("If SessionTimeout is the zero value, idle sessions are never
// closed") meant sessions -- and this package's own session->server
// bookkeeping in h.sessions -- accumulated without bound until an explicit
// DELETE or process restart. 10 minutes comfortably outlives a normal
// think-then-call AI agent loop while still bounding worst-case idle
// memory.
const mcpSessionIdleTimeout = 10 * time.Minute

// mcpMaxSessionsPerUser and mcpMaxSessionsGlobal cap concurrent MCP
// sessions, enforced in getServer (the SDK's own new-session hook -- see
// its doc comment). Without a cap, a single compromised/buggy client (or
// simply many distinct users) could grow both the SDK's own internal
// session map and h.sessions without bound, alongside mcpSessionIdleTimeout
// bounding how long any one of them can live.
//
// Each value is roughly double the number of genuinely concurrent sessions
// this package actually intends to allow (5 and 200, respectively) to
// absorb a real quirk of the go-sdk client (as of the pinned v1.7.0):
// mcp.NewClient(...).Connect, by default, first tries the newer
// "server/discover" RPC (SEP-2575) before falling back to the legacy
// "initialize" handshake whenever it's talking to a server that isn't
// running in [mcp.StreamableHTTPOptions.Stateless] mode (this package
// deliberately is NOT stateless -- Finding 1's session/user binding
// requires real, addressable sessions). That fallback opens a SECOND,
// brand-new HTTP connection/session rather than reusing the first: the
// server DOES fully create and track a session for the discover call (see
// mcp.Server.discover, which sets state.InitializeParams same as a real
// initialize would), but never returns its Mcp-Session-Id to the client
// (StreamableServerTransport only sets that response header for an actual
// "initialize" call), leaving that first session permanently unreachable
// by the client -- until mcpSessionIdleTimeout eventually reaps it. So one
// logical client connection can cost this package up to TWO tracked
// sessions. This is a rough edge in how SEP-2575 discovery interacts with
// non-stateless Streamable HTTP servers in this SDK version, not a bug in
// this package; doubling the caps keeps them a real, bounded ceiling
// without being tripped by ordinary well-behaved clients using the
// reference go-sdk.
const (
	mcpMaxSessionsPerUser = 10
	mcpMaxSessionsGlobal  = 400
)

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
	// bound wraps sdk with the go-sdk's own auth.RequireBearerToken
	// middleware, translating this package's already-verified per-request
	// actor (attached to the request context by ServeHTTP below) into the
	// go-sdk's own auth.TokenInfo -- see New's doc comment on why this is
	// the "cleaner hook" Finding 1's session/user binding uses instead of a
	// hand-rolled map: the go-sdk's StreamableHTTPHandler ALREADY refuses
	// (403) any request whose auth.TokenInfo.UserID doesn't match the
	// session's own recorded owner, once that owner is populated -- this
	// field is what populates it.
	bound http.Handler

	// sessMu guards sessions, this package's own bookkeeping of live MCP
	// sessions used ONLY to enforce mcpMaxSessionsPerUser/
	// mcpMaxSessionsGlobal in getServer -- NOT for session/user binding
	// (that's h.bound's job, via the SDK's own session map). See getServer
	// and pruneClosedSessionsLocked for how entries are added/removed.
	sessMu   sync.Mutex
	sessions map[*mcp.Server]string // tracked *mcp.Server -> the store.User.ID that owns its session
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

	h := &Handler{cfg: cfg, store: st, auth: a, api: apiHandler, invoker: invoker, blob: blobStore, sessions: make(map[*mcp.Server]string)}

	// Finding 2: pass a bounded SessionTimeout so idle sessions (and this
	// package's own h.sessions bookkeeping alongside them) don't
	// accumulate forever -- see mcpSessionIdleTimeout's own doc comment.
	h.sdk = mcp.NewStreamableHTTPHandler(h.getServer, &mcp.StreamableHTTPOptions{SessionTimeout: mcpSessionIdleTimeout})

	// Finding 1 (session/user binding layer): wrap h.sdk with the go-sdk's
	// own auth.RequireBearerToken middleware, whose ONLY job here is to
	// translate the actor ServeHTTP has already authenticated (attached to
	// the request context via auth.WithActor, read back out below) into an
	// sdkauth.TokenInfo carrying that actor's UserID. The verifier below
	// never independently fails in practice -- ServeHTTP has already
	// authenticated the request and refused it (401) before h.bound is
	// ever reached -- but returns sdkauth.ErrInvalidToken defensively if it
	// somehow is (mirrors getServer's own defensive nil-actor check).
	// AllowMissingExpiration is set because funcbox's own access tokens are
	// already independently expiry-checked by ServeHTTP's authenticate;
	// this middleware's ONLY purpose is carrying UserID, not re-deriving
	// funcbox's own expiry policy.
	verifier := func(ctx context.Context, _ string, _ *http.Request) (*sdkauth.TokenInfo, error) {
		act := auth.ActorFromContext(ctx)
		if act == nil {
			return nil, sdkauth.ErrInvalidToken
		}
		return &sdkauth.TokenInfo{UserID: act.User.ID}, nil
	}
	h.bound = sdkauth.RequireBearerToken(verifier, &sdkauth.RequireBearerTokenOptions{AllowMissingExpiration: true})(h.sdk)

	return h, nil
}

// ServeHTTP authenticates the request with funcbox's own access-token
// verification -- NEVER a session cookie, per this package's doc comment
// -- attaches the resolved actor to the request context (mirroring
// internal/auth.Auth.Middleware's shape, so getServer below can read it
// exactly like an /api/v1 handler reads its own actor), and only then
// hands the request to h.bound (the SDK's own Streamable HTTP handler,
// wrapped with session/user-binding middleware -- see New's doc comment).
// This runs on EVERY request against /mcp, not just "initialize": a
// Streamable HTTP session spans many independent HTTP requests sharing one
// Mcp-Session-Id, and each one is authenticated completely fresh here
// (funcbox's access tokens carry no server-side revocation state beyond
// the user's current row -- see auth.Auth.verifyAccessToken's own doc
// comment -- so this fresh-per-request check is what makes a role
// change/disable/revocation visible without waiting for a new session).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	act, err := h.authenticate(r)
	if err != nil {
		h.write401(w)
		return
	}
	h.bound.ServeHTTP(w, r.WithContext(auth.WithActor(r.Context(), act)))
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
	return h.authenticateHeader(r.Context(), r.Header.Get("Authorization"))
}

// authenticateHeader is authenticate's implementation, taking the raw
// "Authorization" header value directly (rather than a *http.Request) so
// actorFromRequest below can reuse it for a single tools/call's own
// per-call header (see mcp.RequestExtra.Header) instead of the HTTP
// request that originally established the MCP session.
func (h *Handler) authenticateHeader(ctx context.Context, hdr string) (*auth.Actor, error) {
	raw, ok := strings.CutPrefix(hdr, "Bearer ")
	if !ok || !strings.HasPrefix(raw, auth.AccessTokenPrefix) {
		return nil, auth.ErrUnauthenticated
	}
	aud, ok := h.auth.AccessTokenAudience(raw)
	if !ok || (aud != "" && aud != auth.AudienceMCP) {
		return nil, auth.ErrUnauthenticated
	}
	act, err := h.auth.AuthenticateAccessToken(ctx, raw)
	if err != nil {
		return nil, err
	}
	if act.User.Status == store.UserStatusPending {
		return nil, auth.ErrUnauthenticated
	}
	return act, nil
}

// actorFromRequest resolves the actor authenticated on THIS SPECIFIC
// tools/call -- from req.Extra.Header (the go-sdk's per-call
// mcp.RequestExtra, populated straight from the http.Request that carried
// this one JSON-RPC call; see mcp.CallToolRequest's definition as
// ServerRequest[*CallToolParamsRaw]) -- rather than from ctx or from the
// initialize-time actor registerTools closed over when building this tool's
// handler.
//
// This is deliberately NOT read from ctx: the go-sdk's Streamable HTTP
// transport dispatches queued JSON-RPC messages on a connection-lifetime
// goroutine detached from any single HTTP request's context (see
// mcp.StreamableHTTPOptions.PropagateRequestCancellation's own doc comment,
// which confirms per-request context propagation is protocol-version-gated
// and off by default) -- so per-call authentication state has to travel via
// the request's own Extra field, which the SDK DOES refresh per call, not
// via context values set once at session-initialize time. This is the fix
// for Finding 1's first half: a tool call made after a mid-session
// role/status change re-authenticates and re-authorizes against the
// CURRENT user row, not the frozen one from initialize.
func (h *Handler) actorFromRequest(ctx context.Context, req *mcp.CallToolRequest) (*auth.Actor, error) {
	var hdr string
	if req != nil && req.Extra != nil {
		hdr = req.Extra.Header.Get("Authorization")
	}
	return h.authenticateHeader(ctx, hdr)
}

// requireActor is every tool handler's first statement (see tools_*.go):
// it re-authenticates the CURRENT call via actorFromRequest and returns a
// ready-to-return tool error on failure. The error message is deliberately
// generic ("authentication required"), matching write401's own refusal to
// let a caller fingerprint *why* a credential failed -- a demoted,
// disabled, or token-revoked caller mid-session is refused exactly like a
// brand-new unauthenticated request would be, with no state change.
func (h *Handler) requireActor(ctx context.Context, req *mcp.CallToolRequest) (*store.User, error) {
	act, err := h.actorFromRequest(ctx, req)
	if err != nil {
		return nil, errors.New("authentication required")
	}
	return act.User, nil
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
// SET (and therefore tools/list) registered here for act's role is fixed
// for the session's whole lifetime: a mid-session role change or status
// change does NOT add or remove a tool from tools/list until the actor's
// next new session. This is deliberately just a tools/list UX detail, not
// an authorization gap: every handler independently re-derives and
// re-checks the CURRENT actor on every call (see actorFromRequest/
// requireActor), so a tool that's still listed but no longer permitted is
// refused with no state change -- see this package's doc comment and
// Finding 1's own writeup for why registration-time filtering and
// call-time authorization are deliberately two separate mechanisms.
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

	// Finding 2: cap concurrent sessions, both globally and per user, so a
	// single actor (or the fleet of them) can't grow the SDK's own session
	// map -- and h.sessions alongside it -- without bound. Returning nil
	// here (like the defensive nil-actor case above) makes the SDK respond
	// 400 Bad Request, refusing the new session outright; there is no
	// ResponseWriter available in this hook to shape a richer error body
	// (see NewStreamableHTTPHandler's own signature), so this is the
	// clearest rejection this integration point can give.
	h.sessMu.Lock()
	defer h.sessMu.Unlock()
	h.pruneClosedSessionsLocked()
	if len(h.sessions) >= mcpMaxSessionsGlobal {
		return nil
	}
	perUser := 0
	for _, uid := range h.sessions {
		if uid == act.User.ID {
			perUser++
		}
	}
	if perUser >= mcpMaxSessionsPerUser {
		return nil
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "funcbox", Version: serverVersion}, nil)
	h.registerTools(server, act.User)
	h.sessions[server] = act.User.ID
	return server
}

// pruneClosedSessionsLocked drops every entry from h.sessions whose
// underlying *mcp.Server no longer has a live session attached (closed via
// idle-timeout eviction, an explicit DELETE, or a failed initialize -- see
// StreamableHTTPHandler.serveStatefulPOST's own "if initialization failed,
// clean up the session" comment) -- otherwise h.sessions would grow forever
// even though the SDK's own session map is correctly bounded by
// mcpSessionIdleTimeout. Callers must hold h.sessMu.
//
// The go-sdk gives no direct "session closed" callback this package can
// register (StreamableHTTPHandler's own onClose hook is private), so this
// runs opportunistically on every new-session attempt instead -- each
// *mcp.Server this package creates is dedicated to exactly one session
// (getServer never returns an existing *mcp.Server for a second session),
// so Server.Sessions() yielding nothing means that session has ended.
//
// Accepted race: a *mcp.Server is added to h.sessions here, in getServer,
// slightly BEFORE the SDK actually calls Connect on it (Connect happens
// just after getServer returns, still within the same HTTP request/response
// cycle). A different, truly concurrent getServer call landing in that
// narrow window would see zero live sessions on the not-yet-connected entry
// and evict it early. This is a soft-cap safety net, not a hard security
// boundary, so an occasional undercount (letting one extra session through
// under heavy concurrent initialize load) is an acceptable tradeoff against
// the complexity of a fully synchronized alternative.
func (h *Handler) pruneClosedSessionsLocked() {
	for server := range h.sessions {
		live := false
		for range server.Sessions() {
			live = true
			break
		}
		if !live {
			delete(h.sessions, server)
		}
	}
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
