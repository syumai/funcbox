// register.go implements POST /oauth/register: RFC 7591 Dynamic Client
// Registration, unauthenticated (any caller may register a client -- this
// is DCR's whole point, letting an MCP client register itself on first
// connection with no prior operator setup) and issuing only a client_id,
// never a client_secret (see this package's doc comment: every registered
// client is public).
package oauth

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/syumai/funcbox/server/internal/store"
)

// maxClientNameLength bounds the caller-supplied client_name (like
// internal/auth's maxCLIDeviceNameLength for the analogous CLI device
// name): it's rendered unescaped-length-wise (though always HTML-escaped)
// on the consent page, so an unbounded value is a footgun, not a feature.
const maxClientNameLength = 128

// maxRedirectURIs caps how many redirect URIs a single registration may
// claim, so a malicious/buggy client can't bloat an oauth_clients row
// (and, transitively, the consent page's own storage) unboundedly.
const maxRedirectURIs = 10

// maxRedirectURILength bounds each individual redirect_uri's length --
// maxRedirectURIs alone still permits an attacker to submit a handful of
// enormous strings, so both caps are needed together.
const maxRedirectURILength = 2048

type registerRequest struct {
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
}

type registerResponse struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	// Rate limit BEFORE parsing/validating anything else: a source
	// hammering this endpoint shouldn't get free JSON-parsing/validation
	// work out of us either, and a 429 needs no knowledge of the request
	// body at all. See ratelimit.go's doc comment for what this is (and
	// isn't) defending against.
	if !h.registerLimiter.allow(clientIP(r)) {
		writeOAuthError(w, http.StatusTooManyRequests, errTemporarilyUnavailable,
			"too many client registrations from this source -- please slow down and try again shortly")
		return
	}

	var body registerRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeOAuthError(w, http.StatusBadRequest, errInvalidClientMetadata, "request body must be JSON")
		return
	}

	if len(body.ClientName) > maxClientNameLength {
		writeOAuthError(w, http.StatusBadRequest, errInvalidClientMetadata, "client_name is too long")
		return
	}
	if len(body.RedirectURIs) == 0 {
		writeOAuthError(w, http.StatusBadRequest, errInvalidClientMetadata, "redirect_uris must be a non-empty array")
		return
	}
	if len(body.RedirectURIs) > maxRedirectURIs {
		writeOAuthError(w, http.StatusBadRequest, errInvalidClientMetadata, "too many redirect_uris")
		return
	}
	for _, u := range body.RedirectURIs {
		if len(u) > maxRedirectURILength {
			writeOAuthError(w, http.StatusBadRequest, errInvalidClientMetadata, "a redirect_uri is too long")
			return
		}
		if !validRedirectURI(u) {
			writeOAuthError(w, http.StatusBadRequest, errInvalidClientMetadata,
				"redirect_uris must each be an https:// URL, or an http:// loopback URL (127.0.0.1/localhost/::1) for native clients")
			return
		}
	}

	cl := &store.OAuthClient{
		Name:         sanitizeClientName(body.ClientName),
		RedirectURIs: body.RedirectURIs,
	}
	if err := h.store.OAuthClients().Create(r.Context(), cl); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, errServerError, "failed to register client")
		return
	}
	// Deliberately not audit-logged: DCR is, by design, an unauthenticated,
	// self-service endpoint (any MCP client may register itself with no
	// prior operator setup) with no actor to attribute the event to --
	// unlike every other Audit() call site in this codebase, which all
	// record an authenticated user's privileged action.

	writeJSON(w, http.StatusCreated, registerResponse{
		ClientID:                cl.ID,
		ClientName:              cl.Name,
		RedirectURIs:            cl.RedirectURIs,
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		ClientIDIssuedAt:        cl.CreatedAt.Unix(),
	})
}

// validRedirectURI reports whether u is an acceptable redirect_uri for a
// registered public client: an https:// URL (any host), or an http://
// loopback URL (127.0.0.1/localhost/::1, any port) for a native client
// running its own local callback listener -- mirroring
// internal/auth's validCLILoopbackRedirect's loopback rule, generalized to
// allow https for the common "web-hosted MCP client" case that flow never
// needed to support. Neither a fragment nor userinfo is permitted
// (RFC 6749 §3.1.2 forbids both).
func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Fragment != "" || u.Host == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		host := strings.ToLower(u.Hostname())
		return host == "127.0.0.1" || host == "localhost" || host == "::1"
	default:
		return false
	}
}

// sanitizeClientName strips control characters and truncates name (like
// internal/auth's sanitizeCLIDeviceName does for the CLI login flow's
// device name), since it's later rendered on the consent page.
func sanitizeClientName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	name = strings.TrimSpace(b.String())
	if len(name) > maxClientNameLength {
		name = name[:maxClientNameLength]
	}
	return name
}
