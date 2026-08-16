// metadata.go implements the two discovery documents an MCP client uses to
// find this authorization server and its endpoints, entirely without prior
// configuration:
//
//   - GET /.well-known/oauth-protected-resource (RFC 9728): served from
//     the RESOURCE's own origin (funcbox's control origin, since /mcp lives
//     there too), it points back at this authorization server.
//   - GET /.well-known/oauth-authorization-server (RFC 8414): served from
//     this authorization server's own origin (the same control origin --
//     funcbox is both AS and resource server), it lists this package's
//     concrete endpoint URLs and capabilities.
//
// Neither requires authentication; both are plain, cacheable JSON.
package oauth

import (
	"encoding/json"
	"net/http"
)

// authorizationServerMetadata is RFC 8414's AS metadata document, trimmed
// to the fields this package's endpoints actually support.
type authorizationServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

func (h *Handler) handleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	meta := authorizationServerMetadata{
		Issuer:                        h.cfg.ControlOrigin,
		AuthorizationEndpoint:         h.cfg.ControlOrigin + "/oauth/authorize",
		TokenEndpoint:                 h.cfg.ControlOrigin + "/oauth/token",
		RegistrationEndpoint:          h.cfg.ControlOrigin + "/oauth/register",
		ResponseTypesSupported:        []string{"code"},
		GrantTypesSupported:           []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported: []string{"S256"},
		// "none": every client this package registers is a public client
		// (RFC 7591 DCR never issues a client_secret here) -- see this
		// package's doc comment.
		TokenEndpointAuthMethodsSupported: []string{"none"},
	}
	writeJSON(w, http.StatusOK, meta)
}

// protectedResourceMetadata is RFC 9728's protected-resource metadata
// document.
type protectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

func (h *Handler) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	meta := protectedResourceMetadata{
		Resource:             h.protectedResource(),
		AuthorizationServers: []string{h.cfg.ControlOrigin},
	}
	writeJSON(w, http.StatusOK, meta)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
