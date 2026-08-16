// Package oauth implements funcbox's OAuth 2.1 authorization server for
// MCP clients, per the MCP Authorization spec (which itself profiles
// RFC 6749/7636/7591/8414/8707/9728). funcbox already has a working
// PKCE-based browser login flow for `funcbox login` (server/internal/auth's
// clicredential.go/cliauth.go/accesstoken.go); this package generalizes
// that shape into standards-compliant endpoints a generic MCP client (not
// just funcbox's own CLI) can drive:
//
//   - GET  /.well-known/oauth-authorization-server  (RFC 8414 AS metadata)
//   - GET  /.well-known/oauth-protected-resource     (RFC 9728 resource metadata)
//   - POST /oauth/register                           (RFC 7591 dynamic client registration)
//   - GET  /oauth/authorize, POST /oauth/authorize    (authorization + consent decision)
//   - POST /oauth/token                               (authorization_code and refresh_token grants)
//
// Every client this package registers is a PUBLIC client (RFC 7591's
// "token_endpoint_auth_methods_supported": ["none"]): there is no
// client_secret anywhere in this flow, matching the MCP Authorization
// spec's expectation that MCP clients authenticate purely via PKCE
// (RFC 7636, S256 required). Access tokens minted by this package's
// /oauth/token reuse funcbox's existing "fbxa_..." HMAC-signed token
// format (server/internal/auth's accesstoken.go) via
// Auth.IssueAccessTokenForAudience, carrying an "aud":"mcp" claim
// (auth.AudienceMCP) -- so `funcbox print-access-token`'s own aud-less
// tokens keep working everywhere they always have, and this package's own
// tokens round-trip that claim for a later step's /mcp acceptance
// scoping. Refresh tokens are a new long-lived entity, oauth_grants
// (server/internal/store), deliberately mirroring cli_credentials'
// sliding-90-day-expiry shape.
//
// This package only exports http.Handlers (via Handler.Routes); it does
// NOT mount them onto any router and does NOT implement the /mcp endpoint
// itself -- both are a later step's job, once server/internal/mcpserver
// exists and the organization's mcp_enabled gate is wired up.
package oauth
