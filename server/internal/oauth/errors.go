package oauth

import "net/http"

// oauthError is the standard OAuth JSON error body (RFC 6749 §5.2's token
// endpoint error response; RFC 7591 §3.2.2 uses the identical shape for
// dynamic client registration errors).
type oauthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// writeOAuthError writes the standard {"error","error_description"} body.
// code is one of RFC 6749/7591's fixed error codes (e.g. "invalid_request",
// "invalid_grant", "invalid_client_metadata") -- always a literal at every
// call site in this package, never caller-controlled data.
func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, oauthError{Error: code, ErrorDescription: description})
}

// invalidRequest/invalidGrant/etc. are shorthands for the fixed error
// codes this package's handlers return, kept as named constants so a
// call site reads "invalid_grant" once, not as a string literal repeated
// at every use (and so a typo in one spot doesn't silently mint a
// different error code than every other caller of the same failure mode).
const (
	errInvalidRequest          = "invalid_request"
	errInvalidClientMetadata   = "invalid_client_metadata"
	errInvalidGrant            = "invalid_grant"
	errUnsupportedGrantType    = "unsupported_grant_type"
	errUnsupportedResponseType = "unsupported_response_type"
	errAccessDenied            = "access_denied"
	errServerError             = "server_error"
)
