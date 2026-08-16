// consent.go implements the signed, short-lived state token carried in the
// consent page's "Approve" form (authorize.go). It plays the same role
// internal/auth's own oauthState cookie / GitHub link-confirmation token
// play: proof that the value being acted on was minted by THIS server for
// THIS specific request, moments ago, rather than forged or replayed by a
// third party -- which is exactly what CSRF protection needs here, since
// the consent page is a plain HTML <form> POST with no custom header a
// double-submit cookie check could inspect (unlike the dashboard's own
// fetch()-based mutations).
//
// Unlike the CLI login flow's one-time, store-persisted auth code, this
// token is stateless (HMAC-signed, not looked up) -- it only needs to
// survive one browser round trip (GET's render to POST's submit), exactly
// like internal/auth's own oauthState cookie.
package oauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// consentStateMaxAge bounds how long a rendered consent page's Approve
// form remains submittable -- generous enough for a human to read the
// page and click a button, short enough that a leaked/logged token isn't
// useful for long. Matches internal/auth's own oauthStateMaxAge.
const consentStateMaxAge = 10 * time.Minute

// consentState is the payload signed into the consent page's hidden
// "state" form field: every parameter GET /oauth/authorize validated,
// plus the acting user's ID (so POST's handler can confirm the SAME
// session that saw the consent page is the one approving it) and an
// issuance timestamp.
type consentState struct {
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	Challenge   string `json:"code_challenge"`
	OAuthState  string `json:"state,omitempty"` // the CLIENT's own "state" query param, echoed back verbatim
	Resource    string `json:"resource,omitempty"`
	UserID      string `json:"user_id"`
	IssuedAt    int64  `json:"iat"`
}

// signConsentState HMAC-signs st and encodes it for use as a hidden form
// field value, the same base64(payload)+"."+hex(hmac) shape
// internal/auth's own signState uses for its OAuth state cookie.
func (h *Handler) signConsentState(st consentState) (string, error) {
	payload, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	sig := hmacHex(h.consentKey, payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + sig, nil
}

// parseConsentState verifies raw's signature and expiry and returns its
// payload.
func (h *Handler) parseConsentState(raw string) (consentState, error) {
	payloadB64, sig, ok := strings.Cut(raw, ".")
	if !ok {
		return consentState{}, fmt.Errorf("oauth: malformed consent state")
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return consentState{}, fmt.Errorf("oauth: malformed consent state: %w", err)
	}
	if !constantTimeEqual(hmacHex(h.consentKey, payload), sig) {
		return consentState{}, fmt.Errorf("oauth: consent state signature mismatch")
	}
	var st consentState
	if err := json.Unmarshal(payload, &st); err != nil {
		return consentState{}, fmt.Errorf("oauth: malformed consent state payload: %w", err)
	}
	if time.Since(time.Unix(st.IssuedAt, 0)) > consentStateMaxAge {
		return consentState{}, fmt.Errorf("oauth: consent state expired")
	}
	return st, nil
}

func hmacHex(key, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return fmt.Sprintf("%x", mac.Sum(nil))
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
