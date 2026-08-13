// devidp.go implements the FUNCBOX_AUTH_MODE=dev stub OIDC issuer
// (tmp/05-auth-and-permissions.md §5.1's "開発モード"): a minimal,
// in-process identity provider serving standard OIDC discovery/JWKS/
// authorize/token endpoints under /dev/oidc/*, signing ID tokens with a
// key generated fresh on every process start. Its authorize endpoint
// accepts ANY email typed into a form -- there is no password, no
// verification of who's actually logging in -- which is exactly why
// Auth.New refuses to enable it outside a loopback listener (config.go).
//
// Everything downstream of "here is a raw ID token JWT" -- provider
// discovery, JWKS-based signature verification, claim checks -- runs
// through the IDENTICAL code path as a real Google login (see provider.go
// and login.go); this file's only job is to produce a token that looks
// exactly like what Google would have sent.
package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// devOIDCPrefix is both the URL prefix every stub endpoint is served
// under and (combined with the server's BaseURL) the issuer URL that
// appears as "iss" in stub-issued ID tokens.
const devOIDCPrefix = "/dev/oidc"

const devIDTokenTTL = 10 * time.Minute
const devAuthCodeTTL = 5 * time.Minute

// devIdP is the stub identity provider's state: one RSA signing key
// generated at construction (i.e. once per process start -- "起動ごとに
// 生成する鍵で ID Token を署名"), and a short-lived, single-use
// authorization-code store.
type devIdP struct {
	issuer string
	kid    string
	key    *rsa.PrivateKey

	mu    sync.Mutex
	codes map[string]devAuthCode
}

type devAuthCode struct {
	email       string
	clientID    string
	redirectURI string
	nonce       string
	expiresAt   time.Time
}

func newDevIdP(issuer string) *devIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		// A CSPRNG/RSA keygen failure at startup is unrecoverable; there's
		// no reasonable degraded mode for an identity provider with no key.
		panic(fmt.Sprintf("auth: generate dev OIDC signing key: %v", err))
	}
	return &devIdP{
		issuer: issuer,
		kid:    "dev-" + fmt.Sprint(time.Now().UnixNano()),
		key:    key,
		codes:  make(map[string]devAuthCode),
	}
}

// DevRoutes returns the http.Handler serving the stub issuer's endpoints
// under devOIDCPrefix, or nil if a isn't running in dev mode. Mount it
// only when non-nil (tmp/07-http-api.md §7.1: "/dev/oidc/* dev モード時
// のみ").
func (a *Auth) DevRoutes() http.Handler {
	if a.dev == nil {
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+devOIDCPrefix+"/.well-known/openid-configuration", a.dev.handleDiscovery)
	mux.HandleFunc("GET "+devOIDCPrefix+"/jwks.json", a.dev.handleJWKS)
	mux.HandleFunc("GET "+devOIDCPrefix+"/authorize", a.dev.handleAuthorizeForm)
	mux.HandleFunc("POST "+devOIDCPrefix+"/authorize", a.dev.handleAuthorizeSubmit)
	mux.HandleFunc("POST "+devOIDCPrefix+"/token", a.dev.handleToken)
	return mux
}

func (d *devIdP) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                d.issuer,
		"authorization_endpoint":                d.issuer + "/authorize",
		"token_endpoint":                        d.issuer + "/token",
		"jwks_uri":                              d.issuer + "/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
		"claims_supported":                      []string{"sub", "email", "email_verified", "name", "iss", "aud", "exp", "iat", "nonce"},
	})
}

func (d *devIdP) handleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := d.key.PublicKey
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": d.kid,
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

// handleAuthorizeForm renders a minimal HTML form letting the developer
// type in any email address to "sign in" as (tmp/05-auth-and-permissions.md
// §5.1: "ログイン画面で任意の email を入力できる"). It carries the OAuth
// request's client_id/redirect_uri/state/nonce through as hidden fields
// rather than re-deriving them at submit time, so the submit handler
// doesn't need any server-side flow state until a code is actually
// issued.
func (d *devIdP) handleAuthorizeForm(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" {
		http.Error(w, "dev oidc: only response_type=code is supported", http.StatusBadRequest)
		return
	}
	if q.Get("redirect_uri") == "" || q.Get("client_id") == "" {
		http.Error(w, "dev oidc: client_id and redirect_uri are required", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html>
<html><head><title>funcbox dev sign-in</title></head>
<body>
<h1>funcbox dev sign-in</h1>
<p>FUNCBOX_AUTH_MODE=dev: enter any email to sign in as that user. This form does not check passwords.</p>
<form method="POST" action="%s/authorize">
<input type="hidden" name="client_id" value="%s">
<input type="hidden" name="redirect_uri" value="%s">
<input type="hidden" name="state" value="%s">
<input type="hidden" name="nonce" value="%s">
<label>Email: <input type="email" name="email" required autofocus></label>
<button type="submit">Sign in</button>
</form>
</body></html>`,
		devOIDCPrefix,
		html.EscapeString(q.Get("client_id")),
		html.EscapeString(q.Get("redirect_uri")),
		html.EscapeString(q.Get("state")),
		html.EscapeString(q.Get("nonce")),
	)
}

func (d *devIdP) handleAuthorizeSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "dev oidc: invalid form", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	redirectURI := r.FormValue("redirect_uri")
	clientID := r.FormValue("client_id")
	state := r.FormValue("state")
	nonce := r.FormValue("nonce")
	if email == "" || redirectURI == "" {
		http.Error(w, "dev oidc: email and redirect_uri are required", http.StatusBadRequest)
		return
	}

	code := randomURLToken(16)
	d.mu.Lock()
	d.codes[code] = devAuthCode{
		email: email, clientID: clientID, redirectURI: redirectURI, nonce: nonce,
		expiresAt: time.Now().Add(devAuthCodeTTL),
	}
	d.mu.Unlock()

	dest, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "dev oidc: invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := dest.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	dest.RawQuery = q.Encode()
	http.Redirect(w, r, dest.String(), http.StatusFound)
}

// handleToken exchanges a one-time code for an ID token. Per this file's
// doc comment, PKCE's code_verifier is accepted but NOT cryptographically
// checked against the authorize step's code_challenge -- the stub issuer
// is not a security boundary (dev mode already requires an explicit env
// var plus a loopback listener), and every other check downstream
// (issuer, audience, expiry, signature) is real and shared with
// production.
func (d *devIdP) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "dev oidc: invalid form", http.StatusBadRequest)
		return
	}
	if r.FormValue("grant_type") != "authorization_code" {
		http.Error(w, "dev oidc: unsupported grant_type", http.StatusBadRequest)
		return
	}
	code := r.FormValue("code")

	d.mu.Lock()
	entry, ok := d.codes[code]
	if ok {
		delete(d.codes, code) // single use
	}
	d.mu.Unlock()

	if !ok || time.Now().After(entry.expiresAt) {
		http.Error(w, "dev oidc: unknown or expired code", http.StatusBadRequest)
		return
	}
	if entry.redirectURI != r.FormValue("redirect_uri") {
		http.Error(w, "dev oidc: redirect_uri mismatch", http.StatusBadRequest)
		return
	}

	clientID := r.FormValue("client_id")
	if clientID == "" {
		clientID = entry.clientID
	}

	idToken, err := d.signIDToken(entry.email, clientID, entry.nonce)
	if err != nil {
		http.Error(w, "dev oidc: failed to sign id token", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": randomURLToken(16),
		"token_type":   "Bearer",
		"expires_in":   int(devIDTokenTTL.Seconds()),
		"id_token":     idToken,
	})
}

// signIDToken builds and RS256-signs a compact JWS ID token with the
// standard OIDC claims a real Google token would carry.
func (d *devIdP) signIDToken(email, aud, nonce string) (string, error) {
	now := time.Now()
	sub := fmt.Sprintf("%x", sha256.Sum256([]byte("dev-subject:"+email)))[:32]

	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": d.kid}
	claims := map[string]any{
		"iss":            d.issuer,
		"sub":            sub,
		"aud":            aud,
		"exp":            now.Add(devIDTokenTTL).Unix(),
		"iat":            now.Unix(),
		"email":          email,
		"email_verified": true,
		"name":           email,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, d.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// writeJSON is devidp.go's own tiny JSON writer, mirroring internal/api's
// (duplicated to avoid an internal/api -> internal/auth import cycle in
// reverse).
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
