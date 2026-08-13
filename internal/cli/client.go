package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"sync"
	"time"
)

// requestTimeout bounds every management-API request the CLI makes. Deploy
// uploads are the slowest case, but they're capped at 5MiB compressed
// (service.MaxCompressedBundleBytes), so this is generous rather than
// tight.
const requestTimeout = 60 * time.Second

// accessTokenRequestTTL is the TTL the CLI requests for the access tokens
// it mints for its own internal use (deploy/list/logs/... calls) --
// distinct from `funcbox print-access-token`'s own --ttl flag, which a
// caller controls directly. 15 minutes matches the server's own default
// (§14.5), comfortably longer than any single CLI invocation needs.
const accessTokenRequestTTL = 15 * time.Minute

// accessTokenRefreshMargin: a cached access token is re-minted once less
// than this much of its lifetime remains, so a long-running command (e.g.
// `funcbox logs --follow`) never presents an about-to-expire token to the
// server.
const accessTokenRefreshMargin = 2 * time.Minute

// Client is a minimal HTTP client for funcbox-server's management API
// (which never talks to a server at all). Every request authenticates
// with a short-lived access token (§14.5) minted on demand from Credential
// (the CLI login credential `funcbox login` saved, §14.4) and cached until
// it's close to expiring -- callers never see this; it happens
// transparently inside do().
type Client struct {
	Server     string // base URL, e.g. "https://fb.example.com"
	Credential string
	HTTP       *http.Client

	mu          sync.Mutex
	accessToken string
	expiresAt   time.Time
}

// NewClient builds a Client from a resolved Config.
func NewClient(cfg Config) *Client {
	return &Client{
		Server:     strings.TrimSuffix(cfg.Server, "/"),
		Credential: cfg.Credential,
		HTTP:       &http.Client{Timeout: requestTimeout},
	}
}

// {"error":{"code","message"}}).
type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// APIError is returned by Client methods for a non-2xx response whose body
// decoded as the standard error envelope (or, failing that, carries the
// raw status/body for debugging).
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("server returned %d %s: %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("server returned %d: %s", e.Status, e.Message)
}

// do issues req (which must already have its path/query set relative to
// c.Server) with a freshly minted-or-cached access token attached as its
// Authorization header, and returns the raw response body on success. A
// non-2xx status is translated to *APIError.
func (c *Client) do(req *http.Request) ([]byte, error) {
	token, err := c.ensureAccessToken(req.Context())
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return c.doRaw(req)
}

// doRaw issues req as-is (no Authorization header of its own opinion) and
// returns the raw response body on success, or *APIError for a non-2xx
// response. Shared by do() (bearer access token) and the unauthenticated
// or credential-authenticated CLI login-flow calls below.
func (c *Client) doRaw(req *http.Request) ([]byte, error) {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cli: request to %s: %w", c.Server, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cli: read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{Status: resp.StatusCode, Message: string(body)}
		var envelope apiError
		if json.Unmarshal(body, &envelope) == nil && envelope.Error.Code != "" {
			apiErr.Code = envelope.Error.Code
			apiErr.Message = envelope.Error.Message
		}
		return nil, apiErr
	}
	return body, nil
}

// ensureAccessToken returns a cached access token if it's not close to
// expiring, minting (and caching) a fresh one otherwise. Every do() call
// goes through this -- it's what lets deploy/list/logs/... never think
// about token lifetime at all.
func (c *Client) ensureAccessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.accessToken != "" && time.Until(c.expiresAt) > accessTokenRefreshMargin {
		return c.accessToken, nil
	}
	token, expiresAt, err := c.mintAccessToken(ctx, accessTokenRequestTTL)
	if err != nil {
		return "", err
	}
	c.accessToken, c.expiresAt = token, expiresAt
	return token, nil
}

// accessTokenResponse is POST /api/v1/cli/access-token's JSON body.
type accessTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresAt   string `json:"expires_at"` // RFC3339
}

// mintAccessToken calls the UNAUTHENTICATED (at the server's
// Auth.Middleware level) POST /api/v1/cli/access-token, authenticated
// instead by c.Credential in its own Authorization header (§14.5). ttl <=
// 0 omits the request body's ttl field entirely, letting the server apply
// its own default (15 minutes).
func (c *Client) mintAccessToken(ctx context.Context, ttl time.Duration) (token string, expiresAt time.Time, err error) {
	if c.Credential == "" {
		return "", time.Time{}, fmt.Errorf("not logged in: run `funcbox login --server <url>`, or set FUNCBOX_CREDENTIAL")
	}
	bodyMap := map[string]string{}
	if ttl > 0 {
		bodyMap["ttl"] = ttl.String()
	}
	bodyJSON, err := json.Marshal(bodyMap)
	if err != nil {
		return "", time.Time{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Server+"/api/v1/cli/access-token", bytes.NewReader(bodyJSON))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Credential)

	respBody, err := c.doRaw(req)
	if err != nil {
		return "", time.Time{}, err
	}
	var out accessTokenResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return "", time.Time{}, fmt.Errorf("cli: decode access-token response: %w", err)
	}
	exp, err := time.Parse(time.RFC3339, out.ExpiresAt)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("cli: parse access token expiry: %w", err)
	}
	return out.AccessToken, exp, nil
}

// MintAccessToken mints a brand-new access token from the saved
// credential with the given ttl (<= 0 requests the server's own default,
// 15 minutes; the server clamps anything past its 1-hour maximum
// regardless), for `funcbox print-access-token`. It bypasses do()'s
// internal cache -- this is the one caller that wants a token with an
// explicit, caller-chosen TTL rather than the client's own fixed internal
// default.
func (c *Client) MintAccessToken(ctx context.Context, ttl time.Duration) (token string, expiresAt time.Time, err error) {
	return c.mintAccessToken(ctx, ttl)
}

// ExchangeCLICode implements the CLI side of the loopback+PKCE login
// flow's final step (§14.4): the UNAUTHENTICATED POST /api/v1/cli/token,
// trading a one-time authorization code + its PKCE verifier for a new CLI
// login credential ("fbxc_...").
func (c *Client) ExchangeCLICode(ctx context.Context, code, verifier string) (credential string, err error) {
	bodyJSON, err := json.Marshal(map[string]string{"code": code, "verifier": verifier})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Server+"/api/v1/cli/token", bytes.NewReader(bodyJSON))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	respBody, err := c.doRaw(req)
	if err != nil {
		return "", err
	}
	var out struct {
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return "", fmt.Errorf("cli: decode token response: %w", err)
	}
	if out.Credential == "" {
		return "", fmt.Errorf("cli: server returned an empty credential")
	}
	return out.Credential, nil
}

// Me calls GET /api/v1/me, mainly used by `funcbox login` to verify a
// token before saving it.
func (c *Client) Me(ctx context.Context) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Server+"/api/v1/me", nil)
	if err != nil {
		return nil, err
	}
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("cli: decode /api/v1/me response: %w", err)
	}
	return out, nil
}

// DeployRequest is the input to Deploy.
type DeployRequest struct {
	Bundle []byte // canonical tar.gz (see bundle.Pack)
	Owner  string
	Name   string
	Note   string
	DryRun bool
}

// FunctionDTO is the subset of the deploy/list/get response's "function"
// object the CLI cares about.
type FunctionDTO struct {
	ID              string `json:"id"`
	OwnerType       string `json:"owner_type"`
	Owner           string `json:"owner,omitempty"`
	Name            string `json:"name"`
	URL             string `json:"url,omitempty"`
	Description     string `json:"description"`
	ActiveVersionID string `json:"active_version_id,omitempty"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

// VersionDTO is the subset of a version object the CLI cares about.
type VersionDTO struct {
	ID       string          `json:"id"`
	Note     string          `json:"note"`
	Manifest json.RawMessage `json:"manifest"`
}

// DeployResponse is POST /api/v1/functions's JSON body
// (internal/api/deploy.go's deployResponseBody).
type DeployResponse struct {
	DryRun   bool            `json:"dry_run"`
	Manifest json.RawMessage `json:"manifest"`
	Warnings []string        `json:"warnings"`
	Function *FunctionDTO    `json:"function"`
	Version  *VersionDTO     `json:"version"`
}

// multipart upload of the pre-packed canonical bundle.
func (c *Client) Deploy(ctx context.Context, r DeployRequest) (*DeployResponse, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	part, err := w.CreateFormFile("bundle", "bundle.tar.gz")
	if err != nil {
		return nil, err
	}
	if _, err := part.Write(r.Bundle); err != nil {
		return nil, err
	}
	for field, value := range map[string]string{"owner": r.Owner, "name": r.Name, "note": r.Note} {
		if value == "" {
			continue
		}
		if err := w.WriteField(field, value); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}

	url := c.Server + "/api/v1/functions"
	if r.DryRun {
		url += "?dry_run=true"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var out DeployResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("cli: decode deploy response: %w", err)
	}
	return &out, nil
}

// List calls GET /api/v1/functions[?owner=...].
func (c *Client) List(ctx context.Context, owner string) ([]FunctionDTO, error) {
	url := c.Server + "/api/v1/functions"
	if owner != "" {
		url += "?owner=" + owner
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var out struct {
		Functions []FunctionDTO `json:"functions"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("cli: decode list response: %w", err)
	}
	return out.Functions, nil
}

// LogDTO is the subset of an invocation log object the CLI cares about
// (internal/api/functions.go's invocationLogDTO).
type LogDTO struct {
	ID         string `json:"id"`
	VersionID  string `json:"version_id"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Status     int    `json:"status"`
	DurationMS int64  `json:"duration_ms"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	CreatedAt  string `json:"created_at"`
}

// Logs calls GET /api/v1/functions/{owner}/{name}/logs[?since=&limit=]
// starting strictly before since (pass an empty since for the first/most
// recent page).
func (c *Client) Logs(ctx context.Context, owner, name, since string, limit int) ([]LogDTO, error) {
	url := fmt.Sprintf("%s/api/v1/functions/%s/%s/logs", c.Server, owner, name)
	q := make([]string, 0, 2)
	if since != "" {
		q = append(q, "since="+since)
	}
	if limit > 0 {
		q = append(q, fmt.Sprintf("limit=%d", limit))
	}
	if len(q) > 0 {
		url += "?" + strings.Join(q, "&")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var out struct {
		Logs []LogDTO `json:"logs"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("cli: decode logs response: %w", err)
	}
	return out.Logs, nil
}

// Activate calls POST /api/v1/functions/{owner}/{name}/versions/{id}/activate
// (the rollback endpoint).
func (c *Client) Activate(ctx context.Context, owner, name, versionID string) (*FunctionDTO, error) {
	url := fmt.Sprintf("%s/api/v1/functions/%s/%s/versions/%s/activate", c.Server, owner, name, versionID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, err
	}
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var out FunctionDTO
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("cli: decode activate response: %w", err)
	}
	return &out, nil
}
