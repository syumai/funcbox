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
	"time"
)

// requestTimeout bounds every management-API request the CLI makes. Deploy
// uploads are the slowest case, but they're capped at 5MiB compressed
// (service.MaxCompressedBundleBytes), so this is generous rather than
// tight.
const requestTimeout = 60 * time.Second

// Client is a minimal HTTP client for funcbox-server's management API
// (which never talks to a server at all).
type Client struct {
	Server string // base URL, e.g. "https://fb.example.com"
	Token  string
	HTTP   *http.Client
}

// NewClient builds a Client from a resolved Config.
func NewClient(cfg Config) *Client {
	return &Client{
		Server: strings.TrimSuffix(cfg.Server, "/"),
		Token:  cfg.Token,
		HTTP:   &http.Client{Timeout: requestTimeout},
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
// c.Server) with the Authorization header attached, and returns the raw
// response body on success. A non-2xx status is translated to *APIError.
func (c *Client) do(req *http.Request) ([]byte, error) {
	req.Header.Set("Authorization", "Bearer "+c.Token)
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
