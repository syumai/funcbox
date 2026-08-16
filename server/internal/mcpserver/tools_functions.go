// tools_functions.go implements the MCP functions tool group: the AI-agent
// deploy/edit/invoke loop this whole step exists for (§16.4.1 of the
// design doc). Every tool here is registered for EVERY authenticated
// actor (see registerFunctionsTools) -- unlike the users/org/audit
// groups, functions authorization is per-RESOURCE (view/deploy rights on
// one specific function or owner), not per-role, so it can't be decided
// at session-registration time the way an admin-only tool group can. Each
// handler instead re-derives it per call, reusing the exact same
// internal/service.Functions checks (CanView/CanManage) and
// internal/service.Deployer the REST API under /api/v1/functions uses --
// see this file's individual handlers for which one each tool calls.
package mcpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/syumai/funcbox/bundle"
	"github.com/syumai/funcbox/server/internal/api"
	"github.com/syumai/funcbox/server/internal/auth"
	"github.com/syumai/funcbox/server/internal/service"
	"github.com/syumai/funcbox/server/internal/store"
)

// getFunctionFilesBudget bounds get_function_files' total response size
// (decoded file content, summed across every included file) -- see
// getFunctionFilesHandler's doc comment.
const getFunctionFilesBudget = 2 << 20 // ~2MB

// invokeFunctionBodyCap bounds invoke_function's returned response body.
const invokeFunctionBodyCap = 1 << 20 // ~1MB

// invokeTokenTTL is how long the ephemeral access token buildInvokeRequest
// mints (see its doc comment) stays valid -- comfortably longer than any
// single invocation's own inv.Timeout, short enough that a leaked log line
// containing it (unlikely; it's never itself returned to the client) would
// stop mattering quickly.
const invokeTokenTTL = 5 * time.Minute

// registerFunctionsTools adds the full functions tool group for every
// authenticated, non-pending actor (h.getServer's own gate already refuses
// a pending user's session entirely) -- see this file's doc comment for
// why there is no role-based registration gate here. get_function_files
// and invoke_function are additionally gated on h.blob/h.invoker being
// configured (both optional dependencies; see New's doc comment).
func (h *Handler) registerFunctionsTools(server *mcp.Server, u *store.User) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_functions",
		Description: "List functions visible to you, optionally restricted to one owner (a public User ID or workspace ID).",
	}, h.listFunctionsHandler(u))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_function",
		Description: "Get a function's metadata, active version, effective fetch policy (organization/workspace/manifest three-tier view), and declared env var KEY NAMES (never values -- use the dashboard or REST API to read/set env var values).",
	}, h.getFunctionHandler(u))

	mcp.AddTool(server, &mcp.Tool{
		Name: "deploy_function",
		Description: "Deploy a function from a file map (funcbox.yaml + source files), the AI-agent deploy loop's centerpiece. " +
			"Files are packed into a canonical bundle and go through the exact same validation, limits, and audit trail as a normal deploy. " +
			"dry_run validates without persisting. Large bundles (node_modules, etc.) are rejected with a hint to use the funcbox CLI instead.",
	}, h.deployFunctionHandler(u))

	if h.blob != nil {
		mcp.AddTool(server, &mcp.Tool{
			Name: "get_function_files",
			Description: "Fetch a version's source files (active version by default, or a specific version_id). " +
				"Text files are returned as utf8, binary as base64. Large listings are capped by a total response budget: " +
				"once exceeded, remaining files are listed by path+size only -- fetch one specifically with input {\"file\": \"path\"}.",
		}, h.getFunctionFilesHandler(u))
	}

	if h.invoker != nil {
		mcp.AddTool(server, &mcp.Tool{
			Name: "invoke_function",
			Description: "Invoke a deployed function as yourself, through the exact same pipeline a real HTTP request uses " +
				"(visibility authorization, caller identity, execution logging, metrics). Useful to verify a deploy worked. " +
				"Response body is capped; oversized bodies are truncated (see \"truncated\").",
		}, h.invokeFunctionHandler(u))
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_function_logs",
		Description: "List a function's recent execution logs (newest first, paged via next_cursor).",
	}, h.getFunctionLogsHandler(u))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "rollback_function",
		Description: "Activate a previously deployed version of a function (rollback or roll-forward).",
	}, h.rollbackFunctionHandler(u))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "delete_function",
		Description: "Permanently delete a function and every one of its versions.",
	}, h.deleteFunctionHandler(u))
}

// listFunctionsIn is list_functions' input.
type listFunctionsIn struct {
	Owner string `json:"owner,omitempty" jsonschema:"optional: restrict the list to this owner (a public User ID or workspace ID); omit to list everything visible to you"`
}

// listFunctionsOut is list_functions' output.
type listFunctionsOut struct {
	Functions []map[string]any `json:"functions"`
}

func (h *Handler) listFunctionsHandler(u *store.User) mcp.ToolHandlerFor[listFunctionsIn, listFunctionsOut] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in listFunctionsIn) (*mcp.CallToolResult, listFunctionsOut, error) {
		dtos, err := h.api.ListFunctions(ctx, u, in.Owner)
		if err != nil {
			return nil, listFunctionsOut{}, toolError(err)
		}
		return nil, listFunctionsOut{Functions: dtos}, nil
	}
}

// getFunctionIn is the input shape shared by every tool below that
// addresses one specific function by owner+name.
type getFunctionIn struct {
	Owner string `json:"owner" jsonschema:"the function's owner: a public User ID or workspace ID"`
	Name  string `json:"name" jsonschema:"the function's name"`
}

func (h *Handler) getFunctionHandler(u *store.User) mcp.ToolHandlerFor[getFunctionIn, map[string]any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in getFunctionIn) (*mcp.CallToolResult, map[string]any, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, nil, errors.New("owner and name are both required")
		}
		fn, err := h.api.ResolveVisible(ctx, u, in.Owner, in.Name)
		if err != nil {
			return nil, nil, toolError(err)
		}
		body := h.api.FunctionDTO(ctx, fn, in.Owner)
		if fn.ActiveVersionID != nil {
			if v, err := h.api.Functions.ActiveVersion(ctx, fn); err == nil {
				body["active_version"] = api.VersionDTO(v)
			}
		}
		if levels, err := h.api.FetchPolicyLevels(ctx, fn); err == nil {
			body["fetch_policy_levels"] = levels
		}
		if keys, err := h.api.Functions.ListEnvKeys(ctx, fn); err == nil {
			sort.Strings(keys)
			body["env_keys"] = keys
		}
		return nil, body, nil
	}
}

// deployFileIn is one entry in deploy_function's "files" input.
type deployFileIn struct {
	Path     string `json:"path" jsonschema:"file path within the bundle, e.g. \"funcbox.yaml\" or \"lib/x.js\""`
	Content  string `json:"content" jsonschema:"file content, in the encoding named by \"encoding\""`
	Encoding string `json:"encoding,omitempty" jsonschema:"\"utf8\" (default) or \"base64\" (for binary files)"`
}

// deployFunctionIn is deploy_function's input: a file map, not an archive
// -- see this package's design doc §16.4.1 for why (an AI agent writes
// files, not tarballs).
type deployFunctionIn struct {
	Owner  string         `json:"owner" jsonschema:"the public User ID or workspace ID to deploy under"`
	Name   string         `json:"name,omitempty" jsonschema:"function name; omit to use funcbox.yaml's own \"name\" field (the two must agree if both are present)"`
	Note   string         `json:"note,omitempty" jsonschema:"optional deploy note, shown alongside this version in the dashboard"`
	DryRun bool           `json:"dry_run,omitempty" jsonschema:"validate only (manifest, limits, policy warnings) without persisting anything"`
	Files  []deployFileIn `json:"files" jsonschema:"the function's full file set, e.g. funcbox.yaml + index.js -- NOT a diff against a previous version"`
}

// deployFunctionOut is deploy_function's output.
type deployFunctionOut struct {
	URL       string   `json:"url,omitempty" jsonschema:"the deployed function's invocation URL (omitted for a dry run)"`
	VersionID string   `json:"version_id,omitempty" jsonschema:"the newly created version's ID (omitted for a dry run)"`
	Warnings  []string `json:"warnings"`
	DryRun    bool     `json:"dry_run"`
}

func (h *Handler) deployFunctionHandler(u *store.User) mcp.ToolHandlerFor[deployFunctionIn, deployFunctionOut] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in deployFunctionIn) (*mcp.CallToolResult, deployFunctionOut, error) {
		if in.Owner == "" {
			return nil, deployFunctionOut{}, errors.New("owner is required")
		}
		if len(in.Files) == 0 {
			return nil, deployFunctionOut{}, errors.New("files must contain at least one entry")
		}

		files := make(map[string][]byte, len(in.Files))
		var totalSize int64
		for _, f := range in.Files {
			if f.Path == "" {
				return nil, deployFunctionOut{}, errors.New("every file requires a non-empty path")
			}
			if _, dup := files[f.Path]; dup {
				return nil, deployFunctionOut{}, fmt.Errorf("duplicate file path %q", f.Path)
			}
			var data []byte
			switch f.Encoding {
			case "", "utf8":
				data = []byte(f.Content)
			case "base64":
				decoded, err := decodeBase64(f.Content)
				if err != nil {
					return nil, deployFunctionOut{}, fmt.Errorf("file %q: invalid base64 content", f.Path)
				}
				data = decoded
			default:
				return nil, deployFunctionOut{}, fmt.Errorf("file %q: encoding must be \"utf8\" or \"base64\"", f.Path)
			}
			files[f.Path] = data
			totalSize += int64(len(data))
		}

		// Oversize check up front, before packing: bundle.Unpack (inside
		// Deploy) would reject this too, but with a generic message that
		// doesn't mention the CLI escape hatch this tool's own design calls
		// for (§16.4.1: "巨大 node_modules 同梱などは CLI を案内する").
		if len(files) > bundle.MaxFiles || totalSize > bundle.MaxUnpackedBytes {
			return nil, deployFunctionOut{}, fmt.Errorf(
				"this bundle is too large to deploy over MCP (%d files, %d bytes unpacked; limits are %d files / %d bytes) -- use the funcbox CLI (`funcbox deploy`) for large bundles",
				len(files), totalSize, bundle.MaxFiles, bundle.MaxUnpackedBytes)
		}

		packed, err := bundle.Pack(files)
		if err != nil {
			return nil, deployFunctionOut{}, errors.New("failed to pack files into a bundle")
		}

		result, err := h.api.Deployer.Deploy(ctx, service.DeployParams{
			Bundle: bytes.NewReader(packed),
			Owner:  in.Owner,
			Name:   in.Name,
			Note:   in.Note,
			DryRun: in.DryRun,
			Actor:  u,
		})
		if err != nil {
			return nil, deployFunctionOut{}, toolError(err)
		}

		out := deployFunctionOut{Warnings: result.Warnings, DryRun: result.DryRun}
		if out.Warnings == nil {
			out.Warnings = []string{}
		}
		if !result.DryRun && result.Function != nil && result.Version != nil {
			dto := h.api.FunctionDTO(ctx, result.Function, in.Owner)
			if urlStr, ok := dto["url"].(string); ok {
				out.URL = urlStr
			}
			out.VersionID = result.Version.ID
			// Same audit entry api/deploy.go's handleDeploy writes for a REST
			// deploy -- see this package's users tool group for why every
			// mutating tool duplicates its REST counterpart's audit call
			// rather than relying on Deploy itself to log (Deploy is called
			// from both places specifically to share validation, not audit).
			_ = auth.Audit(ctx, h.store, u.ID, "function.deploy", "function:"+result.Function.ID,
				map[string]any{"owner": in.Owner, "name": result.Function.Name, "version_id": result.Version.ID})
		}
		return nil, out, nil
	}
}

// functionFileOut is one entry in get_function_files' output.
type functionFileOut struct {
	Path     string `json:"path"`
	Size     int64  `json:"size" jsonschema:"the file's actual size in bytes, even if content was omitted"`
	Encoding string `json:"encoding,omitempty" jsonschema:"utf8 or base64; omitted when content was not included"`
	Content  string `json:"content,omitempty"`
}

// getFunctionFilesIn is get_function_files' input.
type getFunctionFilesIn struct {
	Owner     string `json:"owner"`
	Name      string `json:"name"`
	VersionID string `json:"version_id,omitempty" jsonschema:"a specific version to inspect; omit for the active version"`
	File      string `json:"file,omitempty" jsonschema:"single-file mode: fetch only this one path's full content (use after a truncated listing)"`
}

// getFunctionFilesOut is get_function_files' output.
type getFunctionFilesOut struct {
	Files     []functionFileOut `json:"files"`
	Truncated bool              `json:"truncated,omitempty"`
	Note      string            `json:"note,omitempty"`
}

// getFunctionFilesHandler implements the "編集ループの起点" (§16.4.1): it
// requires deploy authorization (CanManage), same as deploy_function
// itself, since reading source is part of the same edit loop as writing
// it.
func (h *Handler) getFunctionFilesHandler(u *store.User) mcp.ToolHandlerFor[getFunctionFilesIn, getFunctionFilesOut] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in getFunctionFilesIn) (*mcp.CallToolResult, getFunctionFilesOut, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, getFunctionFilesOut{}, errors.New("owner and name are both required")
		}
		fn, err := h.api.ResolveVisible(ctx, u, in.Owner, in.Name)
		if err != nil {
			return nil, getFunctionFilesOut{}, toolError(err)
		}
		if err := h.api.Functions.CanManage(ctx, u, fn); err != nil {
			return nil, getFunctionFilesOut{}, toolError(err)
		}

		version, err := h.resolveVersion(ctx, fn, in.VersionID)
		if err != nil {
			return nil, getFunctionFilesOut{}, toolError(err)
		}
		files, err := h.unpackVersion(ctx, version)
		if err != nil {
			return nil, getFunctionFilesOut{}, err
		}

		if in.File != "" {
			data, ok := files[in.File]
			if !ok {
				return nil, getFunctionFilesOut{}, fmt.Errorf("file %q not found in this version", in.File)
			}
			return nil, getFunctionFilesOut{Files: []functionFileOut{fileEntry(in.File, data, true)}}, nil
		}

		paths := make([]string, 0, len(files))
		for p := range files {
			paths = append(paths, p)
		}
		sort.Strings(paths)

		out := getFunctionFilesOut{Files: make([]functionFileOut, 0, len(paths))}
		var used int64
		for _, p := range paths {
			data := files[p]
			include := used+int64(len(data)) <= getFunctionFilesBudget
			out.Files = append(out.Files, fileEntry(p, data, include))
			if include {
				used += int64(len(data))
			} else {
				out.Truncated = true
			}
		}
		if out.Truncated {
			out.Note = fmt.Sprintf(
				"response content is capped at %d bytes decoded; files beyond the budget are listed with path+size only -- fetch one specifically with input {\"file\": \"path\"}",
				getFunctionFilesBudget)
		}
		return nil, out, nil
	}
}

// fileEntry builds one functionFileOut for path/data. When includeContent
// is false, only Path/Size are set (get_function_files' truncated-listing
// shape). Content encoding is chosen per file: utf8 when data is valid
// UTF-8 text, base64 otherwise (binary).
func fileEntry(path string, data []byte, includeContent bool) functionFileOut {
	entry := functionFileOut{Path: path, Size: int64(len(data))}
	if !includeContent {
		return entry
	}
	if utf8.Valid(data) {
		entry.Encoding = "utf8"
		entry.Content = string(data)
	} else {
		entry.Encoding = "base64"
		entry.Content = base64.StdEncoding.EncodeToString(data)
	}
	return entry
}

// resolveVersion resolves versionID against fn (fn's active version if
// versionID is empty), refusing (NotFoundErr) a version that exists but
// belongs to a DIFFERENT function -- the version-ID namespace is global,
// so without this check a caller who can manage function A could probe
// function B's version IDs.
func (h *Handler) resolveVersion(ctx context.Context, fn *store.Function, versionID string) (*store.FunctionVersion, error) {
	if versionID == "" {
		if fn.ActiveVersionID == nil {
			return nil, service.NotFoundErr("function has no active version", nil)
		}
		versionID = *fn.ActiveVersionID
	}
	v, err := h.store.Functions().Version(ctx, versionID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, service.NotFoundErr("version not found", err)
		}
		return nil, service.Internal("failed to load version", err)
	}
	if v.FunctionID != fn.ID {
		return nil, service.NotFoundErr("version not found for this function", nil)
	}
	return v, nil
}

// unpackVersion fetches v's canonical bundle from blob storage and unpacks
// it with bundle.Unpack -- the SAME safe, streaming, size/file-count-bounded
// unpacker Deploy itself uses (never a naive tar/gzip read), per this
// tool's own safety requirement.
func (h *Handler) unpackVersion(ctx context.Context, v *store.FunctionVersion) (map[string][]byte, error) {
	r, err := h.blob.Get(ctx, service.BundleBlobKey(v.BundleHash))
	if err != nil {
		return nil, errors.New("failed to load this version's bundle from storage")
	}
	defer r.Close()
	files, err := bundle.Unpack(r)
	if err != nil {
		return nil, errors.New("failed to unpack this version's bundle")
	}
	return files, nil
}

// getFunctionLogsIn is get_function_logs' input.
type getFunctionLogsIn struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
	Since string `json:"since,omitempty" jsonschema:"pagination cursor from a previous call's next_cursor; omit for the first (newest) page"`
	Limit int    `json:"limit,omitempty" jsonschema:"max entries to return; server default applies if omitted or <= 0"`
}

// getFunctionLogsOut is get_function_logs' output.
type getFunctionLogsOut struct {
	Logs       []map[string]any `json:"logs"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

func (h *Handler) getFunctionLogsHandler(u *store.User) mcp.ToolHandlerFor[getFunctionLogsIn, getFunctionLogsOut] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in getFunctionLogsIn) (*mcp.CallToolResult, getFunctionLogsOut, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, getFunctionLogsOut{}, errors.New("owner and name are both required")
		}
		fn, err := h.api.ResolveVisible(ctx, u, in.Owner, in.Name)
		if err != nil {
			return nil, getFunctionLogsOut{}, toolError(err)
		}
		logs, next, err := h.api.ListInvocationLogs(ctx, fn, in.Since, in.Limit)
		if err != nil {
			return nil, getFunctionLogsOut{}, toolError(err)
		}
		dtos := make([]map[string]any, 0, len(logs))
		for _, l := range logs {
			dtos = append(dtos, api.InvocationLogDTO(l))
		}
		return nil, getFunctionLogsOut{Logs: dtos, NextCursor: next}, nil
	}
}

// rollbackFunctionIn is rollback_function's input.
type rollbackFunctionIn struct {
	Owner     string `json:"owner"`
	Name      string `json:"name"`
	VersionID string `json:"version_id" jsonschema:"the version to make active, as returned by get_function/get_function_logs/an earlier deploy_function call"`
}

func (h *Handler) rollbackFunctionHandler(u *store.User) mcp.ToolHandlerFor[rollbackFunctionIn, map[string]any] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in rollbackFunctionIn) (*mcp.CallToolResult, map[string]any, error) {
		if in.Owner == "" || in.Name == "" || in.VersionID == "" {
			return nil, nil, errors.New("owner, name, and version_id are all required")
		}
		fn, err := h.api.ResolveVisible(ctx, u, in.Owner, in.Name)
		if err != nil {
			return nil, nil, toolError(err)
		}
		if err := h.api.Functions.CanManage(ctx, u, fn); err != nil {
			return nil, nil, toolError(err)
		}
		fn, err = h.api.Functions.Activate(ctx, fn, in.VersionID)
		if err != nil {
			return nil, nil, toolError(err)
		}
		_ = auth.Audit(ctx, h.store, u.ID, "function.rollback", "function:"+fn.ID, map[string]any{"version_id": in.VersionID})
		return nil, h.api.FunctionDTO(ctx, fn, in.Owner), nil
	}
}

// deleteFunctionIn is delete_function's input.
type deleteFunctionIn struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// deleteFunctionOut is delete_function's output.
type deleteFunctionOut struct {
	Deleted bool `json:"deleted"`
}

func (h *Handler) deleteFunctionHandler(u *store.User) mcp.ToolHandlerFor[deleteFunctionIn, deleteFunctionOut] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in deleteFunctionIn) (*mcp.CallToolResult, deleteFunctionOut, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, deleteFunctionOut{}, errors.New("owner and name are both required")
		}
		fn, err := h.api.ResolveVisible(ctx, u, in.Owner, in.Name)
		if err != nil {
			return nil, deleteFunctionOut{}, toolError(err)
		}
		if err := h.api.Functions.CanManage(ctx, u, fn); err != nil {
			return nil, deleteFunctionOut{}, toolError(err)
		}
		if err := h.api.Functions.Delete(ctx, fn); err != nil {
			return nil, deleteFunctionOut{}, toolError(err)
		}
		_ = auth.Audit(ctx, h.store, u.ID, "function.delete", "function:"+fn.ID, map[string]any{"owner": in.Owner, "name": in.Name})
		return nil, deleteFunctionOut{Deleted: true}, nil
	}
}

// invokeFunctionIn is invoke_function's input.
type invokeFunctionIn struct {
	Owner        string            `json:"owner"`
	Name         string            `json:"name"`
	Method       string            `json:"method,omitempty" jsonschema:"HTTP method; defaults to GET"`
	Path         string            `json:"path,omitempty" jsonschema:"request path below the function root, e.g. \"/items/1\"; defaults to \"/\""`
	Query        map[string]string `json:"query,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Body         string            `json:"body,omitempty"`
	BodyEncoding string            `json:"body_encoding,omitempty" jsonschema:"\"utf8\" (default) or \"base64\""`
}

// invokeFunctionOut is invoke_function's output.
type invokeFunctionOut struct {
	Status       int               `json:"status"`
	Headers      map[string]string `json:"headers" jsonschema:"a subset of the response headers: content-type, content-length"`
	Body         string            `json:"body"`
	BodyEncoding string            `json:"body_encoding" jsonschema:"utf8 or base64"`
	Truncated    bool              `json:"truncated,omitempty" jsonschema:"true if the body was cut to the response cap"`
	DurationMS   int64             `json:"duration_ms"`
}

// invokeFunctionHandler dispatches the request through the exact same
// in-process pipeline server/internal/server's real HTTP invocation path
// (Deps.Invoker.Serve) uses, so visibility authorization, caller-identity
// header injection, execution logging, and metrics all behave exactly as
// they would for a normal HTTP invocation -- see buildInvokeRequest for
// how the actor's identity is carried through. A visibility denial (401,
// 403) is not a tool-level error: it's the function's own response,
// returned in "status" exactly like a real HTTP call would produce, so an
// agent can distinguish "denied" from "tool call itself failed".
func (h *Handler) invokeFunctionHandler(u *store.User) mcp.ToolHandlerFor[invokeFunctionIn, invokeFunctionOut] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in invokeFunctionIn) (*mcp.CallToolResult, invokeFunctionOut, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, invokeFunctionOut{}, errors.New("owner and name are both required")
		}
		req, err := h.buildInvokeRequest(ctx, u, in)
		if err != nil {
			return nil, invokeFunctionOut{}, err
		}

		rec := httptest.NewRecorder()
		start := time.Now()
		h.invoker.Serve(rec, req, in.Owner, in.Name)
		duration := time.Since(start)

		fullLen := rec.Body.Len()
		body := rec.Body.Bytes()
		truncated := false
		if len(body) > invokeFunctionBodyCap {
			body = body[:invokeFunctionBodyCap]
			truncated = true
		}

		out := invokeFunctionOut{
			Status:     rec.Code,
			Headers:    map[string]string{"content-length": strconv.Itoa(fullLen)},
			Truncated:  truncated,
			DurationMS: duration.Milliseconds(),
		}
		if ct := rec.Header().Get("Content-Type"); ct != "" {
			out.Headers["content-type"] = ct
		}
		if utf8.Valid(body) {
			out.BodyEncoding = "utf8"
			out.Body = string(body)
		} else {
			out.BodyEncoding = "base64"
			out.Body = base64.StdEncoding.EncodeToString(body)
		}
		return nil, out, nil
	}
}

// buildInvokeRequest synthesizes an in-process *http.Request for
// invokeFunctionHandler, targeting "/{owner}/{name}{path}" -- the exact
// URL shape server/internal/server's real router builds for
// /{owner}/{func}[/...] before calling Invoker.Serve (see routes.go: "the
// guest sees the full ... URL, not a stripped subpath").
//
// Identity: u's own aud=mcp access token (the one this MCP call itself
// arrived on) is deliberately NOT forwarded -- internal/auth's
// ResolveInvokeCaller rejects any aud!="" bearer token outright (aud=mcp
// tokens are scoped to /mcp only). Instead this mints a fresh, short-lived,
// general-purpose (aud-less) access token for u via Auth.IssueAccessToken,
// exactly as if u had run `funcbox print-access-token` themselves, so the
// invoke pipeline authorizes and attributes the call as u -- "acting as
// the MCP actor" per this package's design doc.
func (h *Handler) buildInvokeRequest(ctx context.Context, u *store.User, in invokeFunctionIn) (*http.Request, error) {
	method := in.Method
	if method == "" {
		method = http.MethodGet
	}
	path := in.Path
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	target := "/" + in.Owner + "/" + in.Name + path
	if len(in.Query) > 0 {
		q := url.Values{}
		for k, v := range in.Query {
			q.Set(k, v)
		}
		target += "?" + q.Encode()
	}

	// A Go-nil io.Reader (the zero value) makes http.NewRequestWithContext
	// leave req.Body Go-nil too -- fine for a real client round trip
	// (net/http never dereferences it before sending), but Invoker.Serve is
	// called IN-PROCESS here, straight into the runtime's own request
	// handling (runtime/enginepool's worker.serve reads req.Body
	// unconditionally via io.ReadAll(http.MaxBytesReader(...))), which
	// panics on a Go-nil Body. http.NoBody is the well-defined "empty body"
	// reader every real net/http server request carries even for a
	// bodyless GET, so it's used here explicitly instead of leaving the
	// default nil.
	bodyReader := io.Reader(http.NoBody)
	if in.Body != "" {
		var data []byte
		switch in.BodyEncoding {
		case "", "utf8":
			data = []byte(in.Body)
		case "base64":
			decoded, err := decodeBase64(in.Body)
			if err != nil {
				return nil, errors.New("invalid base64 body")
			}
			data = decoded
		default:
			return nil, errors.New(`body_encoding must be "utf8" or "base64"`)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, target, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to build the invocation request: %w", err)
	}
	for k, v := range in.Headers {
		req.Header.Set(k, v)
	}
	if origin, err := url.Parse(h.cfg.ControlOrigin); err == nil {
		req.Host = origin.Host
	}

	token, _, err := h.auth.IssueAccessToken(ctx, u.ID, invokeTokenTTL)
	if err != nil {
		return nil, errors.New("failed to authenticate the synthesized invocation")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return req, nil
}

// decodeBase64 decodes s as standard base64, falling back to the
// unpadded/raw variant -- an agent-generated payload is just as likely to
// omit padding as include it, and both are unambiguous to decode.
func decodeBase64(s string) ([]byte, error) {
	if data, err := base64.StdEncoding.DecodeString(s); err == nil {
		return data, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}
