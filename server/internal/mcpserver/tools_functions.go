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
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/goccy/go-yaml"
	"github.com/google/jsonschema-go/jsonschema"
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
	}, h.listFunctionsHandler())

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_function",
		Description: "Get a function's metadata, active version, effective fetch policy (organization/workspace/manifest three-tier view), and declared env var KEY NAMES (never values -- use the dashboard or REST API to read/set env var values).",
	}, h.getFunctionHandler())

	mcp.AddTool(server, &mcp.Tool{
		Name: "deploy_function",
		Description: "Deploy a function from a file map (source files, optionally including funcbox.yaml), the AI-agent deploy loop's centerpiece. " +
			"Prefer the typed \"manifest\" parameter over hand-writing a funcbox.yaml file -- its shape is fully documented in this tool's own input schema. " +
			"Files are packed into a canonical bundle and go through the exact same validation, limits, and audit trail as a normal deploy. " +
			"dry_run validates without persisting. Large bundles (node_modules, etc.) are rejected with a hint to use the funcbox CLI instead.",
		InputSchema: deployFunctionInputSchema(),
	}, h.deployFunctionHandler())

	if h.blob != nil {
		mcp.AddTool(server, &mcp.Tool{
			Name: "get_function_files",
			Description: "Fetch a version's source files (active version by default, or a specific version_id). " +
				"Text files are returned as utf8, binary as base64. Large listings are capped by a total response budget: " +
				"once exceeded, remaining files are listed by path+size only -- fetch one specifically with input {\"file\": \"path\"}.",
		}, h.getFunctionFilesHandler())
	}

	if h.invoker != nil {
		mcp.AddTool(server, &mcp.Tool{
			Name: "invoke_function",
			Description: "Invoke a deployed function as yourself, through the exact same pipeline a real HTTP request uses " +
				"(visibility authorization, caller identity, execution logging, metrics). Useful to verify a deploy worked. " +
				"Response body is capped; oversized bodies are truncated (see \"truncated\").",
		}, h.invokeFunctionHandler())
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_function_logs",
		Description: "List a function's recent execution logs (newest first, paged via next_cursor).",
	}, h.getFunctionLogsHandler())

	mcp.AddTool(server, &mcp.Tool{
		Name:        "rollback_function",
		Description: "Activate a previously deployed version of a function (rollback or roll-forward).",
	}, h.rollbackFunctionHandler())

	mcp.AddTool(server, &mcp.Tool{
		Name:        "delete_function",
		Description: "Permanently delete a function and every one of its versions.",
	}, h.deleteFunctionHandler())
}

// listFunctionsIn is list_functions' input.
type listFunctionsIn struct {
	Owner string `json:"owner,omitempty" jsonschema:"optional: restrict the list to this owner (a public User ID or workspace ID); omit to list everything visible to you"`
}

// listFunctionsOut is list_functions' output.
type listFunctionsOut struct {
	Functions []map[string]any `json:"functions"`
}

func (h *Handler) listFunctionsHandler() mcp.ToolHandlerFor[listFunctionsIn, listFunctionsOut] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in listFunctionsIn) (*mcp.CallToolResult, listFunctionsOut, error) {
		u, err := h.requireActor(ctx, req)
		if err != nil {
			return nil, listFunctionsOut{}, err
		}
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

func (h *Handler) getFunctionHandler() mcp.ToolHandlerFor[getFunctionIn, map[string]any] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in getFunctionIn) (*mcp.CallToolResult, map[string]any, error) {
		u, err := h.requireActor(ctx, req)
		if err != nil {
			return nil, nil, err
		}
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
	Owner    string            `json:"owner" jsonschema:"the public User ID or workspace ID to deploy under"`
	Name     string            `json:"name,omitempty" jsonschema:"function name; omit to use the manifest's own \"name\" field (the two must agree if both are present)"`
	Note     string            `json:"note,omitempty" jsonschema:"optional deploy note, shown alongside this version in the dashboard"`
	DryRun   bool              `json:"dry_run,omitempty" jsonschema:"validate only (manifest, limits, policy warnings) without persisting anything"`
	Files    []deployFileIn    `json:"files" jsonschema:"the function's full file set, e.g. index.js + any other source/asset files -- NOT a diff against a previous version"`
	Manifest *deployManifestIn `json:"manifest,omitempty" jsonschema:"the function's funcbox.yaml settings, typed instead of a hand-written YAML file -- the recommended way to configure a deploy. Do not ALSO include a funcbox.yaml/funcbox.yml/funcbox.json in files[]; provide exactly one of the two. Omit any sub-field you don't need to set; omitted fields keep their normal default."`
}

// deployManifestIn is deploy_function's typed mirror of a funcbox.yaml
// manifest file (manifest/parse.go's own rawManifest, minus "owner" --
// deploy_function's own top-level "owner" argument is authoritative for
// that; a manifest-level owner isn't exposed here). deployFunctionHandler
// serializes a caller-supplied value of this type to canonical YAML (see
// toYAML) and injects it into the bundle as "funcbox.yaml" before packing,
// so it goes through the exact same manifest.Parse -> manifest.Validate
// path as a hand-written file -- this type never duplicates or bypasses
// that validation.
//
// Every field is optional and every group (Compat, Permissions) is a
// pointer, so a caller can supply just the fields they care about: an
// absent field is omitted from the generated YAML entirely (via its
// yaml:"...,omitempty" tag), leaving manifest.Parse's own default
// resolution (e.g. main's index.js/index.mjs search, deny-all fetch) exactly
// as it would behave for a funcbox.yaml that never mentioned the field.
type deployManifestIn struct {
	Name        string   `json:"name,omitempty" yaml:"name,omitempty" jsonschema:"function name, DNS-label form (lowercase letters, digits, hyphens); must agree with deploy_function's own top-level \"name\" argument if both are given"`
	Main        string   `json:"main,omitempty" yaml:"main,omitempty" jsonschema:"entry module path within the bundle, e.g. \"index.js\"; if omitted, \"index.js\" then \"index.mjs\" are tried in that order"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty" jsonschema:"human-readable description of the function"`
	Timeout     string   `json:"timeout,omitempty" yaml:"timeout,omitempty" jsonschema:"invocation timeout as a Go duration string, e.g. \"10s\""`
	Memory      string   `json:"memory,omitempty" yaml:"memory,omitempty" jsonschema:"instance memory limit as a byte size, e.g. \"128MiB\""`
	Env         []string `json:"env,omitempty" yaml:"env,omitempty" jsonschema:"declared environment variable KEY NAMES only (readable in the guest via import.meta.env); this never carries values -- set values separately via the dashboard or REST API, they are never sent through MCP"`
	// Visibility's allowed values (public, org, workspace) are enforced by
	// this tool's explicit input schema (see deployFunctionInputSchema),
	// since the jsonschema struct tag has no enum syntax -- kept here in
	// the description too so the value list stays visible even if a client
	// only surfaces field descriptions.
	Visibility  string                       `json:"visibility,omitempty" yaml:"visibility,omitempty" jsonschema:"function visibility: one of \"public\", \"org\", \"workspace\""`
	Compat      *deployManifestCompatIn      `json:"compat,omitempty" yaml:"compat,omitempty" jsonschema:"Node.js compatibility settings"`
	Permissions *deployManifestPermissionsIn `json:"permissions,omitempty" yaml:"permissions,omitempty" jsonschema:"outbound network permission settings"`
}

// deployManifestCompatIn is deployManifestIn's compat.* group.
type deployManifestCompatIn struct {
	Nodejs bool `json:"nodejs,omitempty" yaml:"nodejs,omitempty" jsonschema:"enable node: core modules and node_modules resolution"`
}

// deployManifestPermissionsIn is deployManifestIn's permissions.* group.
type deployManifestPermissionsIn struct {
	Fetch *deployManifestFetchIn `json:"fetch,omitempty" yaml:"fetch,omitempty" jsonschema:"outbound fetch (network) permission"`
}

// deployManifestFetchIn is deployManifestIn's permissions.fetch.* group.
type deployManifestFetchIn struct {
	// Mode's allowed values (deny, allowlist, allow-all) are likewise
	// enforced by the explicit input schema -- see the Visibility comment
	// above.
	Mode  string   `json:"mode,omitempty" yaml:"mode,omitempty" jsonschema:"fetch permission mode: one of \"deny\", \"allowlist\", \"allow-all\""`
	Allow []string `json:"allow,omitempty" yaml:"allow,omitempty" jsonschema:"host patterns permitted when mode is \"allowlist\": an exact host, a \"*.example.com\" wildcard, optionally suffixed with \":port\""`
}

// toYAML serializes m to canonical funcbox.yaml bytes, emitting only the
// fields the caller actually set -- see deployManifestIn's own doc comment
// for why every field is built to omit itself when absent.
func (m *deployManifestIn) toYAML() ([]byte, error) {
	return yaml.Marshal(m)
}

// manifestFileNames lists the manifest filenames manifest.Parse itself
// recognizes (see manifest/parse.go's own unexported manifestFilenames,
// kept in exact sync with that list -- it isn't exported, and this
// package's scope doesn't include changing the manifest package). Used only
// to detect, ahead of packing, whether files[] already supplies a manifest
// file that would conflict with a typed "manifest" argument.
var manifestFileNames = []string{"funcbox.yaml", "funcbox.yml", "funcbox.json"}

// conflictingManifestFile reports the first manifestFileNames entry present
// in files, if any.
func conflictingManifestFile(files map[string][]byte) (string, bool) {
	for _, name := range manifestFileNames {
		if _, ok := files[name]; ok {
			return name, true
		}
	}
	return "", false
}

// deployFunctionInputSchemaOnce/-Value cache deployFunctionInputSchema's
// result: registerFunctionsTools (and thus this schema build) runs once per
// MCP session, but deployFunctionIn's reflected schema is invariant, so
// every session shares the same *jsonschema.Schema value -- built once,
// never mutated afterward (mcp.Server.AddTool's own doc comment: "The Tool
// argument must not be modified after this call", which this satisfies by
// construction since only a fresh *mcp.Tool wrapper is built per session,
// never the schema it points to).
var (
	deployFunctionInputSchemaOnce  sync.Once
	deployFunctionInputSchemaValue *jsonschema.Schema
)

// deployFunctionInputSchema builds deploy_function's input schema by
// reflecting over deployFunctionIn (exactly what mcp.AddTool would infer on
// its own), then patching in `enum` constraints for the two fields whose
// values are restricted to a fixed set (manifest.visibility,
// manifest.permissions.fetch.mode) -- the jsonschema struct tag this
// package otherwise relies on (see every other jsonschema:"..." tag in this
// file) has no enum syntax; the whole tag string is used verbatim as the
// property's description (github.com/google/jsonschema-go/jsonschema's
// infer.go: a jsonschema tag "is used as the description for the
// corresponding property", full stop). Pre-populating Tool.InputSchema like
// this makes mcp.AddTool use it as-is instead of inferring one (see
// mcp.Server.AddTool's doc comment), so every other field here still gets
// its normal struct-tag-inferred schema -- only these two leaf schemas are
// touched.
func deployFunctionInputSchema() *jsonschema.Schema {
	deployFunctionInputSchemaOnce.Do(func() {
		schema, err := jsonschema.For[deployFunctionIn](nil)
		if err != nil {
			// deployFunctionIn is a fixed, package-local type; a failure here
			// is a programming error (an unsupported field type), not a
			// runtime condition -- fail loudly rather than register a tool
			// with a silently incomplete schema.
			panic(fmt.Errorf("mcpserver: build deploy_function input schema: %w", err))
		}

		manifestSchema := schema.Properties["manifest"]
		if manifestSchema == nil {
			panic("mcpserver: deploy_function input schema has no \"manifest\" property")
		}
		visibilitySchema := manifestSchema.Properties["visibility"]
		if visibilitySchema == nil {
			panic("mcpserver: deploy_function input schema has no \"manifest.visibility\" property")
		}
		visibilitySchema.Enum = []any{"public", "org", "workspace"}

		permissionsSchema := manifestSchema.Properties["permissions"]
		if permissionsSchema == nil {
			panic("mcpserver: deploy_function input schema has no \"manifest.permissions\" property")
		}
		fetchSchema := permissionsSchema.Properties["fetch"]
		if fetchSchema == nil {
			panic("mcpserver: deploy_function input schema has no \"manifest.permissions.fetch\" property")
		}
		modeSchema := fetchSchema.Properties["mode"]
		if modeSchema == nil {
			panic("mcpserver: deploy_function input schema has no \"manifest.permissions.fetch.mode\" property")
		}
		modeSchema.Enum = []any{"deny", "allowlist", "allow-all"}

		deployFunctionInputSchemaValue = schema
	})
	return deployFunctionInputSchemaValue
}

// deployFunctionOut is deploy_function's output.
type deployFunctionOut struct {
	URL       string   `json:"url,omitempty" jsonschema:"the deployed function's invocation URL (omitted for a dry run)"`
	VersionID string   `json:"version_id,omitempty" jsonschema:"the newly created version's ID (omitted for a dry run)"`
	Warnings  []string `json:"warnings"`
	DryRun    bool     `json:"dry_run"`
}

func (h *Handler) deployFunctionHandler() mcp.ToolHandlerFor[deployFunctionIn, deployFunctionOut] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in deployFunctionIn) (*mcp.CallToolResult, deployFunctionOut, error) {
		u, err := h.requireActor(ctx, req)
		if err != nil {
			return nil, deployFunctionOut{}, err
		}
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

		if in.Manifest != nil {
			if conflict, ok := conflictingManifestFile(files); ok {
				return nil, deployFunctionOut{}, fmt.Errorf(
					"provide exactly one of the typed \"manifest\" parameter or a manifest file in files[] -- both %q and \"manifest\" were given",
					conflict)
			}
			manifestYAML, err := in.Manifest.toYAML()
			if err != nil {
				return nil, deployFunctionOut{}, fmt.Errorf("failed to encode the \"manifest\" parameter: %w", err)
			}
			files["funcbox.yaml"] = manifestYAML
			totalSize += int64(len(manifestYAML))
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
			return nil, deployFunctionOut{}, deployToolError(err, in.Manifest != nil)
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

// deployToolError wraps toolError with a small, in-scope hint for the exact
// mistake the typed "manifest" parameter exists to prevent: a manifest file
// supplied via files[] that fails to parse (bad YAML syntax, or an unknown
// field manifest.Parse's own yaml.DisallowUnknownField rejects -- both come
// back with service.Error.Code == "manifest_parse_error", see
// server/internal/service/deploy.go's mapManifestErr). usedTypedManifest
// suppresses the hint when the caller already used the typed route (where
// this class of mistake -- guessing an unknown field name -- can't happen,
// since the SDK-generated schema documents every field).
func deployToolError(err error, usedTypedManifest bool) error {
	if !usedTypedManifest {
		if svcErr, ok := service.AsError(err); ok && svcErr.Code == "manifest_parse_error" {
			return fmt.Errorf("%s -- consider using deploy_function's typed \"manifest\" parameter instead of a hand-written funcbox.yaml file to avoid this class of mistake", svcErr.Message)
		}
	}
	return toolError(err)
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
func (h *Handler) getFunctionFilesHandler() mcp.ToolHandlerFor[getFunctionFilesIn, getFunctionFilesOut] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in getFunctionFilesIn) (*mcp.CallToolResult, getFunctionFilesOut, error) {
		u, err := h.requireActor(ctx, req)
		if err != nil {
			return nil, getFunctionFilesOut{}, err
		}
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

func (h *Handler) getFunctionLogsHandler() mcp.ToolHandlerFor[getFunctionLogsIn, getFunctionLogsOut] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in getFunctionLogsIn) (*mcp.CallToolResult, getFunctionLogsOut, error) {
		u, err := h.requireActor(ctx, req)
		if err != nil {
			return nil, getFunctionLogsOut{}, err
		}
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

func (h *Handler) rollbackFunctionHandler() mcp.ToolHandlerFor[rollbackFunctionIn, map[string]any] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in rollbackFunctionIn) (*mcp.CallToolResult, map[string]any, error) {
		u, err := h.requireActor(ctx, req)
		if err != nil {
			return nil, nil, err
		}
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

func (h *Handler) deleteFunctionHandler() mcp.ToolHandlerFor[deleteFunctionIn, deleteFunctionOut] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in deleteFunctionIn) (*mcp.CallToolResult, deleteFunctionOut, error) {
		u, err := h.requireActor(ctx, req)
		if err != nil {
			return nil, deleteFunctionOut{}, err
		}
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
func (h *Handler) invokeFunctionHandler() mcp.ToolHandlerFor[invokeFunctionIn, invokeFunctionOut] {
	return func(ctx context.Context, mcpReq *mcp.CallToolRequest, in invokeFunctionIn) (*mcp.CallToolResult, invokeFunctionOut, error) {
		u, err := h.requireActor(ctx, mcpReq)
		if err != nil {
			return nil, invokeFunctionOut{}, err
		}
		if in.Owner == "" || in.Name == "" {
			return nil, invokeFunctionOut{}, errors.New("owner and name are both required")
		}
		httpReq, err := h.buildInvokeRequest(ctx, u, in)
		if err != nil {
			return nil, invokeFunctionOut{}, err
		}

		// Finding 3: rec bounds how much of the guest's response body it will
		// ever hold in memory to invokeFunctionBodyCap bytes -- see
		// boundedInvokeRecorder's own doc comment for why this replaces the
		// previous httptest.NewRecorder(), whose bytes.Buffer grew without
		// bound for the FULL response before this tool's own truncation step
		// ever ran.
		rec := newBoundedInvokeRecorder(invokeFunctionBodyCap)
		start := time.Now()
		h.invoker.Serve(rec, httpReq, in.Owner, in.Name)
		duration := time.Since(start)

		body := rec.body.Bytes()
		out := invokeFunctionOut{
			Status:     rec.status,
			Headers:    map[string]string{"content-length": strconv.Itoa(rec.total)},
			Truncated:  rec.truncated(),
			DurationMS: duration.Milliseconds(),
		}
		if ct := rec.header.Get("Content-Type"); ct != "" {
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

// boundedInvokeRecorder is an http.ResponseWriter used by invokeFunctionHandler
// to capture a guest function's response without ever buffering more than
// cap bytes of body -- unlike httptest.ResponseRecorder (this tool's
// previous implementation), whose bytes.Buffer grows to hold the ENTIRE
// response before invoke_function's own truncation step (previously a
// post-hoc slice after the fact) had any effect, letting a guest that
// writes many megabytes (or streams indefinitely) exhaust server memory
// well before the response ever reached that cap. Every byte past cap is
// counted (via total) but discarded immediately rather than retained, so
// this recorder's own memory use is bounded by cap regardless of how much
// the guest actually writes.
type boundedInvokeRecorder struct {
	header    http.Header
	status    int
	wroteHead bool
	body      bytes.Buffer // holds at most cap bytes
	cap       int
	total     int // total bytes the guest wrote, even past cap
}

// newBoundedInvokeRecorder returns a ready-to-use boundedInvokeRecorder that
// retains at most cap bytes of body. status defaults to http.StatusOK,
// matching both net/http's own ResponseWriter contract (an implicit 200 if
// WriteHeader is never called) and httptest.NewRecorder's prior default.
func newBoundedInvokeRecorder(cap int) *boundedInvokeRecorder {
	return &boundedInvokeRecorder{header: make(http.Header), cap: cap, status: http.StatusOK}
}

func (r *boundedInvokeRecorder) Header() http.Header { return r.header }

func (r *boundedInvokeRecorder) WriteHeader(status int) {
	if r.wroteHead {
		return
	}
	r.wroteHead = true
	r.status = status
}

// Write retains up to cap total bytes of body (across every call) and
// discards the rest, but always reports every byte as accepted -- mirroring
// net/http's own ResponseWriter contract, where Write never returns fewer
// bytes than len(p) without a non-nil error, and never erroring the guest's
// own write just because this recorder's retention cap was reached.
func (r *boundedInvokeRecorder) Write(p []byte) (int, error) {
	if !r.wroteHead {
		r.WriteHeader(http.StatusOK)
	}
	r.total += len(p)
	if room := r.cap - r.body.Len(); room > 0 {
		if room > len(p) {
			room = len(p)
		}
		r.body.Write(p[:room])
	}
	return len(p), nil
}

// truncated reports whether the guest wrote more than cap bytes, i.e.
// whether body holds less than the guest actually produced.
func (r *boundedInvokeRecorder) truncated() bool {
	return r.total > r.cap
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
