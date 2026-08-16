// types.ts declares the JSON shapes the management API returns
// hand since the dashboard has no code-generation step from the Go side.

export interface FetchPolicyDTO {
	mode: "deny" | "allowlist" | "allow-all" | string;
	allow?: string[];
}

export interface NormalizedManifest {
	source?: string;
	name: string;
	owner?: string;
	main?: string;
	description?: string;
	timeout?: string;
	memory?: number;
	compat: { nodejs: boolean };
	permissions: { fetch: FetchPolicyDTO };
	env?: string[];
	visibility?: string;
}

export interface BundleFileDTO {
	path: string;
	size: number;
}

export interface VersionDTO {
	id: string;
	main_path: string;
	bundle_hash: string;
	bundle_size: number;
	unpacked_size: number;
	files: BundleFileDTO[];
	manifest: NormalizedManifest;
	note: string;
	created_at: string;
}

export interface FetchPolicyLevels {
	organization: FetchPolicyDTO;
	workspace: FetchPolicyDTO | null;
}

export interface FunctionDTO {
	id: string;
	owner_type: "user" | "workspace";
	name: string;
	url?: string;
	description: string;
	owner?: string;
	active_version_id?: string;
	active_version?: VersionDTO;
	fetch_policy_levels?: FetchPolicyLevels;
	created_at: string;
	updated_at: string;
}

export interface OrgLimits {
	invoke_timeout_max?: string;
	memory_max?: number;
	bundle_unpacked_max?: number;
}

export interface OrgSettings {
	// Dashboard display language selected by organization administrators.
	// The API always returns one of these values; older servers may omit it,
	// in which case the dashboard falls back to English.
	language?: "en" | "ja";
	allow_user_functions: boolean;
	allow_nodejs_compat: boolean;
	default_visibility: string;
	max_visibility: string;
	fetch_policy: FetchPolicyDTO;
	limits: OrgLimits;
	extra_id_token_audiences?: string[];
	session_duration_seconds?: number;
	// require_approval: new (non-bootstrap) accounts are created pending
	// until an org admin approves them (§13.3).
	require_approval: boolean;
	// max_functions_per_user: cap on personal-scope functions owned by a
	// single user, installation-wide. 0/unset = unlimited (§13.4).
	max_functions_per_user?: number;
	// open_mode: public registration posture (§13.1). When true, the
	// dashboard function list narrows to the caller's own functions, the
	// workspace feature is hidden/disabled entirely, and the invoke path
	// stops injecting X-Funcbox-Caller-* headers unless
	// expose_caller_identity opts back in.
	open_mode: boolean;
	// expose_caller_identity: re-enables X-Funcbox-Caller-Email injection
	// while open_mode is on. No effect when open_mode is false (normal
	// mode always injects it).
	expose_caller_identity: boolean;
	// mcp_enabled: whether MCP (Model Context Protocol) clients may
	// connect to this organization's /mcp endpoint. Unlike the other
	// booleans above, this defaults to true -- an organization that has
	// never touched this setting still has MCP access enabled.
	mcp_enabled: boolean;
}

export interface OrgDTO {
	name: string;
	settings: OrgSettings;
	settings_gen: number;
	// open_mode_just_enabled: present (true) only on the PATCH /org
	// response that just flipped open_mode from false to true -- the
	// dashboard uses it to show a one-time notice that existing login
	// rules were left unchanged and still apply (§13.1: "既存の login
	// rules を黙って書き換えない").
	open_mode_just_enabled?: boolean;
}

export interface WorkspaceSettings {
	fetch_policy: FetchPolicyDTO;
	default_visibility?: string;
	max_visibility?: string;
	member_can_deploy: boolean;
	// max_functions_per_member: cap on functions a single member may CREATE
	// within this workspace. 0/unset = unlimited (§13.4).
	max_functions_per_member?: number;
}

export interface WorkspaceMemberDTO {
	user_id: string;
	role: "admin" | "member" | string;
}

export interface WorkspaceDTO {
	id: string;
	name: string;
	settings: WorkspaceSettings;
	settings_gen: number;
	created_at: string;
	members?: WorkspaceMemberDTO[];
}

export interface MeWorkspace {
	id: string;
	name: string;
	// Present only when this workspace has a max_functions_per_member limit
	// (§13.4): the caller's own current per-creator count and that limit.
	function_count?: number;
	function_limit?: number;
}

export interface MeDTO {
	id: string;
	email: string;
	name: string;
	user_id: string;
	role: "admin" | "workspace_manager" | "member" | string;
	workspaces: MeWorkspace[];
	// null means inherit the organization language. effective_language is
	// resolved by the API as personal > organization > English.
	language?: "en" | "ja" | null;
	effective_language?: "en" | "ja";
	// Present only when the organization has a max_functions_per_user limit
	// (§13.4): the caller's own current personal-scope function count.
	personal_function_count?: number;
	personal_function_limit?: number;
	// Present only for an admin caller: the number of users currently
	// awaiting approval (§13.3), for the nav's pending-requests badge.
	pending_approval_count?: number;
}

export interface LoginRuleDTO {
	id: string;
	ord: number;
	type: "email_domain" | "email_exact" | "email_glob" | "default" | string;
	value: string;
	action: "allow" | "deny" | string;
}

export interface UserDTO {
	id: string;
	email: string;
	name: string;
	role: "admin" | "workspace_manager" | "member" | string;
	status: "active" | "pending" | "disabled" | string;
	created_at: string;
}

export interface FetchDecisionDTO {
	host: string;
	port?: number;
	allowed: boolean;
	stage: "resolve" | "dial" | string;
}

export interface InvocationLogDTO {
	id: string;
	version_id: string;
	method: string;
	path: string;
	status: number;
	duration_ms: number;
	stdout: string;
	stderr: string;
	fetch_decisions: FetchDecisionDTO[] | null;
	created_at: string;
}

export interface AuditLogDTO {
	id: string;
	actor_id: string;
	action: string;
	target: string;
	detail: unknown;
	created_at: string;
}

// DeviceDTO is a connected CLI-login device (cli_credentials) OR a
// connected OAuth app grant (an MCP client's connection, minted by the
// OAuth 2.1 authorization-code flow -- server/internal/oauth), as returned
// by GET /api/v1/me/devices (server/internal/api/me.go's DeviceInfo).
// `kind` distinguishes the two ("cli" | "oauth"); for "oauth" entries,
// `name` is the OAuth client's registered name, falling back to its
// client_id if unnamed. Neither kind ever carries the credential secret
// itself -- a "cli" secret is shown exactly once, by the CLI, at `funcbox
// login` time; an "oauth" grant's tokens never round-trip through the
// dashboard at all.
export interface DeviceDTO {
	id: string;
	kind: "cli" | "oauth";
	name: string;
	created_at: string;
	last_used_at: string | null;
}

export interface DeployResultDTO {
	dry_run: boolean;
	manifest?: NormalizedManifest;
	warnings: string[];
	function?: FunctionDTO;
	version?: VersionDTO;
}

export interface APIErrorBody {
	error: { code: string; message: string };
}
