// types.ts declares the JSON shapes the management API returns
// (internal/api's *DTO functions -- tmp/07-http-api.md §7.3), mirrored by
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
	allow_user_functions: boolean;
	allow_workspace_creation: boolean;
	allow_nodejs_compat: boolean;
	default_visibility: string;
	max_visibility: string;
	fetch_policy: FetchPolicyDTO;
	limits: OrgLimits;
	extra_id_token_audiences?: string[];
	session_duration_seconds?: number;
}

export interface OrgDTO {
	name: string;
	settings: OrgSettings;
	settings_gen: number;
}

export interface WorkspaceSettings {
	fetch_policy: FetchPolicyDTO;
	default_visibility?: string;
	max_visibility?: string;
	member_can_deploy: boolean;
}

export interface WorkspaceMemberDTO {
	user_id: string;
	role: "admin" | "member" | string;
}

export interface WorkspaceDTO {
	id: string;
	handle: string;
	name: string;
	settings: WorkspaceSettings;
	settings_gen: number;
	created_at: string;
	members?: WorkspaceMemberDTO[];
}

export interface MeWorkspace {
	id: string;
	handle: string;
	name: string;
}

export interface MeDTO {
	id: string;
	email: string;
	name: string;
	handle: string;
	role: "admin" | "member" | string;
	workspaces: MeWorkspace[];
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
	role: "admin" | "member" | string;
	disabled: boolean;
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

export interface TokenDTO {
	id: string;
	name: string;
	expires_at: string;
	created_at: string;
	token?: string; // present only in the create response
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
