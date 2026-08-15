// api.ts is the SSR-side client for funcbox's management API: it calls
// internalAPI, a privileged function this app (and only this app) imports
// from "funcbox:internal" (internal/dashboard wires it up -- see that
// package's internalapi.go), never a plain HTTP fetch back to funcbox
// itself -- so there is no self-loopback and no need to carry cookies into
// the guest.
//
// Every call also threads a callerToken: an opaque, HMAC-signed string the
// Go host mints per HTTP request from the dashboard's already-authenticated
// session and hands the guest via the X-Funcbox-Caller-Token request header
// (see server.tsx's middleware). internalAPI's Go side verifies it before
// trusting ANY identity claim -- this file just plumbs it through unchanged
// on every call, it never inspects or trusts its contents itself.
import { internalAPI } from "funcbox:internal";
import type {
	AuditLogDTO,
	DeployResultDTO,
	DeviceDTO,
	FunctionDTO,
	InvocationLogDTO,
	LoginRuleDTO,
	MeDTO,
	OrgDTO,
	OrgSettings,
	UserDTO,
	VersionDTO,
	WorkspaceDTO,
	WorkspaceSettings,
} from "./types";
import type { DashboardLanguage } from "./i18n";

interface RawResult {
	status: number;
	body: unknown;
}

export class APIError extends Error {
	status: number;
	code: string;
	constructor(status: number, code: string, message: string) {
		super(message);
		this.status = status;
		this.code = code;
		this.name = "APIError";
	}
}

async function call<T>(callerToken: string, method: string, path: string, body?: unknown): Promise<T> {
	const bodyJSON = body === undefined ? "" : JSON.stringify(body);
	const raw = await internalAPI(method, path, bodyJSON, callerToken);
	let parsed: RawResult;
	try {
		parsed = JSON.parse(raw) as RawResult;
	} catch (e) {
		throw new APIError(502, "bad_internal_response", `internalAPI returned unparseable JSON: ${String(e)}`);
	}
	if (parsed.status >= 400) {
		const errBody = parsed.body as { error?: { code?: string; message?: string } } | undefined;
		throw new APIError(
			parsed.status,
			errBody?.error?.code ?? "unknown",
			errBody?.error?.message ?? `internal API call failed with status ${parsed.status}`,
		);
	}
	return parsed.body as T;
}

// callNoContent is call's counterpart for endpoints that respond 204 No
// Content (DELETE, PUT env, ...), where there is no JSON body to decode.
async function callNoContent(callerToken: string, method: string, path: string, body?: unknown): Promise<void> {
	await call<unknown>(callerToken, method, path, body);
}

export class API {
	constructor(private callerToken: string) {}

	// --- me ---
	me(): Promise<MeDTO> {
		return call(this.callerToken, "GET", "/me");
	}
	updateUserID(userID: string): Promise<{ user_id: string }> {
		return call(this.callerToken, "PATCH", "/me", { user_id: userID });
	}
	updateLanguage(language: DashboardLanguage | null): Promise<MeDTO> {
		return call(this.callerToken, "PATCH", "/me", { language });
	}
	// --- CLI-login devices (§14.4) ---
	listDevices(): Promise<{ devices: DeviceDTO[] }> {
		return call(this.callerToken, "GET", "/me/devices");
	}
	deleteDevice(id: string): Promise<void> {
		return callNoContent(this.callerToken, "DELETE", `/me/devices/${encodeURIComponent(id)}`);
	}
	// authorizeCLILogin implements the dashboard's "funcbox CLI login"
	// approval page's Approve action: POST /api/v1/cli/authorize, session +
	// CSRF-protected like every other mutation here. Returns the one-time
	// code the page then hands off to the CLI's loopback listener by
	// redirecting the browser to `${redirect}?code=${code}`.
	authorizeCLILogin(redirect: string, challenge: string, name: string): Promise<{ code: string }> {
		return call(this.callerToken, "POST", "/cli/authorize", { redirect, challenge, name });
	}

	// --- functions ---
	listFunctions(owner?: string): Promise<{ functions: FunctionDTO[] }> {
		const qs = owner ? `?owner=${encodeURIComponent(owner)}` : "";
		return call(this.callerToken, "GET", `/functions${qs}`);
	}
	getFunction(owner: string, name: string): Promise<FunctionDTO> {
		return call(this.callerToken, "GET", `/functions/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`);
	}
	listVersions(owner: string, name: string): Promise<{ versions: VersionDTO[] }> {
		return call(this.callerToken, "GET", `/functions/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/versions`);
	}
	activateVersion(owner: string, name: string, versionID: string): Promise<FunctionDTO> {
		return call(
			this.callerToken,
			"POST",
			`/functions/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/versions/${encodeURIComponent(versionID)}/activate`,
		);
	}
	deleteFunction(owner: string, name: string): Promise<void> {
		return callNoContent(this.callerToken, "DELETE", `/functions/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`);
	}
	setEnv(owner: string, name: string, key: string, value: string): Promise<void> {
		return callNoContent(
			this.callerToken,
			"PUT",
			`/functions/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/env/${encodeURIComponent(key)}`,
			{ value },
		);
	}
	deleteEnv(owner: string, name: string, key: string): Promise<void> {
		return callNoContent(
			this.callerToken,
			"DELETE",
			`/functions/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/env/${encodeURIComponent(key)}`,
		);
	}
	listLogs(owner: string, name: string, limit?: number): Promise<{ logs: InvocationLogDTO[]; next_cursor: string }> {
		const qs = limit ? `?limit=${limit}` : "";
		return call(this.callerToken, "GET", `/functions/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/logs${qs}`);
	}

	// --- workspaces ---
	listWorkspaces(): Promise<{ workspaces: WorkspaceDTO[] }> {
		return call(this.callerToken, "GET", "/workspaces");
	}
	getWorkspace(workspaceID: string): Promise<WorkspaceDTO> {
		return call(this.callerToken, "GET", `/workspaces/${encodeURIComponent(workspaceID)}`);
	}
	createWorkspace(name: string): Promise<WorkspaceDTO> {
		return call(this.callerToken, "POST", "/workspaces", { name });
	}
	patchWorkspace(workspaceID: string, settings: WorkspaceSettings): Promise<WorkspaceDTO> {
		return call(this.callerToken, "PATCH", `/workspaces/${encodeURIComponent(workspaceID)}`, settings);
	}
	deleteWorkspace(workspaceID: string): Promise<void> {
		return callNoContent(this.callerToken, "DELETE", `/workspaces/${encodeURIComponent(workspaceID)}`);
	}
	putWorkspaceMember(workspaceID: string, userID: string, role: string): Promise<void> {
		return callNoContent(
			this.callerToken,
			"PUT",
			`/workspaces/${encodeURIComponent(workspaceID)}/members/${encodeURIComponent(userID)}`,
			{ role },
		);
	}
	deleteWorkspaceMember(workspaceID: string, userID: string): Promise<void> {
		return callNoContent(
			this.callerToken,
			"DELETE",
			`/workspaces/${encodeURIComponent(workspaceID)}/members/${encodeURIComponent(userID)}`,
		);
	}

	// --- org ---
	getOrg(): Promise<OrgDTO> {
		return call(this.callerToken, "GET", "/org");
	}
	patchOrg(settings: Partial<OrgSettings>): Promise<OrgDTO> {
		return call(this.callerToken, "PATCH", "/org", settings);
	}
	getLoginRules(): Promise<{ login_rules: LoginRuleDTO[] }> {
		return call(this.callerToken, "GET", "/org/login-rules");
	}
	putLoginRules(rules: Array<{ type: string; value: string; action: string }>): Promise<{ login_rules: LoginRuleDTO[] }> {
		return call(this.callerToken, "PUT", "/org/login-rules", { login_rules: rules });
	}
	listOrgUsers(): Promise<{ users: UserDTO[] }> {
		return call(this.callerToken, "GET", "/org/users");
	}
	patchOrgUser(id: string, patch: { role?: string; status?: string }): Promise<UserDTO> {
		return call(this.callerToken, "PATCH", `/org/users/${encodeURIComponent(id)}`, patch);
	}
	listAuditLogs(cursor?: string, limit?: number): Promise<{ audit_logs: AuditLogDTO[]; next_cursor: string }> {
		const params = new URLSearchParams();
		if (cursor) params.set("cursor", cursor);
		if (limit) params.set("limit", String(limit));
		const qs = params.toString();
		return call(this.callerToken, "GET", `/org/audit-logs${qs ? "?" + qs : ""}`);
	}
}

export type { DeployResultDTO };
