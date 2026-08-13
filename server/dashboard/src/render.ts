// render.ts: small shared helpers every route module uses to build a
// Page's common props and to carry a one-line flash message across a
// POST -> redirect -> GET mutation (this app's uniform pattern for every
// mutating form -- see routes/*.tsx) via a short-lived query parameter
// rather than server-side session state.
import type { API } from "./api";
import type { NavKey, PageProps } from "./components/layout";
import type { CallerClaims } from "./identity";
import { translator, type DashboardLanguage } from "./i18n";

export async function baseProps(
	api: API,
	caller: CallerClaims,
	active: NavKey,
	title: string,
): Promise<Omit<PageProps, "children" | "crumb" | "flash">> {
	let orgName = "funcbox";
	let language: DashboardLanguage = "en";
	// pendingCount (§13.3's nav badge) rides along on the SAME api.me() call
	// baseProps already makes for language resolution -- me() only returns
	// pending_approval_count for an admin caller (see internal/api's
	// handleMeGet), so this is undefined (no badge) for anyone else.
	let pendingCount: number | undefined;
	try {
		const [org, me] = await Promise.all([api.getOrg(), api.me()]);
		orgName = org.name || "funcbox";
		// Prefer the API-resolved value. The explicit fallback maintains the
		// documented priority for a rolling upgrade with an older API server.
		language = me.effective_language ?? me.language ?? org.settings.language ?? "en";
		pendingCount = me.pending_approval_count;
	} catch {
		// A failed org lookup shouldn't block rendering the rest of the
		// page; the crumb/env badge just falls back to a generic label.
	}
	const t = translator(language);
	const titleKey: Record<string, string> = {
		Functions: "functions", Workspaces: "workspaces", "Organization settings": "org_settings", Users: "users",
		"Audit logs": "audit_logs", "Personal settings": "personal_settings", "New deployment": "new_deploy", "Function not found": "function_not_found",
	};
	return { title: titleKey[title] ? t(titleKey[title]) : title, active, orgName, caller, language, t, pendingCount };
}

export function flashParam(kind: "notice" | "error", message: string): string {
	return `${kind}=${encodeURIComponent(message)}`;
}

export function flashFromQuery(query: (key: string) => string | undefined, language: DashboardLanguage = "en"): PageProps["flash"] {
	const t = translator(language);
	const notice = query("notice");
	if (notice) return { kind: "notice", message: notice };
	const error = query("error");
	if (error) return { kind: "error", message: error };
	// login_error is set by internal/auth's /auth/callback on a failed
	// sign-in (it redirects to defaultReturnTo="/dashboard" with this
	// query param, since /auth/* has no HTML templates of its own -- see
	// login.go's loginFailed doc comment); surfaced here as an ordinary
	// error flash on whichever page happens to be "/dashboard" itself.
	const loginError = query("login_error");
	if (loginError) return { kind: "error", message: t("login_failed", { error: loginError }) };
	return null;
}

export function redirectWithFlash(base: string, kind: "notice" | "error", message: string): string {
	const sep = base.includes("?") ? "&" : "?";
	return `${base}${sep}${flashParam(kind, message)}`;
}

// Mutations redirect before the next GET can build Page props. Resolve the
// same API-owned effective language here so success notices match the page
// reached after the redirect.
export async function localizedMessage(api: API, key: string, vars?: Record<string, string | number>): Promise<string> {
	try {
		const me = await api.me();
		return translator(me.effective_language ?? me.language ?? "en")(key, vars);
	} catch {
		return translator("en")(key, vars);
	}
}
