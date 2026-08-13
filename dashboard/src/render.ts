// render.ts: small shared helpers every route module uses to build a
// Page's common props and to carry a one-line flash message across a
// POST -> redirect -> GET mutation (this app's uniform pattern for every
// mutating form -- see routes/*.tsx) via a short-lived query parameter
// rather than server-side session state.
import type { API } from "./api";
import type { NavKey, PageProps } from "./components/layout";
import type { CallerClaims } from "./identity";

export async function baseProps(
	api: API,
	caller: CallerClaims,
	active: NavKey,
	title: string,
): Promise<Omit<PageProps, "children" | "crumb" | "flash">> {
	let orgName = "funcbox";
	try {
		const org = await api.getOrg();
		orgName = org.name || "funcbox";
	} catch {
		// A failed org lookup shouldn't block rendering the rest of the
		// page; the crumb/env badge just falls back to a generic label.
	}
	return { title, active, orgName, caller };
}

export function flashParam(kind: "notice" | "error", message: string): string {
	return `${kind}=${encodeURIComponent(message)}`;
}

export function flashFromQuery(query: (key: string) => string | undefined): PageProps["flash"] {
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
	if (loginError) return { kind: "error", message: `ログインに失敗しました: ${loginError}` };
	return null;
}

export function redirectWithFlash(base: string, kind: "notice" | "error", message: string): string {
	const sep = base.includes("?") ? "&" : "?";
	return `${base}${sep}${flashParam(kind, message)}`;
}
