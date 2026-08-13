// routes/cliAuth.tsx: /dashboard/cli-auth, the explicit "funcbox CLI
// login" approval page (§14.4 of tmp/14-auth-and-pool-improvements.md).
//
// This route is reached ONLY via `funcbox login`'s loopback+PKCE flow: the
// CLI opens the browser at
//   /dashboard/cli-auth?redirect=http://127.0.0.1:{port}/callback&challenge={S256}&name={hostname}
// Like every other /dashboard/* route, internal/dashboard's Go hosting
// layer (server.go) has already required a valid session before this
// Hono app ever runs -- an anonymous visit redirects to /auth/login first,
// and a pending-approval account sees ONLY the pending page, never this
// one (see server.go's ServeHTTP for both gates). So by the time this
// handler runs, the caller is a real, active-or-pending-but-not-blocked
// account.
//
// Approval is NEVER automatic: this page always requires an explicit
// click on "Approve" (a real <form method="post"> submission) before any
// code is minted -- a drive-by GET (e.g. an attacker embedding this URL
// in an <img> tag) does nothing by itself.
import { Hono } from "hono";
import type { AppEnv } from "../appenv";
import { Page } from "../components/layout";
import { baseProps, redirectWithFlash } from "../render";
import { APIError } from "../api";

export const cliAuthApp = new Hono<AppEnv>();

cliAuthApp.get("/cli-auth", async (c) => {
	const props = await baseProps(c.var.api, c.var.caller, "none", "CLI login");
	const t = props.t;

	const redirect = c.req.query("redirect") ?? "";
	const challenge = c.req.query("challenge") ?? "";
	const name = c.req.query("name") || "unknown device";

	if (!redirect || !challenge) {
		return c.html(
			<Page {...props} crumb={<>{t("cli_login_title")}</>}>
				<div class="error-box">{t("cli_login_invalid")}</div>
			</Page>,
			400,
		);
	}

	return c.html(
		<Page {...props} crumb={<>{t("cli_login_title")}</>} maxWidth={560}>
			<div class="card">
				<h5>{t("cli_login_heading")}</h5>
				<p>{t("cli_login_description", { name })}</p>
				<dl class="kv">
					<dt>{t("cli_login_device_name")}</dt>
					<dd class="mono">{name}</dd>
				</dl>
				<form method="post" action="/dashboard/cli-auth/approve" class="row" style="margin-top:16px;gap:8px">
					<input type="hidden" name="redirect" value={redirect} />
					<input type="hidden" name="challenge" value={challenge} />
					<input type="hidden" name="name" value={name} />
					<button class="btn" type="submit">
						{t("cli_login_approve")}
					</button>
					<a class="btn ghost" href="/dashboard">
						{t("cli_login_cancel")}
					</a>
				</form>
			</div>
		</Page>,
	);
});

// POST /dashboard/cli-auth/approve: the user has just clicked Approve.
// Mints the one-time code (via the management API, session +
// CSRF-protected like every other mutation in this app) and hands the
// browser off to the CLI's own loopback listener with a plain HTTP
// redirect -- there is no fetch/XHR involved, so no CORS concern crossing
// from this origin to 127.0.0.1.
cliAuthApp.post("/cli-auth/approve", async (c) => {
	const body = await c.req.parseBody();
	const redirect = typeof body.redirect === "string" ? body.redirect : "";
	const challenge = typeof body.challenge === "string" ? body.challenge : "";
	const name = typeof body.name === "string" ? body.name : "";
	try {
		const { code } = await c.var.api.authorizeCLILogin(redirect, challenge, name);
		const sep = redirect.includes("?") ? "&" : "?";
		return c.redirect(`${redirect}${sep}code=${encodeURIComponent(code)}`, 303);
	} catch (e) {
		return c.redirect(redirectWithFlash("/dashboard", "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});
