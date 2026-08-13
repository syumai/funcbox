// routes/settings.tsx: /settings, the personal settings screen (handle,
import { Hono } from "hono";
import type { AppEnv } from "../appenv";
import { Page, fmtTime } from "../components/layout";
import { baseProps, flashFromQuery, localizedMessage, redirectWithFlash } from "../render";
import { APIError } from "../api";
import { languageName } from "../i18n";

export const settingsApp = new Hono<AppEnv>();

// MAX_TOKEN_TTL_DAYS mirrors auth.MaxTokenTTL (server/internal/auth/tokens.go)
// -- kept in sync by hand, since this app has no code-generation step from
// the Go side (see types.ts's doc comment). It drives both the visible
// "最大90日" copy below and the <input max> the browser's native
// datetime-local picker enforces; the server is still the actual source of
// truth (ValidateTokenTTL rejects anything past it regardless of what the
// form allowed).
const MAX_TOKEN_TTL_DAYS = 90;

// toDatetimeLocal formats d as the "YYYY-MM-DDTHH:mm" string
// <input type="datetime-local"> wants for its value/min/max attributes.
function toDatetimeLocal(d: Date): string {
	const pad = (n: number) => String(n).padStart(2, "0");
	return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

settingsApp.get("/settings", async (c) => {
	const api = c.var.api;
	const props = await baseProps(api, c.var.caller, "settings", "Personal settings");
	const t = props.t;
	try {
		const me = await api.me();
		const { tokens } = await api.listTokens();
		const flash = flashFromQuery((k) => c.req.query(k), props.language);
		const newToken = c.req.query("new_token") ?? "";
		const origin = new URL(c.req.url).origin;

		const now = new Date();
		const maxExpiry = new Date(now.getTime() + MAX_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000);

		return c.html(
			<Page {...props} crumb={<>{t("personal_settings_crumb")}</>} flash={flash}>
				<div class="cols">
					<div class="card">
						<h5>{t("profile")}</h5>
						<dl class="kv">
							<dt>{t("email_address")}</dt>
							<dd>{me.email}</dd>
							<dt>{t("role")}</dt>
							<dd>{me.role}</dd>
						</dl>
						<form method="post" action="/dashboard/settings/handle" class="stack" style="margin-top:12px">
							<div class="field">
								<label for="settings-handle">{t("handle_help")}</label>
								<input id="settings-handle" type="text" name="handle" value={me.handle} style="width:220px" />
							</div>
							<button class="btn ghost" type="submit">
								{t("change")}
							</button>
						</form>
						<form method="post" action="/dashboard/settings/language" class="stack" style="margin-top:12px">
							<div class="field">
								<label for="settings-language">{t("language")}</label>
								<select id="settings-language" name="language">
									<option value="">{t("inherit_organization", { language: languageName((me.effective_language ?? props.language), t) })}</option>
									<option value="en" selected={me.language === "en"}>{t("english")}</option>
									<option value="ja" selected={me.language === "ja"}>{t("japanese")}</option>
								</select>
							</div>
							<div class="hint">{t("personal_language_help")}</div>
							<button class="btn ghost" type="submit">{t("save")}</button>
						</form>
					</div>
					<div class="card">
						<h5>{t("api_tokens")}</h5>
						<div class="info-box">
							{t("api_tokens_description", { days: MAX_TOKEN_TTL_DAYS })}
						</div>
						{newToken ? (
							<div class="token-reveal">
								<div class="token-reveal-head">
									{t("new_token_notice")}
								</div>
								<div class="row">
									<span class="urlbox mono" id="new-token-value" style="word-break:break-all;flex:1">
										{newToken}
									</span>
									<button class="copy" type="button" data-copy-target="new-token-value">
										copy
									</button>
								</div>
								<div class="hint">
									{t("usage")} <code class="mono">funcbox login --server {origin}</code> {t("then_paste")}
								</div>
							</div>
						) : null}
						<table class="vers">
							{tokens.map((t) => (
								<tr>
									<td class="mono">{t.name}</td>
									<td class="owner">exp {fmtTime(t.expires_at)}</td>
									<td>
										<form method="post" action={`/dashboard/settings/tokens/${t.id}/delete`} data-confirm={props.t("delete_token_confirm", { name: t.name })}>
											<button class="link danger" type="submit">
												{props.t("delete")}
											</button>
										</form>
									</td>
								</tr>
							))}
						</table>
						<form method="post" action="/dashboard/settings/tokens" class="stack" style="margin-top:10px">
							<div class="field">
								<label for="token-name">{t("token_name")}</label>
								<input id="token-name" type="text" name="name" placeholder={t("token_name_example")} required style="width:220px" />
							</div>
							<div class="field">
								<label for="token-expires">
									{t("expiry", { days: MAX_TOKEN_TTL_DAYS })}
								</label>
								<input
									id="token-expires"
									type="datetime-local"
									name="expires_at"
									required
									min={toDatetimeLocal(now)}
									max={toDatetimeLocal(maxExpiry)}
								/>
							</div>
							<button class="btn ghost" type="submit">
								{t("issue")}
							</button>
						</form>
					</div>
				</div>
			</Page>,
		);
	} catch (e) {
		return c.html(
			<Page {...props}>
				<div class="error-box">{e instanceof APIError ? e.message : String(e)}</div>
			</Page>,
			e instanceof APIError ? (e.status as any) : 500,
		);
	}
});

settingsApp.post("/settings/handle", async (c) => {
	const body = await c.req.parseBody();
	const handle = typeof body.handle === "string" ? body.handle : "";
	try {
		await c.var.api.updateHandle(handle);
		return c.redirect(redirectWithFlash("/dashboard/settings", "notice", await localizedMessage(c.var.api, "handle_updated")), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash("/dashboard/settings", "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});

settingsApp.post("/settings/tokens", async (c) => {
	const body = await c.req.parseBody();
	const name = typeof body.name === "string" ? body.name : "";
	const expiresLocal = typeof body.expires_at === "string" ? body.expires_at : "";
	try {
		const iso = expiresLocal ? new Date(expiresLocal).toISOString() : "";
		const tok = await c.var.api.createToken(name, iso);
		const base = "/dashboard/settings";
		const sep = base.includes("?") ? "&" : "?";
		return c.redirect(`${base}${sep}notice=${encodeURIComponent(await localizedMessage(c.var.api, "token_issued"))}&new_token=${encodeURIComponent(tok.token ?? "")}`, 303);
	} catch (e) {
		return c.redirect(redirectWithFlash("/dashboard/settings", "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});

settingsApp.post("/settings/tokens/:id/delete", async (c) => {
	const { id } = c.req.param();
	try {
		await c.var.api.deleteToken(id);
		return c.redirect(redirectWithFlash("/dashboard/settings", "notice", await localizedMessage(c.var.api, "token_deleted")), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash("/dashboard/settings", "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});

settingsApp.post("/settings/language", async (c) => {
	const body = await c.req.parseBody();
	const language = body.language === "en" || body.language === "ja" ? body.language : null;
	try {
		await c.var.api.updateLanguage(language);
		return c.redirect(redirectWithFlash("/dashboard/settings", "notice", await localizedMessage(c.var.api, "language_updated")), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash("/dashboard/settings", "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});
