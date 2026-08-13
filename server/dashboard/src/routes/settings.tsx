// routes/settings.tsx: /settings, the personal settings screen (User ID,
// language, connected CLI-login devices §14.4).
import { Hono } from "hono";
import type { AppEnv } from "../appenv";
import { Page, fmtTime } from "../components/layout";
import { baseProps, flashFromQuery, localizedMessage, redirectWithFlash } from "../render";
import { APIError } from "../api";
import { languageName } from "../i18n";

export const settingsApp = new Hono<AppEnv>();

settingsApp.get("/settings", async (c) => {
	const api = c.var.api;
	const props = await baseProps(api, c.var.caller, "settings", "Personal settings");
	const t = props.t;
	try {
		const me = await api.me();
		const { devices } = await api.listDevices();
		const flash = flashFromQuery((k) => c.req.query(k), props.language);

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
						<form method="post" action="/dashboard/settings/user-id" class="stack" style="margin-top:12px">
							<div class="field">
								<label for="settings-user-id">{t("user_id_help_profile")}</label>
								<input id="settings-user-id" type="text" name="user_id" value={me.user_id} style="width:220px" />
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
						<h5>{t("connected_devices")}</h5>
						<div class="info-box">{t("connected_devices_description")}</div>
						{devices.length === 0 ? (
							<div class="hint">{t("no_connected_devices")}</div>
						) : (
							<table class="vers">
								{devices.map((d) => (
									<tr>
										<td class="mono">{d.name}</td>
										<td class="owner">
											{t("created")} {fmtTime(d.created_at)}
											{d.last_used_at ? (
												<>
													{" "}
													&middot; {t("last_used")} {fmtTime(d.last_used_at)}
												</>
											) : null}
										</td>
										<td>
											<form method="post" action={`/dashboard/settings/devices/${d.id}/delete`} data-confirm={props.t("revoke_device_confirm", { name: d.name })}>
												<button class="link danger" type="submit">
													{props.t("revoke")}
												</button>
											</form>
										</td>
									</tr>
								))}
							</table>
						)}
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

settingsApp.post("/settings/user-id", async (c) => {
	const body = await c.req.parseBody();
	const userID = typeof body.user_id === "string" ? body.user_id : "";
	try {
		await c.var.api.updateUserID(userID);
		return c.redirect(redirectWithFlash("/dashboard/settings", "notice", await localizedMessage(c.var.api, "user_id_updated")), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash("/dashboard/settings", "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});

settingsApp.post("/settings/devices/:id/delete", async (c) => {
	const { id } = c.req.param();
	try {
		await c.var.api.deleteDevice(id);
		return c.redirect(redirectWithFlash("/dashboard/settings", "notice", await localizedMessage(c.var.api, "device_revoked")), 303);
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
