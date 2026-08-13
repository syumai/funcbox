// routes/settings.tsx: /settings, the personal settings screen (handle,
// API tokens -- tmp/09-dashboard.md §9.5).
import { Hono } from "hono";
import type { AppEnv } from "../appenv";
import { Page, fmtTime } from "../components/layout";
import { baseProps, flashFromQuery, redirectWithFlash } from "../render";
import { APIError } from "../api";

export const settingsApp = new Hono<AppEnv>();

settingsApp.get("/settings", async (c) => {
	const api = c.var.api;
	const props = await baseProps(api, c.var.caller, "settings", "個人設定");
	try {
		const me = await api.me();
		const { tokens } = await api.listTokens();
		const flash = flashFromQuery((k) => c.req.query(k));
		const newToken = c.req.query("new_token") ?? "";

		return c.html(
			<Page {...props} crumb={<>個人設定</>} flash={flash}>
				<div class="cols">
					<div class="card">
						<h5>プロフィール</h5>
						<dl class="kv">
							<dt>メールアドレス</dt>
							<dd>{me.email}</dd>
							<dt>ロール</dt>
							<dd>{me.role}</dd>
						</dl>
						<form method="post" action="/dashboard/settings/handle" class="row" style="margin-top:12px">
							<label style="width:auto">handle</label>
							<input type="text" name="handle" value={me.handle} style="width:200px" />
							<button class="btn ghost" type="submit">
								変更
							</button>
						</form>
					</div>
					<div class="card">
						<h5>API トークン</h5>
						{newToken ? (
							<div class="notice-box">
								新しいトークン（この画面でのみ表示されます）:
								<div class="urlbox mono" style="margin-top:6px;word-break:break-all">
									{newToken}
								</div>
							</div>
						) : null}
						<table class="vers">
							{tokens.map((t) => (
								<tr>
									<td class="mono">{t.name}</td>
									<td class="owner">exp {fmtTime(t.expires_at)}</td>
									<td>
										<form method="post" action={`/dashboard/settings/tokens/${t.id}/delete`} data-confirm={`トークン ${t.name} を削除しますか?`}>
											<button class="link danger" type="submit">
												削除
											</button>
										</form>
									</td>
								</tr>
							))}
						</table>
						<form method="post" action="/dashboard/settings/tokens" class="row" style="margin-top:10px">
							<input type="text" name="name" placeholder="トークン名" required style="width:140px" />
							<input type="datetime-local" name="expires_at" required />
							<button class="btn ghost" type="submit">
								発行
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
		return c.redirect(redirectWithFlash("/dashboard/settings", "notice", "handle を更新しました"), 303);
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
		return c.redirect(`${base}${sep}notice=${encodeURIComponent("トークンを発行しました")}&new_token=${encodeURIComponent(tok.token ?? "")}`, 303);
	} catch (e) {
		return c.redirect(redirectWithFlash("/dashboard/settings", "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});

settingsApp.post("/settings/tokens/:id/delete", async (c) => {
	const { id } = c.req.param();
	try {
		await c.var.api.deleteToken(id);
		return c.redirect(redirectWithFlash("/dashboard/settings", "notice", "トークンを削除しました"), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash("/dashboard/settings", "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});
