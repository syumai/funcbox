// routes/settings.tsx: /settings, the personal settings screen (handle,
// API tokens -- tmp/09-dashboard.md §9.5).
import { Hono } from "hono";
import type { AppEnv } from "../appenv";
import { Page, fmtTime } from "../components/layout";
import { baseProps, flashFromQuery, redirectWithFlash } from "../render";
import { APIError } from "../api";

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
	const props = await baseProps(api, c.var.caller, "settings", "個人設定");
	try {
		const me = await api.me();
		const { tokens } = await api.listTokens();
		const flash = flashFromQuery((k) => c.req.query(k));
		const newToken = c.req.query("new_token") ?? "";
		const origin = new URL(c.req.url).origin;

		const now = new Date();
		const maxExpiry = new Date(now.getTime() + MAX_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000);

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
						<form method="post" action="/dashboard/settings/handle" class="stack" style="margin-top:12px">
							<div class="field">
								<label for="settings-handle">{"ハンドル（関数の URL やダッシュボードのパス /functions/{ハンドル}/{名前} に使われる識別子）"}</label>
								<input id="settings-handle" type="text" name="handle" value={me.handle} style="width:220px" />
							</div>
							<button class="btn ghost" type="submit">
								変更
							</button>
						</form>
					</div>
					<div class="card">
						<h5>API トークン</h5>
						<div class="info-box">
							API トークンは CLI（<code>funcbox login</code>）や CI から管理 API を呼び出すための認証情報です。 発行されるトークンは
							<code>fbx_</code> で始まり、有効期限は発行から最大 {MAX_TOKEN_TTL_DAYS} 日です。期限が切れるとそのトークンでの認証は失敗するようになります（自動更新はされません
							— 必要であれば新しいトークンを発行してください）。 漏えいした、または不要になったトークンは一覧の「削除」から即座に無効化できます。
						</div>
						{newToken ? (
							<div class="token-reveal">
								<div class="token-reveal-head">
									新しいトークンを発行しました。<b>この画面を離れると二度と表示されません。</b> 今すぐコピーしてください。
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
									使い方: ターミナルで <code class="mono">funcbox login --server {origin}</code>{" "}
									を実行し、プロンプトが表示されたらこのトークンを貼り付けてください。
								</div>
							</div>
						) : null}
						<table class="vers">
							{tokens.map((t) => (
								<tr>
									<td class="mono">{t.name}</td>
									<td class="owner">exp {fmtTime(t.expires_at)}</td>
									<td>
										<form method="post" action={`/dashboard/settings/tokens/${t.id}/delete`} data-confirm={`トークン ${t.name} を削除しますか? この操作は取り消せません。`}>
											<button class="link danger" type="submit">
												削除
											</button>
										</form>
									</td>
								</tr>
							))}
						</table>
						<form method="post" action="/dashboard/settings/tokens" class="stack" style="margin-top:10px">
							<div class="field">
								<label for="token-name">名前（用途がわかる名前を推奨。例: laptop, ci）</label>
								<input id="token-name" type="text" name="name" placeholder="例: laptop" required style="width:220px" />
							</div>
							<div class="field">
								<label for="token-expires">
									有効期限（最大 {MAX_TOKEN_TTL_DAYS} 日後まで）
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
		return c.redirect(redirectWithFlash("/dashboard/settings", "notice", "ハンドルを更新しました"), 303);
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
