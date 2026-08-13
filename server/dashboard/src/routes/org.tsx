// routes/org.tsx: /org (admin-only org settings: fetch policy, visibility
// §9.5). See routes/orgUsers.tsx and routes/orgAudit.tsx for the other two
// admin-only screens under the same "organization" nav section.
import { Hono } from "hono";
import type { AppEnv } from "../appenv";
import { Page } from "../components/layout";
import { baseProps, flashFromQuery, localizedMessage, redirectWithFlash } from "../render";
import { APIError } from "../api";
import type { LoginRuleDTO } from "../types";

export const orgApp = new Hono<AppEnv>();

// SPARE_LOGIN_RULE_ROWS is how many blank rows the login-rules editor form
// always renders below the existing rules, so an admin can add new rules
// without any client-side "add row" JS -- a deliberate tradeoff to keep
// capacity per save instead of a dynamic list.
const SPARE_LOGIN_RULE_ROWS = 5;

function Forbidden(props: { message: string }) {
	return <div class="error-box">{props.message}</div>;
}

orgApp.get("/org", async (c) => {
	const api = c.var.api;
	const props = await baseProps(api, c.var.caller, "org", "Organization settings");
	const t = props.t;
	if (c.var.caller.role !== "admin") {
		return c.html(
			<Page {...props}>
				<Forbidden message={t("admin_required")} />
			</Page>,
			403,
		);
	}

	try {
		const org = await api.getOrg();
		const rulesRes = await api.getLoginRules();
		const rules = rulesRes.login_rules;
		const s = org.settings;

		const ruleTypeOptions = ["", "email_domain", "email_exact", "email_glob", "default"];
		const ruleRow = (rule: LoginRuleDTO | null, idx: number) => (
			<tr>
				<td>
					<select name="rule_type[]">
						{ruleTypeOptions.map((t) => (
							<option value={t} selected={rule ? rule.type === t : t === ""}>
								{t || props.t("unused")}
							</option>
						))}
					</select>
				</td>
				<td>
					<input type="text" name="rule_value[]" value={rule?.value ?? ""} placeholder="example.com / user@example.com / *@ex.com" style="width:220px" />
				</td>
				<td>
					<select name="rule_action[]">
						<option value="allow" selected={!rule || rule.action === "allow"}>
							allow
						</option>
						<option value="deny" selected={rule?.action === "deny"}>
							deny
						</option>
					</select>
				</td>
			</tr>
		);

		return c.html(
			<Page {...props} crumb={<>{t("organization_colon")} <b>{props.orgName}</b></>} flash={flashFromQuery((k) => c.req.query(k), props.language)}>
				<div class="cols">
					<div class="card">
						<h5>{t("org_settings")}</h5>
						<form method="post" action="/dashboard/org" class="stack">
							<div class="field">
								<label for="org-language">{t("language")}</label>
								<select id="org-language" name="language">
									<option value="en" selected={s.language !== "ja"}>{t("english")}</option>
									<option value="ja" selected={s.language === "ja"}>{t("japanese")}</option>
								</select>
								<div class="hint">{t("org_language_help")}</div>
							</div>
							<div class="field">
								<label>
									<input type="checkbox" name="allow_user_functions" checked={s.allow_user_functions} /> {t("allow_personal_functions")}
								</label>
							</div>
							<div class="field">
								<label>
									<input type="checkbox" name="allow_workspace_creation" checked={s.allow_workspace_creation} /> {t("allow_workspace_creation")}
								</label>
							</div>
							<div class="field">
								<label>
									<input type="checkbox" name="allow_nodejs_compat" checked={s.allow_nodejs_compat} /> {t("allow_nodejs")}
								</label>
							</div>
							<div class="field">
								<label>default_visibility</label>
								<select name="default_visibility">
									{["private", "workspace", "org", "public"].map((v) => (
										<option value={v} selected={v === s.default_visibility}>
											{v}
										</option>
									))}
								</select>
							</div>
							<div class="field">
								<label>max_visibility</label>
								<select name="max_visibility">
									{["private", "workspace", "org", "public"].map((v) => (
										<option value={v} selected={v === s.max_visibility}>
											{v}
										</option>
									))}
								</select>
							</div>
							<div class="field">
								<label>{t("fetch_policy_mode")}</label>
								<select name="fetch_mode">
									{["deny", "allowlist", "allow-all"].map((m) => (
										<option value={m} selected={m === s.fetch_policy.mode}>
											{m}
										</option>
									))}
								</select>
							</div>
							<div class="field">
								<label>{t("allowlist_help")}</label>
								<input type="text" name="fetch_allow" value={(s.fetch_policy.allow ?? []).join(", ")} style="width:100%" />
							</div>
							<div class="field">
								<label>{t("session_duration")}</label>
								<input type="number" name="session_duration_seconds" value={s.session_duration_seconds || ""} />
							</div>
							<button class="btn" type="submit">
								{t("save")}
							</button>
						</form>
						<dl class="kv" style="margin-top:16px">
							<dt>invoke_timeout_max</dt>
							<dd class="mono">{s.limits.invoke_timeout_max ?? "-"}</dd>
							<dt>memory_max</dt>
							<dd class="mono">{s.limits.memory_max ?? "-"} bytes</dd>
							<dt>bundle_unpacked_max</dt>
							<dd class="mono">{s.limits.bundle_unpacked_max ?? "-"} bytes</dd>
						</dl>
					</div>
					<div class="card">
						<h5>{t("login_rules")}</h5>
						<form method="post" action="/dashboard/org/login-rules">
							<table class="vers">
								<tr>
									<th class="owner" style="font-weight:400;font-size:11px">
										type
									</th>
									<th class="owner" style="font-weight:400;font-size:11px">
										value
									</th>
									<th class="owner" style="font-weight:400;font-size:11px">
										action
									</th>
								</tr>
								{rules.map((r, i) => ruleRow(r, i))}
								{Array.from({ length: SPARE_LOGIN_RULE_ROWS }).map((_, i) => ruleRow(null, rules.length + i))}
							</table>
							<div class="hint">{t("login_rule_help")}</div>
							<button class="btn" type="submit" style="margin-top:10px">
								{t("save_login_rules")}
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

orgApp.post("/org", async (c) => {
	if (c.var.caller.role !== "admin") return c.text("forbidden", 403);
	const body = await c.req.parseBody();
	const allow = String(body.fetch_allow ?? "")
		.split(",")
		.map((s) => s.trim())
		.filter(Boolean);
	try {
		await c.var.api.patchOrg({
			language: body.language === "ja" ? "ja" : "en",
			allow_user_functions: body.allow_user_functions === "on",
			allow_workspace_creation: body.allow_workspace_creation === "on",
			allow_nodejs_compat: body.allow_nodejs_compat === "on",
			default_visibility: String(body.default_visibility ?? "org"),
			max_visibility: String(body.max_visibility ?? "public"),
			fetch_policy: { mode: String(body.fetch_mode ?? "deny"), allow },
			session_duration_seconds: body.session_duration_seconds ? Number(body.session_duration_seconds) : 0,
		});
		return c.redirect(redirectWithFlash("/dashboard/org", "notice", await localizedMessage(c.var.api, "org_settings_updated")), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash("/dashboard/org", "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});

orgApp.post("/org/login-rules", async (c) => {
	if (c.var.caller.role !== "admin") return c.text("forbidden", 403);
	const body = await c.req.parseBody({ all: true });
	const types = asArray(body["rule_type[]"]);
	const values = asArray(body["rule_value[]"]);
	const actions = asArray(body["rule_action[]"]);

	const rules: Array<{ type: string; value: string; action: string }> = [];
	for (let i = 0; i < types.length; i++) {
		const type = types[i];
		if (!type) continue;
		rules.push({ type, value: values[i] ?? "", action: actions[i] ?? "allow" });
	}

	try {
		await c.var.api.putLoginRules(rules);
		return c.redirect(redirectWithFlash("/dashboard/org", "notice", await localizedMessage(c.var.api, "login_rules_saved")), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash("/dashboard/org", "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});

function asArray(v: unknown): string[] {
	if (v === undefined) return [];
	if (Array.isArray(v)) return v.map(String);
	return [String(v)];
}
