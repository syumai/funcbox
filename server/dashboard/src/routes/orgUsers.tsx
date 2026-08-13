// routes/orgUsers.tsx: /org/users (admin-only user management --
import { Hono } from "hono";
import type { AppEnv } from "../appenv";
import { Page } from "../components/layout";
import { baseProps, flashFromQuery, localizedMessage, redirectWithFlash } from "../render";
import { APIError } from "../api";

export const orgUsersApp = new Hono<AppEnv>();

orgUsersApp.get("/org/users", async (c) => {
	const api = c.var.api;
	const props = await baseProps(api, c.var.caller, "org-users", "Users");
	const t = props.t;
	if (c.var.caller.role !== "admin") {
		return c.html(
			<Page {...props}>
				<div class="error-box">{t("admin_required")}</div>
			</Page>,
			403,
		);
	}
	try {
		const { users } = await api.listOrgUsers();
		return c.html(
			<Page {...props} crumb={<>{t("organization_colon")} <b>{props.orgName}</b></>} flash={flashFromQuery((k) => c.req.query(k), props.language)}>
				<table class="fn">
					<tr>
						<th>{t("user")}</th>
						<th>role</th>
						<th>{t("state")}</th>
						<th>{t("created")}</th>
						<th></th>
					</tr>
					{users.map((u) => (
						<tr>
							<td>
								<span class="fname">{u.name || u.email}</span> <span class="owner">{u.email}</span>
							</td>
							<td>
								<span class={u.role === "admin" ? "pill admin" : "pill member"}>{u.role}</span>
							</td>
							<td>{u.disabled ? <span class="pill deny">disabled</span> : <span class="pill allow">active</span>}</td>
							<td class="owner">{new Date(u.created_at).toLocaleDateString()}</td>
							<td>
								<form method="post" action={`/dashboard/org/users/${u.id}`} class="row">
									<select name="role">
										<option value="member" selected={u.role === "member"}>
											member
										</option>
										<option value="admin" selected={u.role === "admin"}>
											admin
										</option>
									</select>
									<label style="display:flex;align-items:center;gap:4px">
										<input type="checkbox" name="disabled" checked={u.disabled} /> disabled
									</label>
									<button class="link" type="submit">
										{t("update")}
									</button>
								</form>
							</td>
						</tr>
					))}
				</table>
				<div class="hint" style="margin-top:8px">
					{t("user_ids")} {users.map((u) => `${u.email}=${u.id}`).join(" / ")}
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

orgUsersApp.post("/org/users/:id", async (c) => {
	if (c.var.caller.role !== "admin") return c.text("forbidden", 403);
	const { id } = c.req.param();
	const body = await c.req.parseBody();
	try {
		await c.var.api.patchOrgUser(id, {
			role: typeof body.role === "string" ? body.role : undefined,
			disabled: body.disabled === "on",
		});
		return c.redirect(redirectWithFlash("/dashboard/org/users", "notice", await localizedMessage(c.var.api, "user_updated")), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash("/dashboard/org/users", "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});
