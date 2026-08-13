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
	// roleLabel translates the workspace_manager role into a friendlier
	// display string (§14.1); admin/member stay as their raw values, same
	// as before this role was added.
	const roleLabel = (role: string) => (role === "workspace_manager" ? t("role_workspace_manager") : role);
	const rolePillClass = (role: string) => (role === "admin" ? "pill admin" : role === "workspace_manager" ? "pill wsmanager" : "pill member");

	try {
		const { users } = await api.listOrgUsers();
		// pending (§13.3) gets its own section above the full user table --
		// approve (status=active) / reject (status=disabled) reuse the exact
		// same PATCH /dashboard/org/users/:id route as the full table's
		// role/status form below, just pre-filled with the target status.
		const pending = users.filter((u) => u.status === "pending");
		return c.html(
			<Page {...props} crumb={<>{t("organization_colon")} <b>{props.orgName}</b></>} flash={flashFromQuery((k) => c.req.query(k), props.language)}>
				{pending.length > 0 ? (
					<div class="card" style="margin-bottom:16px">
						<h5>
							{t("pending_requests")} ({pending.length})
						</h5>
						<table class="fn">
							<tr>
								<th>{t("user")}</th>
								<th>{t("requested")}</th>
								<th></th>
							</tr>
							{pending.map((u) => (
								<tr>
									<td>
										<span class="fname">{u.name || u.email}</span> <span class="owner">{u.email}</span>
									</td>
									<td class="owner">{new Date(u.created_at).toLocaleString()}</td>
									<td>
										<div class="row">
											<form method="post" action={`/dashboard/org/users/${u.id}`}>
												<input type="hidden" name="status" value="active" />
												<button class="btn" type="submit">
													{t("approve")}
												</button>
											</form>
											<form method="post" action={`/dashboard/org/users/${u.id}`}>
												<input type="hidden" name="status" value="disabled" />
												<button class="link danger" type="submit">
													{t("reject")}
												</button>
											</form>
										</div>
									</td>
								</tr>
							))}
						</table>
					</div>
				) : null}
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
								<span class={rolePillClass(u.role)}>{roleLabel(u.role)}</span>
							</td>
							<td>{u.status === "active" ? <span class="pill allow">active</span> : <span class="pill deny">{u.status}</span>}</td>
							<td class="owner">{new Date(u.created_at).toLocaleDateString()}</td>
							<td>
								<form method="post" action={`/dashboard/org/users/${u.id}`} class="row">
									<select name="role">
										<option value="member" selected={u.role === "member"}>
											member
										</option>
										<option value="workspace_manager" selected={u.role === "workspace_manager"}>
											{t("role_workspace_manager")}
										</option>
										<option value="admin" selected={u.role === "admin"}>
											admin
										</option>
									</select>
									<select name="status">
										<option value="active" selected={u.status === "active"}>
											active
										</option>
										<option value="pending" selected={u.status === "pending"}>
											pending
										</option>
										<option value="disabled" selected={u.status === "disabled"}>
											disabled
										</option>
									</select>
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
			status: typeof body.status === "string" ? body.status : undefined,
		});
		return c.redirect(redirectWithFlash("/dashboard/org/users", "notice", await localizedMessage(c.var.api, "user_updated")), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash("/dashboard/org/users", "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});
