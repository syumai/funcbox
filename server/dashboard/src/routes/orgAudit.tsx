// routes/orgAudit.tsx: /org/audit (admin-only audit log --
// tmp/09-dashboard.md §9.5), cursor-paginated per GET /api/v1/org/audit-logs.
import { Hono } from "hono";
import type { AppEnv } from "../appenv";
import { Page, fmtTime } from "../components/layout";
import { baseProps } from "../render";
import { APIError } from "../api";

export const orgAuditApp = new Hono<AppEnv>();

orgAuditApp.get("/org/audit", async (c) => {
	const api = c.var.api;
	const props = await baseProps(api, c.var.caller, "org-audit", "Audit logs");
	const t = props.t;
	if (c.var.caller.role !== "admin") {
		return c.html(
			<Page {...props}>
				<div class="error-box">{t("admin_required")}</div>
			</Page>,
			403,
		);
	}
	const cursor = c.req.query("cursor") ?? "";
	try {
		const { audit_logs, next_cursor } = await api.listAuditLogs(cursor || undefined, 50);
		return c.html(
			<Page {...props} crumb={<>{t("organization_colon")} <b>{props.orgName}</b></>}>
				<table class="fn">
					<tr>
						<th>{t("time")}</th>
						<th>actor</th>
						<th>action</th>
						<th>target</th>
						<th>detail</th>
					</tr>
					{audit_logs.map((l) => (
						<tr>
							<td class="owner mono">{fmtTime(l.created_at)}</td>
							<td class="mono owner">{l.actor_id}</td>
							<td class="mono">{l.action}</td>
							<td class="mono owner">{l.target}</td>
							<td class="mono owner" style="max-width:280px;overflow-wrap:anywhere">
								{l.detail ? JSON.stringify(l.detail) : ""}
							</td>
						</tr>
					))}
				</table>
				{audit_logs.length === 0 ? <div class="empty">{t("no_audit_logs")}</div> : null}
				{next_cursor ? (
					<div style="margin-top:12px">
						<a class="btn ghost" href={`/dashboard/org/audit?cursor=${encodeURIComponent(next_cursor)}`}>
							{t("next_page")}
						</a>
					</div>
				) : null}
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
