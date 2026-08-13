// layout.tsx: the "Operator" shell (tmp/09-dashboard.md §9.4/§dashboard-ui-
// proposals.html) -- left rail nav, crumb, page title -- shared by every
// screen. Client asset URLs are esbuild `define`d constants (see
// build.ts): they resolve to literal string constants at bundle time, so
// there's no runtime manifest lookup.
import { html } from "hono/html";
import type { CallerClaims } from "../identity";
import type { DashboardLanguage, Translate } from "../i18n";

declare const __ASSET_SCRIPT_URL__: string;
declare const __ASSET_STYLE_URL__: string;

export type NavKey = "functions" | "workspaces" | "org" | "org-users" | "org-audit" | "settings" | "none";

interface NavItem {
	key: NavKey;
	href: string;
	label: string;
	icon: string;
	adminOnly?: boolean;
	section?: string;
}

const navItems: NavItem[] = [
	{ key: "functions", href: "/dashboard", label: "functions", icon: "▣" },
	{ key: "workspaces", href: "/dashboard/workspaces", label: "workspaces", icon: "◫" },
	{ key: "org", href: "/dashboard/org", label: "org_settings", icon: "⚙", section: "organization", adminOnly: true },
	{ key: "org-users", href: "/dashboard/org/users", label: "users", icon: "👥", section: "organization", adminOnly: true },
	{ key: "org-audit", href: "/dashboard/org/audit", label: "audit_logs", icon: "≣", section: "organization", adminOnly: true },
	{ key: "settings", href: "/dashboard/settings", label: "personal_settings", icon: "⌘", section: "account" },
];

export interface PageProps {
	title: string;
	active: NavKey;
	orgName: string;
	caller: CallerClaims;
	language: DashboardLanguage;
	t: Translate;
	crumb?: any;
	maxWidth?: number;
	flash?: { kind: "notice" | "error"; message: string } | null;
	children?: any;
}

export function Page(props: PageProps) {
	const isAdmin = props.caller.role === "admin";
	let lastSection: string | undefined;
	const items = navItems.filter((item) => !item.adminOnly || isAdmin);

	const body = (
		<div class="shell">
			<aside class="side">
				<div class="brand">
					<a href="/dashboard">
						<span class="cube"></span>
						<b>funcbox</b>
					</a>
					<span class="env">{props.orgName}</span>
				</div>
				<nav class="nav">
					{items.map((item) => {
						const sectionHeader =
							item.section && item.section !== lastSection ? (
								<div class="sec">{props.t(item.section)}</div>
							) : null;
						lastSection = item.section;
						return (
							<>
								{sectionHeader}
								<a href={item.href} class={item.key === props.active ? "on" : ""}>
									<span>{item.icon}</span> {props.t(item.label)}
								</a>
							</>
						);
					})}
				</nav>
			</aside>
			<div class="main" style={props.maxWidth ? `max-width:${props.maxWidth}px` : undefined}>
				{props.crumb ? <div class="crumb">{props.crumb}</div> : null}
				<h4>{props.title}</h4>
				{props.flash ? <div class={props.flash.kind === "error" ? "error-box" : "notice-box"}>{props.flash.message}</div> : null}
				{props.children}
			</div>
		</div>
	);

	return html`<!doctype html>
		<html lang="${props.language}">
			<head>
				<meta charset="utf-8" />
				<meta name="viewport" content="width=device-width, initial-scale=1" />
				<title>${props.title} - funcbox</title>
				<link rel="stylesheet" href="${__ASSET_STYLE_URL__}" />
			</head>
			<body data-language="${props.language}">
				${body}
				<script src="${__ASSET_SCRIPT_URL__}" defer></script>
			</body>
		</html>`;
}

export function Pill(props: { kind: string; children: any }) {
	return <span class={`pill ${props.kind}`}>{props.children}</span>;
}

export function fmtBytes(n: number): string {
	if (!n && n !== 0) return "-";
	if (n < 1024) return `${n} B`;
	if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
	return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

export function fmtTime(iso: string): string {
	if (!iso) return "-";
	try {
		const d = new Date(iso);
		if (Number.isNaN(d.getTime())) return iso;
		return d.toISOString().replace("T", " ").slice(0, 19) + " UTC";
	} catch {
		return iso;
	}
}
