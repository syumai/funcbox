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

// NavIconKey is every key NAV_ICON_PATHS actually has a drawing for: every
// real nav item, plus "logout" for the sidebar's sign-out button. It
// excludes NavKey's "none" sentinel (used only as PageProps.active for pages
// with no corresponding nav item, e.g. the CLI login approval screen) since
// that value is never passed to NavIcon.
type NavIconKey = Exclude<NavKey, "none"> | "logout";

interface NavItem {
	key: NavKey;
	href: string;
	label: string;
	icon: NavIconKey;
	adminOnly?: boolean;
	section?: string;
}

const navItems: NavItem[] = [
	{ key: "functions", href: "/dashboard", label: "functions", icon: "functions" },
	{ key: "workspaces", href: "/dashboard/workspaces", label: "workspaces", icon: "workspaces" },
	{ key: "org", href: "/dashboard/org", label: "org_settings", icon: "org", section: "organization", adminOnly: true },
	{ key: "org-users", href: "/dashboard/org/users", label: "users", icon: "org-users", section: "organization", adminOnly: true },
	{ key: "org-audit", href: "/dashboard/org/audit", label: "audit_logs", icon: "org-audit", section: "organization", adminOnly: true },
	{ key: "settings", href: "/dashboard/settings", label: "personal_settings", icon: "settings", section: "account" },
];

// Sidebar nav icons: a consistent stroke-based SVG set (viewBox 0 0 24 24,
// fill="none", stroke="currentColor", uniform 1.75 stroke-width), each
// rendered at a fixed 17px square inside a flex-centered <span class="nav-icon">.
// This replaces a prior mix of unicode symbols and emoji (▣ ◫ ⚙ 👥 ≣ ⌘ ⏻)
// whose glyphs rendered at wildly different sizes/widths depending on the
// platform's font/emoji fallback, making the rail look ragged -- SVG paths
// give every item the exact same footprint and let icons inherit
// currentColor so the existing hover/active (.nav a.on) color rules keep
// working with no extra CSS.
const ICON_ATTRS = {
	width: "17",
	height: "17",
	viewBox: "0 0 24 24",
	fill: "none",
	stroke: "currentColor",
	"stroke-width": "1.75",
	"stroke-linecap": "round" as const,
	"stroke-linejoin": "round" as const,
};

// NAV_ICON_PATHS maps each nav key to its icon's inner SVG markup:
//   functions       -- braces, evoking code/function bodies
//   workspaces      -- 2x2 grid, evoking grouped resources
//   org (settings)  -- hex nut with a center hole, a simplified "gear"
//   org-users       -- two overlapping head-and-shoulders silhouettes
//   org-audit       -- three list lines (shorter last line reads as a log)
//   settings        -- vertical sliders, for personal preferences
//   logout          -- door frame with an outward arrow
const NAV_ICON_PATHS: Record<NavIconKey, any> = {
	functions: (
		<path d="M8 4c-2 0-3 1-3 3v2a2 2 0 0 1-2 2 2 2 0 0 1 2 2v2c0 2 1 3 3 3M16 4c2 0 3 1 3 3v2a2 2 0 0 0 2 2 2 2 0 0 0-2 2v2c0 2-1 3-3 3" />
	),
	workspaces: (
		<>
			<rect x="3" y="3" width="7.5" height="7.5" rx="1.2" />
			<rect x="13.5" y="3" width="7.5" height="7.5" rx="1.2" />
			<rect x="3" y="13.5" width="7.5" height="7.5" rx="1.2" />
			<rect x="13.5" y="13.5" width="7.5" height="7.5" rx="1.2" />
		</>
	),
	org: (
		<>
			<path d="M12 2 4.5 6.5v11L12 22l7.5-4.5v-11z" />
			<circle cx="12" cy="12" r="3" />
		</>
	),
	"org-users": (
		<>
			<path d="M2.5 20a5.5 5.5 0 0 1 11 0" />
			<circle cx="8" cy="8.5" r="3.5" />
			<path d="M15.5 20a4.5 4.5 0 0 0-3-4.24" />
			<path d="M13.5 4.3a3.5 3.5 0 0 1 0 6.9" />
		</>
	),
	"org-audit": <path d="M4 6h16M4 12h16M4 18h9" />,
	settings: (
		<>
			<path d="M4 21v-6M4 11V3M12 21v-9M12 8V3M20 21v-4M20 13V3" />
			<circle cx="4" cy="13" r="2" />
			<circle cx="12" cy="10" r="2" />
			<circle cx="20" cy="15" r="2" />
		</>
	),
	logout: (
		<>
			<path d="M9 21H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h3" />
			<path d="M16 17l5-5-5-5" />
			<path d="M21 12H9" />
		</>
	),
};

function NavIcon(props: { name: NavIconKey }) {
	return (
		<span class="nav-icon">
			<svg {...ICON_ATTRS}>{NAV_ICON_PATHS[props.name]}</svg>
		</span>
	);
}

export interface PageProps {
	title: string;
	active: NavKey;
	orgName: string;
	caller: CallerClaims;
	language: DashboardLanguage;
	t: Translate;
	crumb?: any;
	// titleExtra renders inline, right after the title text, inside the
	// SAME <h4> Page itself already owns -- for a page whose title is a
	// dynamic name (e.g. a function's) that wants to add pills/badges next
	// to it, without a caller having to render its own separate, visually
	// duplicate title heading (functions.tsx's detail route used to render
	// "{fn.name}" a second time this way -- a real duplicate-heading bug).
	titleExtra?: any;
	maxWidth?: number;
	flash?: { kind: "notice" | "error"; message: string } | null;
	children?: any;
	// Number of users awaiting approval (§13.3), admin-only (baseProps
	// leaves this undefined for anyone else); rendered as a badge next to
	// the "users" nav item when > 0.
	pendingCount?: number;
	// openMode: the organization's open_mode setting (§13.1). The
	// workspace feature is disabled entirely while it's on, so the nav
	// hides that item -- the API 404s the workspace routes regardless,
	// this just avoids linking to a dead end.
	openMode?: boolean;
}

export function Page(props: PageProps) {
	const isAdmin = props.caller.role === "admin";
	let lastSection: string | undefined;
	const items = navItems.filter((item) => (!item.adminOnly || isAdmin) && (item.key !== "workspaces" || !props.openMode));

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
									<NavIcon name={item.icon} /> {props.t(item.label)}
									{item.key === "org-users" && props.pendingCount ? <span class="badge">{props.pendingCount}</span> : null}
								</a>
							</>
						);
					})}
					<form class="nav-logout" method="POST" action="/auth/logout">
						<button type="submit">
							<NavIcon name="logout" /> {props.t("logout")}
						</button>
					</form>
				</nav>
			</aside>
			<div class="main" style={props.maxWidth ? `max-width:${props.maxWidth}px` : undefined}>
				{props.crumb ? <div class="crumb">{props.crumb}</div> : null}
				<h4>
					{props.title}
					{props.titleExtra ? <> {props.titleExtra}</> : null}
				</h4>
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
