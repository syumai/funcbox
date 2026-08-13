// policy.tsx renders the function detail page's centerpiece
// (tmp/09-dashboard.md §9.5: "実効 fetch ポリシーを組織 / WS / manifest の
// 3 段で可視化"): a gate pipeline of the three policy levels intersected
// (∩) into one effective result, mirroring internal/policy.Effective's
// actual semantics (deny wins; allow-all only if every level is; otherwise
// a request must satisfy EVERY allowlist level simultaneously).
import { fmtTime } from "./layout";
import type { FetchPolicyDTO, InvocationLogDTO } from "../types";

export interface PolicyLevel {
	label: string;
	sub: string;
	policy: FetchPolicyDTO;
}

export function computeEffectiveMode(levels: FetchPolicyDTO[]): "deny" | "allowlist" | "allow-all" {
	if (levels.some((l) => l.mode === "deny")) return "deny";
	if (levels.every((l) => l.mode === "allow-all")) return "allow-all";
	return "allowlist";
}

// pickDisplayAllowlist is a DISPLAY-ONLY heuristic, not a re-implementation
// of internal/policy.Effective's actual per-request matching (which ANDs
// every allowlist-mode level together per outbound call -- see
// internal/policy/fetch.go's EffectivePolicy.Decision). Rendering the true
// set-intersection of several host-pattern allowlists would require
// enumerating candidate hosts, which this page has no reason to do. Instead
// it shows the MOST SPECIFIC non-empty allowlist level (manifest, then
// workspace, then organization) as a representative "what this is likely
// scoped to" hint, with an explicit note that every other allowlist level
// above it must ALSO match -- accurate about the AND semantics without
// overclaiming precision it doesn't have.
export function pickDisplayAllowlist(levels: PolicyLevel[]): PolicyLevel | null {
	for (let i = levels.length - 1; i >= 0; i--) {
		const l = levels[i];
		if (l.policy.mode === "allowlist" && l.policy.allow && l.policy.allow.length > 0) return l;
	}
	return null;
}

function laneTag(mode: string): string {
	if (mode === "deny") return "DENY-ALL";
	if (mode === "allow-all") return "ALLOW-ALL";
	return "ALLOWLIST";
}

function laneClass(mode: string): string {
	if (mode === "deny") return "lane deny";
	if (mode === "allowlist") return "lane allow";
	return "lane";
}

function laneBody(p: FetchPolicyDTO): string {
	if (p.mode === "deny") return "すべて拒否";
	if (p.mode === "allow-all") return "（制約なし — 下位で narrowing される場合があります）";
	if (p.allow && p.allow.length > 0) return p.allow.join(", ");
	return "（空の allowlist = 実質 deny）";
}

export function FetchPolicyGate(props: { levels: PolicyLevel[] }) {
	const mode = computeEffectiveMode(props.levels.map((l) => l.policy));
	const proxy = pickDisplayAllowlist(props.levels);

	return (
		<div class="card">
			<h5>実効 fetch ポリシー</h5>
			<div class="gate">
				{props.levels.map((lvl, i) => (
					<>
						<div class="lvl">
							<b>{lvl.label}</b>
							{lvl.sub}
						</div>
						<div class={laneClass(lvl.policy.mode)}>
							<span class="tag">{laneTag(lvl.policy.mode)}</span>
							{laneBody(lvl.policy)}
						</div>
						{i < props.levels.length - 1 ? (
							<div class="arrow">
								∩<br />▼
							</div>
						) : null}
					</>
				))}
			</div>
			<div style="height:10px"></div>
			<div class={mode === "deny" ? "eff deny" : "eff"}>
				<small>EFFECTIVE — この関数が実際に fetch できる範囲</small>
				{mode === "deny"
					? "すべての fetch 呼び出しが拒否されます"
					: mode === "allow-all"
						? "制約なし（すべてのホストへ fetch 可能。ただし SSRF ガードは別途常時適用）"
						: proxy
							? `${proxy.policy.allow!.join(" / ")}（${proxy.label} の allowlist より。他段の allowlist にも同時に一致する必要があります）`
							: "allowlist モードですが、いずれの段にも許可ホストが設定されていません（実質すべて拒否）"}
			</div>
		</div>
	);
}

// ExecutionLog renders the function detail page's recent-invocation panel
// (tmp/09-dashboard.md §9.5) from GET .../logs (internal/api/functions.go's
// handleLogs, tmp/10-roadmap.md Phase 4). This is SSR: the caller
// (routes/functions.tsx) fetches the page's worth of entries once per
// request, no live tail/streaming is attempted here -- reload the page to
// see newer invocations (`funcbox logs --follow` is the CLI's live-tail
// equivalent for anyone who wants that).
export function ExecutionLog(props: { logs: InvocationLogDTO[] }) {
	if (props.logs.length === 0) {
		return (
			<div class="log">
				<div class="t">まだ実行ログがありません。この関数を呼び出すとここに表示されます。</div>
			</div>
		);
	}
	return (
		<div class="log">
			{props.logs.map((l) => (
				<>
					<div>
						<span class="t">{fmtTime(l.created_at)}</span> {l.method} {l.path}{" "}
						<span class={l.status >= 500 ? "lerr" : "lok"}>{l.status}</span> <span class="t">{l.duration_ms}ms</span>
					</div>
					{l.stdout ? <LogStream label="stdout" cls="lok" text={l.stdout} /> : null}
					{l.stderr ? <LogStream label="stderr" cls="lerr" text={l.stderr} /> : null}
					{l.fetch_decisions && l.fetch_decisions.length > 0 ? (
						<div class="t">
							fetch:{" "}
							{l.fetch_decisions
								.map((d) => `${d.allowed ? "ALLOW" : "DENY"} ${d.host}${d.port ? ":" + d.port : ""} (${d.stage})`)
								.join(", ")}
						</div>
					) : null}
				</>
			))}
		</div>
	);
}

function LogStream(props: { label: string; cls: string; text: string }) {
	const lines = props.text.replace(/\n+$/, "").split("\n");
	return (
		<>
			{lines.map((line) => (
				<div class={props.cls}>
					[{props.label}] {line}
				</div>
			))}
		</>
	);
}
