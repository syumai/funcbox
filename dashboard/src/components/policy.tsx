// policy.tsx renders the function detail page's centerpiece
// (tmp/09-dashboard.md §9.5: "実効 fetch ポリシーを組織 / WS / manifest の
// 3 段で可視化"): a gate pipeline of the three policy levels intersected
// (∩) into one effective result, mirroring internal/policy.Effective's
// actual semantics (deny wins; allow-all only if every level is; otherwise
// a request must satisfy EVERY allowlist level simultaneously).
import type { FetchPolicyDTO } from "../types";

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

// ExecutionLog is a placeholder: this phase's backend has no per-invocation
// fetch-decision log store (internal/store only has the privileged-action
// AuditLog, not a per-request ALLOW/DENY trail), so rendering fabricated
// log lines here would misrepresent what funcbox actually records. The
// "console island" box the mockup specifies is kept as a structural
// placeholder -- dark-fixed styling and all -- so wiring in real log data
// later (a follow-up phase) is a pure content change, not a redesign.
export function ExecutionLog() {
	return (
		<div class="log">
			<div class="t">実行ログの収集は現バージョンでは未実装です。org/ws/manifest のポリシーは上記の通り即時に反映され、実際の fetch 呼び出しはこの範囲でのみ許可されます。</div>
		</div>
	);
}
