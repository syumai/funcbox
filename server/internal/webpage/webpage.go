// Package webpage renders funcbox's small set of server-side (non-React)
// HTML pages -- the dev IdP sign-in form, the dashboard's pending-approval
// and sign-in-failed pages, the invoke path's access-denied page, and
// GitHub's account-link confirmation page -- with one shared, self-contained
// shell: a centered card, the funcbox wordmark, and the SAME "Operator"
// design tokens the dashboard's own React app uses
// (server/dashboard/src/styles.css: amber accent, light/dark via
// prefers-color-scheme). The stylesheet is inlined into every page rather
// than linked, since some of these pages (most notably invoke's
// access-denied page) are served from arbitrary function hosts, not the
// dashboard's own origin, where /dashboard/assets/* may not be reachable at
// all.
//
// This package deliberately produces plain format-string HTML, not a
// template engine or the dashboard's hono/jsx stack -- these pages are few,
// small, and need no client-side interactivity. Every value interpolated
// from caller-controlled or stored data (an email address, an error
// message, ...) MUST be HTML-escaped by the caller (html.EscapeString)
// before being passed in; Page and its sibling helpers do not escape their
// arguments themselves, matching the pre-existing pages this package
// replaces.
package webpage

import (
	"context"
	"fmt"

	"github.com/syumai/funcbox/server/internal/settings"
	"github.com/syumai/funcbox/server/internal/store"
)

// Lang is one of the two languages this package's pages can render in.
type Lang string

const (
	LangEN Lang = "en"
	LangJA Lang = "ja"
)

// ResolveLang normalizes an arbitrary language string (typically an
// organization's settings.Org.Language) to one of this package's two
// supported languages, defaulting to English for anything else -- unset,
// malformed, or pre-migration data.
func ResolveLang(language string) Lang {
	if language == string(LangJA) {
		return LangJA
	}
	return LangEN
}

// OrgLanguage resolves the language these pages render in: the
// organization's default (settings.Org.Language), defaulting to English on
// any lookup failure (no organization row yet, a store error, ...) --
// mirroring the fail-closed pattern internal/auth's own
// requireApprovalEnabled uses for the same settings document. Unlike the
// dashboard React app's own per-request language resolution
// (settings.EffectiveLanguage, api/me.go's effective_language), these pages
// never consult a signed-in user's personal language preference: several of
// them (the dev sign-in form, the sign-in-failed page, the GitHub link
// confirmation page) render before any user/session exists at all, so
// resolving a per-user override consistently across all of them would need
// plumbing these deliberately minimal pages don't warrant. The organization
// default is a reasonable single source of truth for all of them.
func OrgLanguage(ctx context.Context, st store.Store) Lang {
	if st == nil {
		return LangEN
	}
	org, err := st.Organizations().Get(ctx)
	if err != nil {
		return LangEN
	}
	orgSet, err := settings.ParseOrg(org.Settings)
	if err != nil {
		return LangEN
	}
	return ResolveLang(orgSet.Language)
}

// Page renders a complete, self-contained HTML document: doctype, head with
// an inlined stylesheet, and a centered card containing the funcbox
// wordmark followed by bodyHTML verbatim. title becomes the document's
// <title> and must be a literal, static string (never caller-controlled
// data) -- every call site in this codebase passes one.
func Page(title, bodyHTML string) string {
	return fmt.Sprintf(pageTemplate, title, css, bodyHTML)
}

const pageTemplate = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>%s</title>
<style>%s</style>
</head>
<body>
<div class="wp-shell">
<div class="wp-card">
<div class="wp-brand"><span class="wp-cube"></span><b>funcbox</b></div>
%s
</div>
</div>
</body></html>`

// css is the shared "Operator" token stylesheet, trimmed to only what these
// small card pages need (no sidebar/nav/table styles -- see the dashboard's
// own server/dashboard/src/styles.css for the full set this is drawn from).
// Token values are copied verbatim from that file's :root / dark-mode
// blocks so both surfaces stay visually identical.
const css = `
:root {
	--bg: #f6f6f4; --panel: #ffffff; --line: #dddcd5;
	--ink: #23262b; --sub: #6c7078; --faint: #989ca5;
	--accent: #a86f0b; --accent-bg: #e8a33d; --accent-ink: #241a06;
	--code-bg: #f1f0ec; --err: #c23649;
}
@media (prefers-color-scheme: dark) {
	:root {
		--bg: #15181d; --panel: #101319; --line: #262b34;
		--ink: #d6dae2; --sub: #8d95a3; --faint: #5b6270;
		--accent: #e8a33d; --accent-bg: #e8a33d; --accent-ink: #20180a;
		--code-bg: #0d1015; --err: #f7768e;
	}
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
	background: var(--bg); color: var(--ink); min-height: 100vh;
	display: flex; align-items: center; justify-content: center; padding: 24px;
	font-family: "Hiragino Sans", "Yu Gothic UI", "Noto Sans JP", system-ui, sans-serif;
	font-size: 14px; line-height: 1.6;
}
.wp-shell { width: 100%; max-width: 480px; }
.wp-card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 30px 32px; }
.wp-brand { display: flex; align-items: center; gap: 8px; margin-bottom: 20px; }
.wp-cube { width: 20px; height: 20px; border-radius: 5px; background: linear-gradient(135deg, #e8a33d, #c97b16); flex: none; }
.wp-brand b { font-size: 14.5px; letter-spacing: .03em; color: var(--ink); }
.wp-card h1 { font-size: 20px; margin: 0 0 14px; font-weight: 700; color: var(--ink); }
.wp-card p { font-size: 14px; color: var(--sub); margin: 0 0 16px; }
.wp-card strong { color: var(--ink); }
.wp-card hr { border: none; border-top: 1px solid var(--line); margin: 24px 0; }
.wp-card label { display: block; font-size: 13px; color: var(--sub); margin-bottom: 6px; }
.wp-card input[type=email], .wp-card input[type=text] {
	width: 100%; background: var(--code-bg); border: 1px solid var(--line); border-radius: 6px;
	padding: 8px 12px; color: var(--ink); font-size: 13.5px; margin-bottom: 16px;
}
.wp-btn {
	display: inline-block; background: var(--accent-bg); color: var(--accent-ink);
	font-weight: 700; border: none; border-radius: 6px; padding: 8px 18px; font-size: 13.5px;
	cursor: pointer; text-decoration: none; font-family: inherit;
}
.wp-btn:hover { text-decoration: none; filter: brightness(0.96); }
.wp-btn.wp-btn-ghost { background: var(--panel); color: var(--ink); border: 1px solid var(--line); font-weight: 500; }
.wp-link { color: var(--accent); font-weight: 600; font-size: 13.5px; text-decoration: none; }
.wp-link:hover { text-decoration: underline; }
.wp-note { font-size: 12.5px; color: var(--faint); margin-top: 16px; }
.wp-err { color: var(--err); }
`
