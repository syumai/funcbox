// accessdenied.go renders the invoke path's browser-facing "access denied"
// page: what a browser-like GET/HEAD request sees when it's authenticated
// (a valid session behind the invoke SSO cookie, or -- see invoke.go's authorize --
// an already-consumed one) but not authorized for the specific function it
// asked for, either because the identity itself currently can't invoke
// anything (pending approval, disabled, or excluded by the organization's
// login rules -- auth.ErrInvokeForbidden) or because it simply isn't a
// member of the function's workspace. A bare {"error":...} JSON body (what
// every non-browser caller still gets) would just render as text in a
// browser tab, so this mirrors internal/dashboard's own
// writePendingApprovalPage: a minimal, self-contained page rendered via the
// shared server/internal/webpage shell rather than routing through any app
// framework -- deliberately simple, since it exists on every function
// host, not just the dashboard's own origin.
//
// It is intentionally generic rather than trying to explain the SPECIFIC
// reason for the denial (pending vs. disabled vs. not-a-workspace-member):
// the invoke path already reports that precisely in the JSON body for
// non-browser callers, and the one actionable thing a human browsing here
// can do either way is go check their account on the dashboard -- which
// itself already renders the right thing for whichever state actually
// applies (e.g. the pending-approval page, if that's the reason).
//
// Rendered in the organization's default language only (webpage.OrgLanguage,
// resolved by the caller via inv.Auth.OrgLanguage since this file has no
// store access of its own), matching every other Go-rendered auth-adjacent
// page (item 2 of the auth-pages styling work).
package invoke

import (
	"fmt"
	"html"
	"net/http"

	"github.com/syumai/funcbox/server/internal/webpage"
)

func writeInvokeAccessDeniedPage(w http.ResponseWriter, lang webpage.Lang, dashboardURL string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	msg := invokeAccessDeniedMessages[lang]
	escapedURL := html.EscapeString(dashboardURL)
	body := fmt.Sprintf(`<h1>%s</h1>
<p>%s</p>
<p><a href="%s" class="wp-link">%s</a></p>`,
		msg.heading, msg.description, escapedURL, msg.link)
	fmt.Fprint(w, webpage.Page(msg.title, body))
}

type invokeAccessDeniedMessage struct {
	title, heading, description, link string
}

var invokeAccessDeniedMessages = map[webpage.Lang]invokeAccessDeniedMessage{
	webpage.LangEN: {
		title:   "funcbox -- access denied",
		heading: "Access denied",
		description: "You're signed in, but your account does not currently have access to " +
			"this function. If you're waiting on an administrator's approval or a " +
			"workspace invitation, check your account status on the dashboard.",
		link: "Go to the funcbox dashboard",
	},
	webpage.LangJA: {
		title:   "funcbox -- アクセス権がありません",
		heading: "アクセス権がありません",
		description: "ログインは完了していますが、この関数へのアクセス権がありません。" +
			"承認待ち、またはワークスペースへの招待が必要な場合は、ダッシュボードで" +
			"アカウントの状態をご確認ください。",
		link: "funcbox ダッシュボードへ",
	},
}
