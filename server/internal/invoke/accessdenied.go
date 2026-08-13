// accessdenied.go renders the invoke path's browser-facing "access denied"
// page (tmp/14-auth-and-pool-improvements.md §14.3, item 3): what a
// browser-like GET/HEAD request sees when it's authenticated (a valid
// session behind the invoke SSO cookie, or -- see invoke.go's authorize --
// an already-consumed one) but not authorized for the specific function it
// asked for, either because the identity itself currently can't invoke
// anything (pending approval, disabled, or excluded by the organization's
// login rules -- auth.ErrInvokeForbidden) or because it simply isn't a
// member of the function's workspace. A bare {"error":...} JSON body (what
// every non-browser caller still gets) would just render as text in a
// browser tab, so this mirrors internal/dashboard's own
// writePendingApprovalPage: a minimal, dependency-free, bilingual
// (English+Japanese) static page rather than routing through any app
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
package invoke

import (
	"fmt"
	"html"
	"net/http"
)

func writeInvokeAccessDeniedPage(w http.ResponseWriter, dashboardURL string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, invokeAccessDeniedPageHTML, html.EscapeString(dashboardURL), html.EscapeString(dashboardURL))
}

const invokeAccessDeniedPageHTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>funcbox -- access denied / アクセス権がありません</title></head>
<body style="font-family:sans-serif;padding:40px;max-width:640px;margin:0 auto;line-height:1.6">
<h1>Access denied</h1>
<p>You're signed in, but your account does not currently have access to
this function. If you're waiting on an administrator's approval or a
workspace invitation, check your account status on the dashboard.</p>
<p><a href="%s">Go to the funcbox dashboard</a></p>
<hr style="margin:32px 0">
<h1>アクセス権がありません</h1>
<p>ログインは完了していますが、この関数へのアクセス権がありません。
承認待ち、またはワークスペースへの招待が必要な場合は、ダッシュボードで
アカウントの状態をご確認ください。</p>
<p><a href="%s">funcbox ダッシュボードへ</a></p>
</body></html>`
