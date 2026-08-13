// Package authz implements funcbox's authorization matrix
// (tmp/07-http-api.md §7.4): given an authenticated actor and the minimal
// context an operation needs (org settings flags, the actor's role within
// a specific workspace, ...), it decides whether the operation is
// permitted. It has no knowledge of HTTP or storage -- callers (internal/
// api, internal/service) are responsible for gathering the inputs (e.g.
// looking up the actor's workspace membership) and reacting to the
// boolean result (404 to hide existence, 403 to refuse a known-visible
// action, 409 for the last-admin guard, ...).
//
// Every decision function takes explicit, already-resolved inputs rather
// than reaching into a store itself, which is what makes the table-driven
// tests in authz_test.go possible: the whole permission matrix is
// exercised without a database.
package authz

import "github.com/syumai/funcbox/server/internal/store"

// Actor is the authenticated caller's identity for an authorization
// decision. A single Actor may act against many different workspaces
// within one request's lifetime (e.g. the org/workspace list endpoints),
// so workspace-scoped role information is passed per-call rather than
// embedded here.
type Actor struct {
	UserID string
	Role   store.Role // organization-wide role: admin | member
}

// IsOrgAdmin reports whether a holds the organization-wide admin role. Per
// tmp/05-auth-and-permissions.md §5.3, an org admin implicitly holds admin
// rights over every workspace too ("Org Admin は暗黙的にすべての WS の
// Admin 相当の権限を持つ"), which is why every Can* function below checks
// this first and short-circuits to "allowed".
func (a Actor) IsOrgAdmin() bool { return a.Role == store.RoleAdmin }

// CanUpdateOrgSettings: 組織設定変更 (org admin only).
func CanUpdateOrgSettings(a Actor) bool { return a.IsOrgAdmin() }

// CanReadAuditLog: 監査ログ閲覧 (org admin only).
func CanReadAuditLog(a Actor) bool { return a.IsOrgAdmin() }

// CanManageOrgUsers: role changes / disabling other users (org admin
// only; the caller is additionally responsible for the last-admin guard,
// which needs a live admin count this package deliberately doesn't fetch
// -- see the "last admin" note in this package's doc comment and
// internal/service's org user handler).
func CanManageOrgUsers(a Actor) bool { return a.IsOrgAdmin() }

// CanCreateWorkspace: WS 作成 (org admin, or any user when the org setting
// allows it).
func CanCreateWorkspace(a Actor, allowWorkspaceCreation bool) bool {
	return a.IsOrgAdmin() || allowWorkspaceCreation
}

// CanManageWorkspace: WS 設定・メンバー変更. wsRole is the actor's role
// within THIS workspace; nil means "not a member".
func CanManageWorkspace(a Actor, wsRole *store.Role) bool {
	return a.IsOrgAdmin() || (wsRole != nil && *wsRole == store.RoleAdmin)
}

// CanDeployToWorkspace: WS 関数デプロイ. memberCanDeploy is the
// workspace's own member_can_deploy setting (tmp/05-auth-and-permissions.md
// §5.5); WS admins can always deploy regardless of it.
func CanDeployToWorkspace(a Actor, wsRole *store.Role, memberCanDeploy bool) bool {
	if a.IsOrgAdmin() {
		return true
	}
	if wsRole == nil {
		return false
	}
	if *wsRole == store.RoleAdmin {
		return true
	}
	return memberCanDeploy
}

// CanDeployPersonal: 個人関数デプロイ. ownerUserID is the handle's owning
// user. Per tmp/07-http-api.md §7.4's "組織設定次第（自分の handle 配下
// のみ）", a general member may only ever deploy under their own handle,
// gated by the org's allow_user_functions setting; an org admin's
// blanket access lets them deploy under any personal handle regardless of
// that setting (mirroring their unconditional access to every workspace).
func CanDeployPersonal(a Actor, ownerUserID string, allowUserFunctions bool) bool {
	if a.IsOrgAdmin() {
		return true
	}
	return allowUserFunctions && a.UserID == ownerUserID
}

// CanManageFunction covers every function-scoped write this task's matrix
// treats as following "deploy rights" -- version rollback, deletion, and
// env var management (tmp/07-http-api.md §7.4's "関数の env 設定:
// デプロイ権限に準ずる" / "自分の関数のみ"). ownerType/ownerUserID
// describe the function's owner (a workspace or a user); for a
// workspace-owned function, wsRole/memberCanDeploy are that workspace's
// values for the actor, same as CanDeployToWorkspace.
func CanManageFunction(a Actor, ownerType store.OwnerType, ownerUserID string, wsRole *store.Role, memberCanDeploy bool) bool {
	if ownerType == store.OwnerTypeWorkspace {
		return CanDeployToWorkspace(a, wsRole, memberCanDeploy)
	}
	return a.IsOrgAdmin() || a.UserID == ownerUserID
}

// Action names one of the operations in tmp/07-http-api.md §7.4's matrix,
// for use with Can.
type Action string

const (
	ActionOrgSettingsUpdate Action = "org.settings.update"
	ActionOrgUsersManage    Action = "org.users.manage"
	ActionAuditRead         Action = "audit.read"
	ActionWorkspaceCreate   Action = "workspace.create"
	ActionWorkspaceManage   Action = "workspace.manage"
	ActionWorkspaceDeploy   Action = "workspace.deploy"
	ActionPersonalDeploy    Action = "personal.deploy"
	ActionFunctionManage    Action = "function.manage" // rollback, delete, env
)

// Target bundles every optional input Can's Action variants might need.
// Only the fields relevant to the chosen Action are read.
type Target struct {
	AllowWorkspaceCreation bool
	AllowUserFunctions     bool
	WorkspaceRole          *store.Role
	MemberCanDeploy        bool
	OwnerType              store.OwnerType
	OwnerUserID            string
}

// Can dispatches to the Can* function matching action, per
// tmp/07-http-api.md §7.4: "認可判定は policy [here:
// internal/authz] に集約し、ハンドラは policy.Can(actor, action, target)
// を呼ぶだけにする". The individual Can* functions above remain exported
// (and are what Can itself calls) because most call sites already have
// their inputs in hand and a direct call reads more clearly than
// constructing a Target; Can exists for the cases -- e.g. a
// generic pre-handler check -- where dispatching on a uniform Action enum
// is more convenient.
func Can(a Actor, action Action, t Target) bool {
	switch action {
	case ActionOrgSettingsUpdate:
		return CanUpdateOrgSettings(a)
	case ActionOrgUsersManage:
		return CanManageOrgUsers(a)
	case ActionAuditRead:
		return CanReadAuditLog(a)
	case ActionWorkspaceCreate:
		return CanCreateWorkspace(a, t.AllowWorkspaceCreation)
	case ActionWorkspaceManage:
		return CanManageWorkspace(a, t.WorkspaceRole)
	case ActionWorkspaceDeploy:
		return CanDeployToWorkspace(a, t.WorkspaceRole, t.MemberCanDeploy)
	case ActionPersonalDeploy:
		return CanDeployPersonal(a, t.OwnerUserID, t.AllowUserFunctions)
	case ActionFunctionManage:
		return CanManageFunction(a, t.OwnerType, t.OwnerUserID, t.WorkspaceRole, t.MemberCanDeploy)
	default:
		return false
	}
}
