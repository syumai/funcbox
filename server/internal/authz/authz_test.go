// matrix, one subtest per matrix row, each exercising all four archetypal
// actors (Org Admin, WS Admin, WS Member, general user) from that row's
// columns.
package authz_test

import (
	"testing"

	"github.com/syumai/funcbox/server/internal/authz"
	"github.com/syumai/funcbox/server/internal/store"
)

var (
	orgAdmin = authz.Actor{UserID: "u-admin", Role: store.RoleAdmin}
	genUser  = authz.Actor{UserID: "u-member", Role: store.RoleMember}

	roleAdmin  = store.RoleAdmin
	roleMember = store.RoleMember
)

func TestMatrix_OrgSettingsChange(t *testing.T) {
	// 組織設定変更: Org Admin only.
	if !authz.CanUpdateOrgSettings(orgAdmin) {
		t.Error("org admin should be able to update org settings")
	}
	if authz.CanUpdateOrgSettings(genUser) {
		t.Error("general user should not be able to update org settings")
	}
}

func TestMatrix_WorkspaceCreate(t *testing.T) {
	// WS 作成: Org Admin always; general user only if the org setting
	// allows it.
	if !authz.CanCreateWorkspace(orgAdmin, false) {
		t.Error("org admin should always be able to create a workspace")
	}
	if authz.CanCreateWorkspace(genUser, false) {
		t.Error("general user should not be able to create a workspace when the org setting disallows it")
	}
	if !authz.CanCreateWorkspace(genUser, true) {
		t.Error("general user should be able to create a workspace when the org setting allows it")
	}
}

func TestMatrix_WorkspaceManage(t *testing.T) {
	// WS 設定・メンバー変更: Org Admin, WS Admin (own WS) only.
	wsAdmin := authz.Actor{UserID: "u-wsadmin", Role: store.RoleMember}
	wsMember := authz.Actor{UserID: "u-wsmember", Role: store.RoleMember}

	if !authz.CanManageWorkspace(orgAdmin, nil) {
		t.Error("org admin should be able to manage any workspace, even one it's not a member of")
	}
	if !authz.CanManageWorkspace(wsAdmin, &roleAdmin) {
		t.Error("WS admin should be able to manage their own workspace")
	}
	if authz.CanManageWorkspace(wsMember, &roleMember) {
		t.Error("WS member should not be able to manage the workspace")
	}
	if authz.CanManageWorkspace(genUser, nil) {
		t.Error("a non-member general user should not be able to manage the workspace")
	}
}

func TestMatrix_WorkspaceDeploy(t *testing.T) {
	// WS 関数デプロイ: Org Admin, WS Admin always; WS Member per WS
	// setting; general (non-member) never.
	wsAdmin := authz.Actor{UserID: "u-wsadmin", Role: store.RoleMember}
	wsMember := authz.Actor{UserID: "u-wsmember", Role: store.RoleMember}

	if !authz.CanDeployToWorkspace(orgAdmin, nil, false) {
		t.Error("org admin should always be able to deploy to a workspace")
	}
	if !authz.CanDeployToWorkspace(wsAdmin, &roleAdmin, false) {
		t.Error("WS admin should be able to deploy even when member_can_deploy is false")
	}
	if authz.CanDeployToWorkspace(wsMember, &roleMember, false) {
		t.Error("WS member should not be able to deploy when member_can_deploy is false")
	}
	if !authz.CanDeployToWorkspace(wsMember, &roleMember, true) {
		t.Error("WS member should be able to deploy when member_can_deploy is true")
	}
	if authz.CanDeployToWorkspace(genUser, nil, true) {
		t.Error("non-member should not be able to deploy regardless of member_can_deploy")
	}
}

func TestMatrix_PersonalDeploy(t *testing.T) {
	// 個人関数デプロイ: Org Admin always (even under someone else's
	// User ID); general user only under their OWN User ID, gated by the
	// org setting.
	if !authz.CanDeployPersonal(orgAdmin, "someone-elses-user-id", false) {
		t.Error("org admin should be able to deploy under any public User ID regardless of the org setting")
	}
	if authz.CanDeployPersonal(genUser, genUser.UserID, false) {
		t.Error("general user should not be able to deploy personally when the org setting disallows it")
	}
	if !authz.CanDeployPersonal(genUser, genUser.UserID, true) {
		t.Error("general user should be able to deploy under their own User ID when the org setting allows it")
	}
	if authz.CanDeployPersonal(genUser, "someone-elses-user-id", true) {
		t.Error("general user should never be able to deploy under someone else's User ID")
	}
}

func TestMatrix_FunctionEnvManage(t *testing.T) {
	// 関数の env 設定: Org Admin always; WS Admin (own WS); WS Member
	// follows deploy rights; general user only their own function.
	wsAdmin := authz.Actor{UserID: "u-wsadmin", Role: store.RoleMember}
	wsMember := authz.Actor{UserID: "u-wsmember", Role: store.RoleMember}

	// Workspace-owned function.
	if !authz.CanManageFunction(orgAdmin, store.OwnerTypeWorkspace, "", nil, false) {
		t.Error("org admin should manage env vars on any workspace function")
	}
	if !authz.CanManageFunction(wsAdmin, store.OwnerTypeWorkspace, "", &roleAdmin, false) {
		t.Error("WS admin should manage env vars on their own workspace's function")
	}
	if authz.CanManageFunction(wsMember, store.OwnerTypeWorkspace, "", &roleMember, false) {
		t.Error("WS member should not manage env vars when member_can_deploy is false")
	}
	if !authz.CanManageFunction(wsMember, store.OwnerTypeWorkspace, "", &roleMember, true) {
		t.Error("WS member should manage env vars when member_can_deploy is true (follows deploy rights)")
	}

	// User-owned (personal) function.
	if !authz.CanManageFunction(orgAdmin, store.OwnerTypeUser, "someone-else", nil, false) {
		t.Error("org admin should manage env vars on any personal function")
	}
	if !authz.CanManageFunction(genUser, store.OwnerTypeUser, genUser.UserID, nil, false) {
		t.Error("general user should manage env vars on their own function")
	}
	if authz.CanManageFunction(genUser, store.OwnerTypeUser, "someone-else", nil, false) {
		t.Error("general user should not manage env vars on someone else's personal function")
	}
}

func TestMatrix_AuditLogRead(t *testing.T) {
	// 監査ログ閲覧: Org Admin only.
	if !authz.CanReadAuditLog(orgAdmin) {
		t.Error("org admin should be able to read the audit log")
	}
	if authz.CanReadAuditLog(genUser) {
		t.Error("general user should not be able to read the audit log")
	}
}

func TestCan_DispatchesToMatchingFunction(t *testing.T) {
	tests := []struct {
		name   string
		actor  authz.Actor
		action authz.Action
		target authz.Target
		want   bool
	}{
		{"org settings, admin", orgAdmin, authz.ActionOrgSettingsUpdate, authz.Target{}, true},
		{"org settings, member", genUser, authz.ActionOrgSettingsUpdate, authz.Target{}, false},
		{"ws create, allowed by org setting", genUser, authz.ActionWorkspaceCreate, authz.Target{AllowWorkspaceCreation: true}, true},
		{"ws create, disallowed", genUser, authz.ActionWorkspaceCreate, authz.Target{AllowWorkspaceCreation: false}, false},
		{"ws manage, ws admin", genUser, authz.ActionWorkspaceManage, authz.Target{WorkspaceRole: &roleAdmin}, true},
		{"ws deploy, ws member allowed", genUser, authz.ActionWorkspaceDeploy, authz.Target{WorkspaceRole: &roleMember, MemberCanDeploy: true}, true},
		{"personal deploy, self", genUser, authz.ActionPersonalDeploy, authz.Target{OwnerUserID: genUser.UserID, AllowUserFunctions: true}, true},
		{"personal deploy, other", genUser, authz.ActionPersonalDeploy, authz.Target{OwnerUserID: "other", AllowUserFunctions: true}, false},
		{"function manage, own", genUser, authz.ActionFunctionManage, authz.Target{OwnerType: store.OwnerTypeUser, OwnerUserID: genUser.UserID}, true},
		{"audit read, admin", orgAdmin, authz.ActionAuditRead, authz.Target{}, true},
		{"unknown action", orgAdmin, authz.Action("bogus"), authz.Target{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := authz.Can(tt.actor, tt.action, tt.target); got != tt.want {
				t.Errorf("Can(%+v, %q, %+v) = %v, want %v", tt.actor, tt.action, tt.target, got, tt.want)
			}
		})
	}
}
