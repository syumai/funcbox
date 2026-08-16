package dynamodb

import (
	"fmt"

	"github.com/syumai/funcbox/server/internal/store"
)

// This file centralizes the single-table PK/SK layout from
// handful of application-maintained index items this package adds beyond
// that table (documented inline where they diverge). Keeping every key
// shape in one place makes the mapping auditable against the design doc at
// a glance.
//
//	PK                                SK                    entity
//	ORG                               META                  organization
//	ORG                               BOOTSTRAP_LOCK        bootstrap singleton lock (this package's addition; see aggregate.go)
//	ORG                               RULE#<0-padded ord>   login_rule
//	USER#<id>                         META                  user
//	USER#PROVIDER#<provider>#<sub>    META                  GSI-substitute lookup item (id only)
//	HANDLE#<handle>                   META                  handle
//	WS#<id>                           META                  workspace
//	WS#<id>                           MEMBER#<user_id>      workspace_member
//	FUNC#<id>                         META                  function (primary item; also the VER#/ENV# partition)
//	FUNC#<id>                         VER#<version_id>      function_version
//	FUNC#<id>                         ENV#<key>             env_var
//	FUNC#<ownerType>:<ownerID>#<name> META                  function owner+name lookup pointer (id only)
//	FUNCNAME#<name>                   META                  installation-global name claim
//	FUNCLIST#<ownerType>:<ownerID>    <function_id>          function-by-owner index item (this package's addition; see functions.go)
//	SESSION#<id>                      META                  session (TTL via ttlAttribute)
//	CLIAUTHCODE#<id>                  META                  cli_auth_code (TTL via ttlAttribute)
//	CLICRED#<hash>                    META                  cli_credential
//	CLICREDID#<id>                    META                  cli_credential by-id lookup pointer (id only)
//	OAUTHCLIENT#<id>                  META                  oauth_client
//	OAUTHAUTHCODE#<id>                META                  oauth_auth_code (TTL via ttlAttribute)
//	OAUTHGRANT#<hash>                 META                  oauth_grant
//	OAUTHGRANTID#<id>                 META                  oauth_grant by-id lookup pointer (id only)
//	OAUTHGRANTPREV#<hash>             META                  oauth_grant reuse-detection pointer (id only; see oauthgrants.go's Rotate/RevokeIfPreviousSecret)
//	AUDIT#<yyyymm>                    <ulid>                audit_log
//	INVLOG#<function_id>              <ulid>                invocation_log (TTL via ttlAttribute)
const (
	skMeta          = "META"
	skBootstrapLock = "BOOTSTRAP_LOCK"
)

const pkOrg = "ORG"

func skLoginRule(ord int) string { return fmt.Sprintf("RULE#%010d", ord) }

func pkUser(id string) string { return "USER#" + id }

// pkUserProviderSubject is the GSI-substitute lookup key for
// UserRepo.ByProviderSubject (formerly ByGoogleSub / "USER#SUB#<sub>";
// see migrate_user_provider.go for the one-time migration off the old
// key shape).
func pkUserProviderSubject(provider store.Provider, subject string) string {
	return "USER#PROVIDER#" + string(provider) + "#" + subject
}

// pkUserSubLegacy is the pre-migration lookup key
// ("USER#SUB#<google_sub>"), kept only so migrate_user_provider.go can
// locate and remove leftover legacy pointer items.
func pkUserSubLegacy(sub string) string { return "USER#SUB#" + sub }

func pkHandle(handle string) string { return "HANDLE#" + handle }

func pkWorkspace(id string) string  { return "WS#" + id }
func skMember(userID string) string { return "MEMBER#" + userID }

// funcOwnerKey is the "<ownerType>:<ownerID>" fragment shared by both the
// function owner+name lookup pointer's PK and the FUNCLIST index's PK.
func funcOwnerKey(ownerType, ownerID string) string { return string(ownerType) + ":" + ownerID }

func pkFunc(id string) string    { return "FUNC#" + id }
func skVersion(id string) string { return "VER#" + id }
func skEnv(key string) string    { return "ENV#" + key }

func pkFuncPtr(ownerType, ownerID, name string) string {
	return "FUNC#" + funcOwnerKey(ownerType, ownerID) + "#" + name
}

func pkFuncName(name string) string { return "FUNCNAME#" + name }

func pkFuncList(ownerType, ownerID string) string {
	return "FUNCLIST#" + funcOwnerKey(ownerType, ownerID)
}

// pkVersion is the global by-id lookup key for a function_version (this
// FUNC#<id>/VER#<version_id> item alone can't answer
// FunctionRepo.Version(ctx, id), which is handed only a version id with no
// function id, so CreateVersion additionally writes a full duplicate under
// this key; see functions.go). Safe to duplicate because versions are
// immutable once created.
func pkVersion(id string) string { return "VER#" + id }

func pkSession(id string) string        { return "SESSION#" + id }
func pkInvokeAuthCode(id string) string { return "INVOKEAUTH#" + id }

func pkCLIAuthCode(id string) string { return "CLIAUTHCODE#" + id }

func pkCLICredential(secretHash string) string { return "CLICRED#" + secretHash }

// pkCLICredentialID is a by-id lookup pointer for a cli_credential (this
// package's addition, same pattern as the retired api_token's
// TOKENID#<id> pointer): Touch/Delete/revoke are handed only an id, but
// the table's own key shape, CLICRED#<hash>, requires the hash to address
// an item directly; see clicredentials.go.
func pkCLICredentialID(id string) string { return "CLICREDID#" + id }

func pkOAuthClient(id string) string { return "OAUTHCLIENT#" + id }

func pkOAuthAuthCode(id string) string { return "OAUTHAUTHCODE#" + id }

func pkOAuthGrant(secretHash string) string { return "OAUTHGRANT#" + secretHash }

// pkOAuthGrantID is a by-id lookup pointer for an oauth_grant, same
// pattern as pkCLICredentialID: Touch/Delete are handed only an id, but
// the table's own key shape, OAUTHGRANT#<hash>, requires the hash to
// address an item directly; see oauthgrants.go.
func pkOAuthGrantID(id string) string { return "OAUTHGRANTID#" + id }

// pkOAuthGrantPrev is the reuse-detection lookup pointer written by
// Rotate for the secret hash it just retired (store.OAuthGrant.
// PrevSecretHash's storage counterpart) and consulted by
// RevokeIfPreviousSecret. Only one exists per grant at a time -- Rotate
// deletes the previous rotation's pointer as it writes the new one; see
// oauthgrants.go.
func pkOAuthGrantPrev(hash string) string { return "OAUTHGRANTPREV#" + hash }

func pkAudit(month string) string { return "AUDIT#" + month }

func pkInvocationLog(functionID string) string { return "INVLOG#" + functionID }
