package auth

import (
	"context"
	"encoding/json"

	"github.com/syumai/funcbox/internal/store"
)

// Audit appends an audit_logs entry (tmp/05-auth-and-permissions.md §5.7).
// It is exported so internal/api can reuse the exact same
// marshal-and-append logic for the audit events it's responsible for
// (settings changes, membership changes, deploys, ...); auth.go itself
// only ever calls it for "user.login".
//
// Audit failures are logged by the caller, not surfaced as request
// failures -- losing an audit entry must never block the underlying
// action it's describing.
func Audit(ctx context.Context, st store.Store, actorID, action, target string, detail any) error {
	var detailJSON []byte
	if detail != nil {
		b, err := json.Marshal(detail)
		if err != nil {
			return err
		}
		detailJSON = b
	} else {
		detailJSON = []byte("{}")
	}
	return st.Audit().Append(ctx, &store.AuditLog{
		ActorID: actorID,
		Action:  action,
		Target:  target,
		Detail:  detailJSON,
	})
}
