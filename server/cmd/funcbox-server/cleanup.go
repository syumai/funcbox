package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/syumai/funcbox/server/internal/settings"
	"github.com/syumai/funcbox/server/internal/store"
)

// logRetentionSweepInterval is how often runLogRetention checks for
// invocation logs to delete. Retention itself is measured in days
// (organization setting, default 7; see internal/settings), so an hourly
// sweep is frequent enough that the oldest a stale row ever gets is
// "retention + <1h", while still being cheap.
const logRetentionSweepInterval = 1 * time.Hour

// runLogRetention periodically deletes invocation_logs rows older than the
// "実行ログの保持期間設定"). It runs once immediately (so a freshly
// restarted server doesn't wait a full sweep interval before applying a
// changed retention setting) and then on logRetentionSweepInterval, until
// ctx is canceled (server shutdown).
//
// For a DynamoDB store, InvocationLogRepo.DeleteOlderThan is a documented
// no-op (retention there is enforced by a TTL attribute set at write time
// instead), so this goroutine is harmless, if redundant, on that backend
// too -- it doesn't need to special-case which store.Store implementation
// it's running against.
func runLogRetention(ctx context.Context, st store.Store, logger *slog.Logger) {
	sweep := func() {
		retention := logRetentionDays(ctx, st)
		cutoff := time.Now().Add(-time.Duration(retention) * 24 * time.Hour)
		n, err := st.InvocationLogs().DeleteOlderThan(ctx, cutoff)
		if err != nil {
			logger.Error("log retention sweep failed", "error", err)
			return
		}
		if n > 0 {
			logger.Info("log retention sweep", "deleted", n, "retention_days", retention)
		}
	}

	sweep()
	ticker := time.NewTicker(logRetentionSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep()
		}
	}
}

// logRetentionDays reads the organization's current log_retention_days
// setting, falling back to settings.DefaultLogRetentionDays if the
// organization hasn't been bootstrapped yet or its settings can't be
// parsed -- a sweep must never fail outright just because the org row
// isn't there yet on a brand new server.
func logRetentionDays(ctx context.Context, st store.Store) int {
	org, err := st.Organizations().Get(ctx)
	if err != nil {
		return settings.DefaultLogRetentionDays
	}
	orgSet, err := settings.ParseOrg(org.Settings)
	if err != nil || orgSet.LogRetentionDays <= 0 {
		return settings.DefaultLogRetentionDays
	}
	return orgSet.LogRetentionDays
}

// oauthCleanupSweepInterval is how often runOAuthCleanup runs, mirroring
// logRetentionSweepInterval's own reasoning: cheap, and frequent enough
// that neither swept entity lingers meaningfully past its own TTL/expiry.
const oauthCleanupSweepInterval = 1 * time.Hour

// oauthClientUnusedTTL bounds how long a dynamically registered OAuth
// client (server/internal/oauth's POST /oauth/register, RFC 7591 DCR) may
// sit unused before runOAuthCleanup deletes it -- part of that endpoint's
// storage-exhaustion defense in depth (security review finding A),
// alongside its own per-source rate limit and input-size bounds. 30 days
// is generous enough that a real MCP client's first actual connection
// (which is what turns a registration into a client with a grant) is never
// plausibly delayed that long past its own registration, while still
// bounding how long an abandoned or abusive registration's row survives.
const oauthClientUnusedTTL = 30 * 24 * time.Hour

// runOAuthCleanup periodically sweeps two server/internal/oauth entities
// that need bounded lifetimes but have no other periodic owner:
//
//   - oauth_clients rows that were never used to complete an authorization
//     (store.OAuthClientRepo.DeleteUnusedOlderThan) -- see
//     oauthClientUnusedTTL.
//   - oauth_auth_codes rows past their (few-minutes) expiry
//     (store.OAuthAuthCodeRepo.DeleteExpired). SQL backends already
//     opportunistically delete these on every new Create, and a DynamoDB
//     backend self-expires them via its ttl attribute, so this half of the
//     sweep is redundant-but-harmless defense in depth for SQL and a
//     tighter bound than DynamoDB's own (eventually-consistent) TTL sweep.
//
// Runs once immediately, then on oauthCleanupSweepInterval, until ctx is
// canceled -- same lifecycle as runLogRetention, which this mirrors.
func runOAuthCleanup(ctx context.Context, st store.Store, logger *slog.Logger) {
	sweep := func() {
		now := time.Now()
		if n, err := st.OAuthClients().DeleteUnusedOlderThan(ctx, now.Add(-oauthClientUnusedTTL)); err != nil {
			logger.Error("oauth client cleanup sweep failed", "error", err)
		} else if n > 0 {
			logger.Info("oauth client cleanup sweep", "deleted", n)
		}
		if n, err := st.OAuthAuthCodes().DeleteExpired(ctx, now); err != nil {
			logger.Error("oauth auth code cleanup sweep failed", "error", err)
		} else if n > 0 {
			logger.Info("oauth auth code cleanup sweep", "deleted", n)
		}
	}

	sweep()
	ticker := time.NewTicker(oauthCleanupSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep()
		}
	}
}
