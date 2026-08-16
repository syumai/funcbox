-- Refresh-token rotation (security review finding B): oauth_grants gains a
-- prev_secret_hash column recording the sha256 hex of the refresh token
-- secret a grant carried immediately before its most recent rotation
-- (empty string until the grant's first rotation). See
-- store.OAuthGrant.PrevSecretHash's doc comment for the full rotation/
-- reuse-detection design this backs: server/internal/oauth's refresh_token
-- grant handler now rotates the secret on every use (OAuthGrantRepo.Rotate)
-- instead of sliding the same one indefinitely, and treats a presented
-- prev_secret_hash as theft (OAuthGrantRepo.RevokeIfPreviousSecret) by
-- deleting the whole grant.
--
-- The index supports RevokeIfPreviousSecret's "DELETE ... WHERE
-- prev_secret_hash = ?" lookup, called on every refresh_token grant whose
-- presented secret doesn't match any grant's CURRENT secret_hash.
ALTER TABLE oauth_grants ADD COLUMN prev_secret_hash TEXT NOT NULL DEFAULT '';

CREATE INDEX idx_oauth_grants_prev_secret_hash ON oauth_grants(prev_secret_hash);
