// Package auth implements funcbox's dashboard/API authentication
// Authorization Code + PKCE login flow, server-side sessions, API tokens,
// and the built-in dev-mode stub identity provider.
//
// Design summary:
//
//   - Auth is a generic OIDC relying party. Google is simply its default
//     issuer configuration; FUNCBOX_AUTH_MODE=dev swaps in a stub issuer
//     this package itself serves under /dev/oidc/*, so the exact same
//     verification code (provider discovery -> IDTokenVerifier.Verify) runs
//     in both cases -- see provider.go.
//   - Sessions are server-side (the sessions table): the cookie carries
//     only a random, unguessable token, and the DB row storing its SHA-256
//     hash is what sessions.go actually authenticates against, so a
//     session can be revoked instantly (session delete, or the login-rule
//     re-check on every request) without any cookie-side signature to
//     invalidate.
//   - Handle derivation (handle.go) and login-rule evaluation
//     (loginrules.go) are pure functions over the store types, factored out
//     so they're unit-testable without an HTTP round trip.
//   - API tokens (tokens.go) are a second, independent authentication path
//     for the same actor model, sharing every downstream check (login
//     rules, disabled flag) with session auth.
//
// This package is server-only: it depends on internal/store and
// internal/crypto and is not part of the funcbox CLI's dependency
// closure.
package auth
