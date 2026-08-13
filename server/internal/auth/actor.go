package auth

import (
	"context"

	"github.com/syumai/funcbox/server/internal/store"
)

// Method identifies how an Actor authenticated, which matters for CSRF:
// only cookie-authenticated (browser) requests are exposed to cross-site
// request forgery, since a bearer token is never attached automatically by
// a browser the way a cookie is.
type Method int

const (
	// MethodSession identifies a request authenticated via the session
	// cookie.
	MethodSession Method = iota
	// MethodToken identifies a request authenticated via an
	// "Authorization: Bearer fbx_..." API token.
	MethodToken
)

// Actor is the authenticated caller attached to a request's context by
// Authenticate/Middleware.
type Actor struct {
	User   *store.User
	Method Method

	// csrfCookie is the raw value of the __Host-fbx_csrf cookie present on the
	// request that produced this Actor, captured here (rather than
	// re-read from the request later) so CSRF verification doesn't need
	// its own cookie lookup. Only meaningful when Method == MethodSession.
	csrfCookie string
}

type actorContextKey struct{}

// WithActor returns a copy of ctx carrying actor.
func WithActor(ctx context.Context, actor *Actor) context.Context {
	return context.WithValue(ctx, actorContextKey{}, actor)
}

// ActorFromContext returns the Actor attached to ctx by Middleware, or nil
// if none is present (e.g. the request never reached the middleware, or
// wasn't authenticated).
func ActorFromContext(ctx context.Context) *Actor {
	a, _ := ctx.Value(actorContextKey{}).(*Actor)
	return a
}
