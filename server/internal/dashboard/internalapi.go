package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	spidermonkey "github.com/goccy/go-spidermonkey"
	"github.com/goccy/go-spidermonkey/compat/cfworkers"

	"github.com/syumai/funcbox/internal/api"
	"github.com/syumai/funcbox/internal/auth"
	"github.com/syumai/funcbox/runtime"
)

// internalAPICallTimeout bounds each individual env.INTERNAL_API call's
// underlying Go work (an internal/api handler invocation, which may touch
// the store). AsyncFuncBinding's fn (bindings.go) runs on its own goroutine
// with no access to the originating HTTP request's context -- see this
// file's doc comment on internalAPIBinding -- so this package must invent
// its own bound rather than inherit one.
const internalAPICallTimeout = 15 * time.Second

// internalAPIBinding builds the env.INTERNAL_API cfworkers.Binding
// (tmp/09-dashboard.md §9.3): a guest call env.INTERNAL_API(method, path,
// bodyJSON, callerToken) returns a Promise (runtime.AsyncFuncBinding's
// verified poll-based pattern -- see that function's doc comment for why a
// naive goroutine-resolves-the-promise design is unreliable) that resolves
// to a JSON string `{"status":<int>,"body":<any>}`.
//
// callerToken is NOT trusted at face value: it is verified against
// tokenKey on every single call (verifyCallerToken), because a Binding is
// built ONCE per pooled instance at warm-up (cfworkers.PoolConfig.Env) and
// then reused across every request that instance ever serves -- there is
// no way to rebuild it per request the way a per-request identity would
// normally suggest. The identity therefore has to travel as a per-CALL
// argument instead, carried by the guest from the X-Funcbox-Caller-Token
// request header server.go injects, and re-verified here every time. This
// is the "individual呼び出し引数として、signed tokenを検証する" design
// tmp/09-dashboard.md §9.3 calls for.
//
// apiHandler.ServeInternal (internal/api/handler.go) is what actually
// dispatches the call: it installs the verified actor into the request
// context and runs the same route/handler logic ServeHTTP would, but
// skips Auth.Middleware/RequireCSRF entirely -- appropriate here because
// this whole call never touched an HTTP network hop or a cookie; the
// authentication decision was already made, in Go, by verifyCallerToken
// above.
func internalAPIBinding(apiHandler *api.Handler, tokenKey []byte) cfworkers.Binding {
	fn := func(cfg spidermonkey.Config, args []spidermonkey.Value) (spidermonkey.Value, error) {
		if len(args) < 4 {
			return nil, fmt.Errorf("INTERNAL_API: expected 4 arguments (method, path, body, callerToken), got %d", len(args))
		}
		method := args[0].String()
		path := args[1].String()
		bodyJSON := args[2].String()
		callerToken := args[3].String()

		claims, err := verifyCallerToken(tokenKey, callerToken)
		if err != nil {
			// A guest that can't produce a validly-signed token gets a
			// rejected Promise, not silent anonymous access -- see
			// AsyncFuncBinding's doc comment: a returned error rejects.
			return nil, fmt.Errorf("INTERNAL_API: %w", err)
		}
		act := &auth.Actor{User: claims.storeUser(), Method: auth.MethodSession}

		status, body, err := callInternalAPI(apiHandler, act, method, path, bodyJSON)
		if err != nil {
			return nil, fmt.Errorf("INTERNAL_API: %w", err)
		}

		out, err := json.Marshal(struct {
			Status int             `json:"status"`
			Body   json.RawMessage `json:"body"`
		}{Status: status, Body: body})
		if err != nil {
			return nil, fmt.Errorf("INTERNAL_API: marshal response: %w", err)
		}
		return spidermonkey.ValueOf(string(out)), nil
	}
	return runtime.AsyncFuncBinding("INTERNAL_API", fn)
}

// callInternalAPI builds an in-memory *http.Request for method/path
// (path is relative to /api/v1, matching internal/api.Handler.route's own
// stripping of that prefix) and dispatches it through
// apiHandler.ServeInternal, capturing the response into recorder (this
// package's own minimal http.ResponseWriter -- deliberately not
// net/http/httptest.ResponseRecorder, which is a testing-only helper this
// is production request-handling code, not a test).
func callInternalAPI(apiHandler *api.Handler, act *auth.Actor, method, path, bodyJSON string) (status int, body json.RawMessage, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), internalAPICallTimeout)
	defer cancel()

	var bodyReader *strings.Reader
	if bodyJSON != "" {
		bodyReader = strings.NewReader(bodyJSON)
	} else {
		bodyReader = strings.NewReader("")
	}
	req, err := http.NewRequestWithContext(ctx, method, "/api/v1"+path, bodyReader)
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	if bodyJSON != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	rec := newResponseRecorder()
	apiHandler.ServeInternal(rec, req, act)

	respBody := rec.body.Bytes()
	if len(respBody) == 0 {
		respBody = []byte("null")
	}
	return rec.status, json.RawMessage(respBody), nil
}
