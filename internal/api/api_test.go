package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/syumai/funcbox/internal/api"
	blobfs "github.com/syumai/funcbox/internal/blob/fs"
	"github.com/syumai/funcbox/internal/bundle"
	"github.com/syumai/funcbox/internal/runtime"
	"github.com/syumai/funcbox/internal/service"
	"github.com/syumai/funcbox/internal/store"
	"github.com/syumai/funcbox/internal/store/sqlite"
)

// newTestAPI wires a Handler against a real in-memory sqlite store and a
// temp-dir filesystem blob store, returning it behind an httptest.Server
// plus the Deployer used to seed a function directly (bypassing the HTTP
// deploy path, which is already covered by the top-level e2e tests).
func newTestAPI(t *testing.T) (baseURL string, deployer *service.Deployer) {
	t.Helper()

	st, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	blobStore, err := blobfs.New(t.TempDir())
	if err != nil {
		t.Fatalf("blobfs.New: %v", err)
	}
	manager := runtime.NewManager()
	t.Cleanup(func() { manager.Close() })

	deployer = &service.Deployer{Store: st, Blob: blobStore, Runtime: manager}
	functions := &service.Functions{Store: st, Runtime: manager}
	handler := api.New(deployer, functions, slog.New(slog.NewTextHandler(io.Discard, nil)))

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv.URL, deployer
}

func seedFunction(t *testing.T, deployer *service.Deployer, owner, name, indexJS string) string {
	t.Helper()
	actor := seedOwnerActor(t, deployer.Store, owner)
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: " + name + "\n"),
		"index.js":     []byte(indexJS),
	}
	packed, err := bundle.Pack(files)
	if err != nil {
		t.Fatalf("bundle.Pack: %v", err)
	}
	result, err := deployer.Deploy(context.Background(), service.DeployParams{
		Bundle: bytes.NewReader(packed),
		Owner:  owner,
		Name:   name,
		Actor:  actor,
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	return result.Version.ID
}

// seedOwnerActor creates a user and claims owner as their handle if it
// isn't already claimed, returning the user. Phase 2's Deploy requires an
// already-claimed handle plus an authorized Actor (see
// internal/service.Deployer.Deploy); tests that seed multiple functions
// under the same owner call this more than once, so an already-claimed
// handle is not an error.
func seedOwnerActor(t *testing.T, st store.Store, owner string) *store.User {
	t.Helper()
	ctx := context.Background()
	if h, err := st.Handles().ByHandle(ctx, owner); err == nil {
		u, err := st.Users().ByID(ctx, h.OwnerID)
		if err != nil {
			t.Fatalf("Users().ByID: %v", err)
		}
		return u
	}
	u := &store.User{GoogleSub: "sub-" + owner, Email: owner + "@example.com", Name: owner, Role: store.RoleMember}
	if err := st.Users().Create(ctx, u); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	if err := st.Handles().Create(ctx, &store.Handle{Handle: owner, OwnerType: store.OwnerTypeUser, OwnerID: u.ID}); err != nil {
		t.Fatalf("Handles().Create: %v", err)
	}
	return u
}

func getJSON(t *testing.T, url string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil && err != io.EOF {
		t.Fatalf("decode response: %v", err)
	}
	return resp.StatusCode, body
}

func TestHandleGet(t *testing.T) {
	baseURL, deployer := newTestAPI(t)
	seedFunction(t, deployer, "alice", "greet", `export default { fetch() { return new Response("hi"); } };`)

	status, body := getJSON(t, baseURL+"/api/v1/functions/alice/greet")
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %v", status, body)
	}
	if body["name"] != "greet" {
		t.Errorf("name = %v, want %q", body["name"], "greet")
	}
	av, ok := body["active_version"].(map[string]any)
	if !ok {
		t.Fatalf("active_version missing or not an object: %v", body)
	}
	if av["main_path"] != "index.js" {
		t.Errorf("active_version.main_path = %v, want %q", av["main_path"], "index.js")
	}
}

func TestHandleGet_UnknownFunctionIs404(t *testing.T) {
	baseURL, _ := newTestAPI(t)
	status, _ := getJSON(t, baseURL+"/api/v1/functions/nobody/nothing")
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", status)
	}
}

func TestHandleListVersions(t *testing.T) {
	baseURL, deployer := newTestAPI(t)
	v1 := seedFunction(t, deployer, "bob", "app", `export default { fetch() { return new Response("v1"); } };`)
	v2 := seedFunction(t, deployer, "bob", "app", `export default { fetch() { return new Response("v2"); } };`)

	status, body := getJSON(t, baseURL+"/api/v1/functions/bob/app/versions")
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %v", status, body)
	}
	versions, ok := body["versions"].([]any)
	if !ok || len(versions) != 2 {
		t.Fatalf("versions = %v, want 2 entries", body["versions"])
	}
	// Newest first.
	first := versions[0].(map[string]any)
	second := versions[1].(map[string]any)
	if first["id"] != v2 || second["id"] != v1 {
		t.Errorf("versions order = [%v, %v], want [%v, %v]", first["id"], second["id"], v2, v1)
	}
}

func TestHandleActivate_UnknownVersionIs404(t *testing.T) {
	baseURL, deployer := newTestAPI(t)
	seedFunction(t, deployer, "carol", "app", `export default { fetch() { return new Response("v1"); } };`)

	resp, err := http.Post(baseURL+"/api/v1/functions/carol/app/versions/nonexistent/activate", "application/json", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandleDelete(t *testing.T) {
	baseURL, deployer := newTestAPI(t)
	seedFunction(t, deployer, "dave", "app", `export default { fetch() { return new Response("v1"); } };`)

	req, err := http.NewRequest(http.MethodDelete, baseURL+"/api/v1/functions/dave/app", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}

	// Now gone.
	status, _ := getJSON(t, baseURL+"/api/v1/functions/dave/app")
	if status != http.StatusNotFound {
		t.Fatalf("status after delete = %d, want 404", status)
	}
}

func TestHandleList_RequiresOwnerQueryParam(t *testing.T) {
	baseURL, _ := newTestAPI(t)
	status, _ := getJSON(t, baseURL+"/api/v1/functions")
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
}

func TestHandleList_ByOwner(t *testing.T) {
	baseURL, deployer := newTestAPI(t)
	seedFunction(t, deployer, "erin", "one", `export default { fetch() { return new Response("1"); } };`)
	seedFunction(t, deployer, "erin", "two", `export default { fetch() { return new Response("2"); } };`)

	status, body := getJSON(t, baseURL+"/api/v1/functions?owner=erin")
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %v", status, body)
	}
	fns, ok := body["functions"].([]any)
	if !ok || len(fns) != 2 {
		t.Fatalf("functions = %v, want 2 entries", body["functions"])
	}
}
