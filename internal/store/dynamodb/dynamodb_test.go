package dynamodb_test

import (
	"context"
	"os"
	"testing"

	"github.com/syumai/funcbox/internal/store"
	dynamodbstore "github.com/syumai/funcbox/internal/store/dynamodb"
	"github.com/syumai/funcbox/internal/store/storetest"
)

// TestStore runs the storetest conformance suite against a real DynamoDB-
// compatible endpoint (DynamoDB Local, LocalStack, or kumo). It is gated
// behind FUNCBOX_TEST_DYNAMODB_ENDPOINT so `go test ./...` stays green (and
// fast) in any environment without one running — which is the normal case
// for this repo's sandbox and most CI runs that don't stand up a
// DynamoDB-compatible service.
//
// To run it for real, start DynamoDB Local (no AWS account needed — Open
// uses static dummy credentials whenever Options.Endpoint is set):
//
//	docker run -p 8000:8000 amazon/dynamodb-local
//	FUNCBOX_TEST_DYNAMODB_ENDPOINT=http://localhost:8000 go test ./internal/store/dynamodb/... -run TestStore -v
//
// Optional env vars:
//   - FUNCBOX_TEST_DYNAMODB_TABLE: table name (default "funcbox_test").
//   - AWS_REGION / AWS_DEFAULT_REGION: region used to sign requests
//     (Open's resolution order; a local endpoint doesn't care what region
//     string is used, but the SDK still requires a non-empty one).
//
// Each subtest gets its own freshly created table (named with a random
// ULID suffix so repeated runs against a shared endpoint don't collide,
// and so storetest's independent subtests — several of which assert exact
// counts like "len(Users().List()) == 1" — never see another subtest's
// data) via newStore below, which is the pattern storetest.TestStore
// documents (newStore is called once per subtest).
func TestStore(t *testing.T) {
	endpoint := os.Getenv("FUNCBOX_TEST_DYNAMODB_ENDPOINT")
	if endpoint == "" {
		t.Skip("FUNCBOX_TEST_DYNAMODB_ENDPOINT not set; skipping DynamoDB conformance suite (see this file's doc comment for how to run it)")
	}
	storetest.TestStore(t, func(t *testing.T) store.Store {
		return newStore(t, endpoint)
	})
}

func newStore(t *testing.T, endpoint string) store.Store {
	t.Helper()
	table := os.Getenv("FUNCBOX_TEST_DYNAMODB_TABLE")
	if table == "" {
		table = "funcbox_test"
	}
	// Suffix with a fresh ULID so concurrent/repeated test runs against a
	// shared endpoint never collide or see each other's data.
	table += "_" + store.NewID()

	ctx := context.Background()
	s, err := dynamodbstore.Open(ctx, dynamodbstore.Options{TableName: table, Endpoint: endpoint})
	if err != nil {
		t.Fatalf("dynamodb.Open: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
