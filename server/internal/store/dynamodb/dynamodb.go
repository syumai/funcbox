// Package dynamodb implements store.Store on top of a single Amazon
// DynamoDB table, using the single-table PK/SK layout specified in
// github.com/aws/aws-sdk-go-v2 (a pure-Go SDK, so this package stays
//
// # Access-pattern notes
//
// DynamoDB has no secondary indexes configured for this table (a real
// deployment would likely add a couple of GSIs), so a handful of lookups
// that would be trivial with one are implemented either as an
// application-maintained "GSI-substitute" pointer item (e.g. the
// USER#PROVIDER#<provider>#<sub> item that makes ByProviderSubject a plain
// GetItem) or, where a
// pointer item isn't practical, as a full-table Scan with a
// FilterExpression. Every method that Scans documents why in its own
// comment; all of them are choices explicitly sanctioned as acceptable at
// against (UserRepo.ByEmail, WorkspaceRepo.ListForUser/ListAll,
// FunctionRepo.ListAll, PublicUserIDRepo.ByOwner).
package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"

	"github.com/syumai/funcbox/server/internal/store"
)

// defaultRegion is used when neither Options.Region nor the AWS_REGION /
// AWS_DEFAULT_REGION environment variables specify one. DynamoDB Local /
// LocalStack / kumo don't care what region string is used (Options.Endpoint
// overrides where requests actually go), but the SDK still requires a
// non-empty region to sign requests.
const defaultRegion = "us-east-1"

// Options configures Open.
type Options struct {
	// TableName is the single DynamoDB table this Store reads and writes.
	// Required.
	TableName string

	// Endpoint, if set, overrides the DynamoDB service endpoint (e.g.
	// "http://localhost:8000" for DynamoDB Local, or a kumo/LocalStack
	// endpoint). When set, Open uses static dummy credentials instead of
	// the normal AWS credential chain, since local/CI DynamoDB-compatible
	// endpoints don't validate credentials and requiring a real AWS
	// account for local testing would defeat the point.
	Endpoint string

	// Region is the AWS region used to sign requests. Resolution order:
	// Options.Region, then the AWS_REGION environment variable, then
	// AWS_DEFAULT_REGION, then defaultRegion ("us-east-1").
	Region string
}

// resolveRegion implements Options.Region's documented resolution order.
func resolveRegion(opts Options) string {
	if opts.Region != "" {
		return opts.Region
	}
	if v := os.Getenv("AWS_REGION"); v != "" {
		return v
	}
	if v := os.Getenv("AWS_DEFAULT_REGION"); v != "" {
		return v
	}
	return defaultRegion
}

// Store implements store.Store on top of a single DynamoDB table (see this
// package's doc comment).
type Store struct {
	client *dynamodb.Client
	table  string

	organizations   *organizationRepo
	users           *userRepo
	handles         *handleRepo
	workspaces      *workspaceRepo
	functions       *functionRepo
	sessions        *sessionRepo
	invokeAuthCodes *invokeAuthCodeRepo
	cliCredentials  *cliCredentialRepo
	cliAuthCodes    *cliAuthCodeRepo
	oauthClients    *oauthClientRepo
	oauthAuthCodes  *oauthAuthCodeRepo
	oauthGrants     *oauthGrantRepo
	audit           *auditRepo
	invocationLogs  *invocationLogRepo
}

var _ store.Store = (*Store)(nil)

// Open resolves AWS credentials/region per Options and returns a
// ready-to-use Store bound to Options.TableName. Call Migrate before using
// it against a table that may not exist yet.
func Open(ctx context.Context, opts Options) (*Store, error) {
	if opts.TableName == "" {
		return nil, errors.New("dynamodb: Options.TableName is required")
	}
	region := resolveRegion(opts)

	loadOpts := []func(*config.LoadOptions) error{config.WithRegion(region)}
	if opts.Endpoint != "" {
		// Local/CI DynamoDB-compatible endpoints (DynamoDB Local,
		// LocalStack, kumo) don't validate credentials; static dummy
		// credentials let Open work with no AWS account configured.
		loadOpts = append(loadOpts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider("dummy", "dummy", ""),
		))
	}
	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("dynamodb: load AWS config: %w", err)
	}

	client := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
		if opts.Endpoint != "" {
			o.BaseEndpoint = aws.String(opts.Endpoint)
		}
	})

	s := &Store{client: client, table: opts.TableName}
	s.organizations = &organizationRepo{s: s}
	s.users = &userRepo{s: s}
	s.handles = &handleRepo{s: s}
	s.workspaces = &workspaceRepo{s: s}
	s.functions = &functionRepo{s: s}
	s.sessions = &sessionRepo{s: s}
	s.invokeAuthCodes = &invokeAuthCodeRepo{s: s}
	s.cliCredentials = &cliCredentialRepo{s: s}
	s.cliAuthCodes = &cliAuthCodeRepo{s: s}
	s.oauthClients = &oauthClientRepo{s: s}
	s.oauthAuthCodes = &oauthAuthCodeRepo{s: s}
	s.oauthGrants = &oauthGrantRepo{s: s}
	s.audit = &auditRepo{s: s}
	s.invocationLogs = &invocationLogRepo{s: s}
	return s, nil
}

func (s *Store) Organizations() store.OrganizationRepo     { return s.organizations }
func (s *Store) Users() store.UserRepo                     { return s.users }
func (s *Store) PublicUserIDs() store.PublicUserIDRepo     { return s.handles }
func (s *Store) Workspaces() store.WorkspaceRepo           { return s.workspaces }
func (s *Store) Functions() store.FunctionRepo             { return s.functions }
func (s *Store) Sessions() store.SessionRepo               { return s.sessions }
func (s *Store) InvokeAuthCodes() store.InvokeAuthCodeRepo { return s.invokeAuthCodes }
func (s *Store) CLICredentials() store.CLICredentialRepo   { return s.cliCredentials }
func (s *Store) CLIAuthCodes() store.CLIAuthCodeRepo       { return s.cliAuthCodes }
func (s *Store) OAuthClients() store.OAuthClientRepo       { return s.oauthClients }
func (s *Store) OAuthAuthCodes() store.OAuthAuthCodeRepo   { return s.oauthAuthCodes }
func (s *Store) OAuthGrants() store.OAuthGrantRepo         { return s.oauthGrants }
func (s *Store) Audit() store.AuditRepo                    { return s.audit }
func (s *Store) InvocationLogs() store.InvocationLogRepo   { return s.invocationLogs }

// Close is a no-op: the AWS SDK v2 HTTP client has no explicit close/shutdown
// step (it uses the shared net/http transport's connection pooling).
func (s *Store) Close() error { return nil }

// ttlAttribute is the DynamoDB attribute name enabled for TTL-based item
// expiry, used by Session items (see sessions.go) and InvocationLog items
// (see invocationlogs.go). AuditLog items intentionally have no TTL: audit
// is meant to be retained indefinitely (see AuditRepo's doc comment).
const ttlAttribute = "ttl"

// Migrate creates the table if it doesn't already exist and ensures TTL is
// テーブル作成 + GSI 定義のみ" — this table has no GSIs, see this package's
// doc comment for why). It is idempotent and safe to call on every process
// start: a second call against an already-ACTIVE table with TTL already
// enabled is just two no-op describe calls.
func (s *Store) Migrate(ctx context.Context) error {
	exists, err := s.tableExists(ctx)
	if err != nil {
		return fmt.Errorf("dynamodb: describe table: %w", err)
	}
	if !exists {
		if _, err := s.client.CreateTable(ctx, &dynamodb.CreateTableInput{
			TableName: aws.String(s.table),
			AttributeDefinitions: []types.AttributeDefinition{
				{AttributeName: aws.String("PK"), AttributeType: types.ScalarAttributeTypeS},
				{AttributeName: aws.String("SK"), AttributeType: types.ScalarAttributeTypeS},
			},
			KeySchema: []types.KeySchemaElement{
				{AttributeName: aws.String("PK"), KeyType: types.KeyTypeHash},
				{AttributeName: aws.String("SK"), KeyType: types.KeyTypeRange},
			},
			BillingMode: types.BillingModePayPerRequest,
		}); err != nil {
			return fmt.Errorf("dynamodb: create table: %w", err)
		}
	}

	waiter := dynamodb.NewTableExistsWaiter(s.client)
	if err := waiter.Wait(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(s.table)}, 2*time.Minute); err != nil {
		return fmt.Errorf("dynamodb: wait for table active: %w", err)
	}

	if err := s.ensureTTL(ctx); err != nil {
		return fmt.Errorf("dynamodb: ensure TTL: %w", err)
	}
	if err := s.functions.backfillGlobalNames(ctx); err != nil {
		return fmt.Errorf("dynamodb: migrate global function names: %w", err)
	}
	if err := s.removeLegacyWorkspaceHandles(ctx); err != nil {
		return fmt.Errorf("dynamodb: remove legacy workspace handles: %w", err)
	}
	if err := s.migrateUserProviderPointers(ctx); err != nil {
		return fmt.Errorf("dynamodb: migrate user provider pointers: %w", err)
	}
	if err := s.functions.backfillCreatedBy(ctx); err != nil {
		return fmt.Errorf("dynamodb: backfill function created_by: %w", err)
	}
	if err := s.functions.backfillFunctionCounts(ctx); err != nil {
		return fmt.Errorf("dynamodb: backfill function counts: %w", err)
	}
	return nil
}

func (s *Store) tableExists(ctx context.Context) (bool, error) {
	_, err := s.client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(s.table)})
	if err == nil {
		return true, nil
	}
	var nf *types.ResourceNotFoundException
	if errors.As(err, &nf) {
		return false, nil
	}
	return false, err
}

func (s *Store) ensureTTL(ctx context.Context) error {
	out, err := s.client.DescribeTimeToLive(ctx, &dynamodb.DescribeTimeToLiveInput{TableName: aws.String(s.table)})
	if err != nil {
		return err
	}
	switch out.TimeToLiveDescription.TimeToLiveStatus {
	case types.TimeToLiveStatusEnabled, types.TimeToLiveStatusEnabling:
		return nil
	}
	_, err = s.client.UpdateTimeToLive(ctx, &dynamodb.UpdateTimeToLiveInput{
		TableName: aws.String(s.table),
		TimeToLiveSpecification: &types.TimeToLiveSpecification{
			AttributeName: aws.String(ttlAttribute),
			Enabled:       aws.Bool(true),
		},
	})
	// DynamoDB Local / some LocalStack versions reject enabling TTL twice in
	// quick succession with a generic ValidationException ("TimeToLive is
	// already disabled/enabled") rather than a typed exception; tolerate
	// that racy-looking response by matching on the smithy API error code,
	// since the net effect (TTL enabled) is what we're after.
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "ValidationException" {
			return nil
		}
	}
	return err
}
