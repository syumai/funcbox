// Package s3 implements blob.Store on top of Amazon S3 and S3-compatible
// object stores: Cloudflare R2 (via a custom endpoint), MinIO, LocalStack,
// and funcbox's own local S3-compatible test harness ("kumo"). It is a
// pure-Go client (aws-sdk-go-v2), so using it keeps the funcbox-server
// binary CGo-free.
package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/syumai/funcbox/internal/blob"
)

// Options configures a Store.
//
// Credential resolution: New always starts from config.LoadDefaultConfig,
// which follows the AWS SDK's standard chain — AWS_ACCESS_KEY_ID /
// AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN env vars, then shared
// config/credentials files, then the EC2/ECS/EKS instance metadata service
// — in that order. That alone is enough to run against real AWS S3 or
// Cloudflare R2 with nothing beyond ambient credentials (an IAM role, or
// the usual env vars). AccessKeyID/SecretAccessKey exist as an explicit
// override on top of that chain, mainly for pointing at a local
// S3-compatible endpoint (MinIO, LocalStack, kumo) that has no ambient AWS
// credentials to discover: set them alongside Endpoint and every request
// uses exactly those static credentials instead of the ambient chain.
type Options struct {
	// Bucket is the S3 bucket name. Required.
	Bucket string

	// Endpoint, when set, overrides the default AWS endpoint resolution so
	// the client talks to an S3-compatible service instead of AWS S3 —
	// e.g. a Cloudflare R2 account endpoint, or a local MinIO/LocalStack/
	// kumo instance's HTTP address.
	Endpoint string

	// Region selects the AWS region used for request signing. Resolution
	// order: Region (this field) > AWS_REGION env > AWS_DEFAULT_REGION env
	// > "us-east-1". Most S3-compatible servers ignore the region value
	// itself but the SDK requires one to be set to sign requests.
	Region string

	// PathStyle forces path-style addressing (https://host/bucket/key)
	// instead of virtual-hosted-style (https://bucket.host/key). Set this
	// for MinIO, LocalStack, and most other self-hosted S3-compatible
	// servers, which generally don't do virtual-host DNS routing for
	// arbitrary bucket names. Leave it false for AWS S3 and Cloudflare R2,
	// which both support (and default to) virtual-hosted-style.
	PathStyle bool

	// AccessKeyID and SecretAccessKey, when both set, override the ambient
	// AWS credential chain with a static pair. Typically used together
	// with Endpoint to talk to a local S3-compatible server that has no
	// real AWS account behind it.
	AccessKeyID     string
	SecretAccessKey string
}

// Store is an S3-backed blob.Store. It works against real Amazon S3 as
// well as any S3-compatible service reachable via Options.Endpoint.
type Store struct {
	client *s3.Client
	bucket string
}

// New creates a Store for the given bucket. See Options for how endpoint,
// region, and credentials are resolved.
func New(ctx context.Context, opts Options) (*Store, error) {
	if opts.Bucket == "" {
		return nil, errors.New("blob/s3: Bucket is required")
	}

	region := opts.Region
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	if region == "" {
		region = "us-east-1"
	}

	cfgOpts := []func(*config.LoadOptions) error{config.WithRegion(region)}
	if opts.AccessKeyID != "" && opts.SecretAccessKey != "" {
		cfgOpts = append(cfgOpts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(opts.AccessKeyID, opts.SecretAccessKey, ""),
		))
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		return nil, fmt.Errorf("blob/s3: load AWS config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if opts.Endpoint != "" {
			o.BaseEndpoint = aws.String(opts.Endpoint)
		}
		o.UsePathStyle = opts.PathStyle
	})

	return &Store{client: client, bucket: opts.Bucket}, nil
}

// Put uploads r (exactly size bytes) to key via a single PutObject call.
// Because keys are content-addressed, this is inherently idempotent: two
// Puts of the same key race to overwrite each other with identical bytes,
// so whichever lands last leaves S3 in the same observable state either
// way. The SDK's client is safe for concurrent use, so no extra locking is
// needed across goroutines sharing a Store.
func (s *Store) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	if err := blob.ValidateKey(key); err != nil {
		return err
	}
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(key),
		Body:          r,
		ContentLength: aws.Int64(size),
	})
	if err != nil {
		return fmt.Errorf("blob/s3: put %q: %w", key, err)
	}
	return nil
}

// Get returns a reader for the content stored under key, streaming
// directly from the GetObject response body rather than buffering it.
// Returns blob.ErrNotExist if key has no stored content.
func (s *Store) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := blob.ValidateKey(key); err != nil {
		return nil, err
	}
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if isNotFound(err) {
			return nil, blob.ErrNotExist
		}
		return nil, fmt.Errorf("blob/s3: get %q: %w", key, err)
	}
	return out.Body, nil
}

// Exists reports whether key has stored content, via HeadObject (no body
// transfer).
func (s *Store) Exists(ctx context.Context, key string) (bool, error) {
	if err := blob.ValidateKey(key); err != nil {
		return false, err
	}
	_, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("blob/s3: head %q: %w", key, err)
	}
	return true, nil
}

// Delete removes key. S3 already treats deleting a missing key as success
// (a 204 no-op), so this needs no special-case translation to satisfy
// blob.Store's idempotent-delete contract.
func (s *Store) Delete(ctx context.Context, key string) error {
	if err := blob.ValidateKey(key); err != nil {
		return err
	}
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("blob/s3: delete %q: %w", key, err)
	}
	return nil
}

// List implements blob.Lister via a paginated ListObjectsV2.
func (s *Store) List(ctx context.Context, prefix string, fn func(key string) error) error {
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(prefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("blob/s3: list: %w", err)
		}
		for _, obj := range page.Contents {
			if obj.Key == nil {
				continue
			}
			if err := fn(*obj.Key); err != nil {
				return err
			}
		}
	}
	return nil
}

// isNotFound reports whether err represents a "no such object" response
// from S3 or an S3-compatible service. It checks the typed errors the SDK
// generates for the common cases (NoSuchKey from GetObject, NotFound from
// HeadObject) and falls back to a bare HTTP 404 status so
// S3-compatible services that don't reproduce AWS's exact error codes are
// still handled correctly.
func isNotFound(err error) bool {
	var nsk *types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}
	var nf *types.NotFound
	if errors.As(err, &nf) {
		return true
	}
	var re *smithyhttp.ResponseError
	if errors.As(err, &re) {
		return re.HTTPStatusCode() == http.StatusNotFound
	}
	return false
}

var (
	_ blob.Store  = (*Store)(nil)
	_ blob.Lister = (*Store)(nil)
)
