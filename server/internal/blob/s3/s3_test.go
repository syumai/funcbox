package s3_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/syumai/funcbox/server/internal/blob"
	"github.com/syumai/funcbox/server/internal/blob/blobtest"
	blobs3 "github.com/syumai/funcbox/server/internal/blob/s3"
)

// TestStore runs the shared blob.Store conformance suite against a real
// S3-compatible endpoint. It requires FUNCBOX_TEST_S3_ENDPOINT and
// FUNCBOX_TEST_S3_BUCKET (e.g. a local MinIO/LocalStack/kumo instance); it
// skips cleanly when either is unset, since no such endpoint is available
// in ordinary dev/CI sandboxes.
func TestStore(t *testing.T) {
	newStore := s3TestStore(t)
	blobtest.TestStore(t, newStore)
}

func TestLister(t *testing.T) {
	newStore := s3TestStore(t)
	blobtest.TestLister(t, newStore)
}

// s3TestStore returns a constructor for a blob.Store backed by the real
// S3-compatible endpoint named by FUNCBOX_TEST_S3_ENDPOINT/
// FUNCBOX_TEST_S3_BUCKET, skipping the calling test cleanly if either is
// unset (no such endpoint is available in ordinary dev/CI sandboxes).
func s3TestStore(t *testing.T) func(t *testing.T) blob.Store {
	t.Helper()
	endpoint := os.Getenv("FUNCBOX_TEST_S3_ENDPOINT")
	bucket := os.Getenv("FUNCBOX_TEST_S3_BUCKET")
	if endpoint == "" || bucket == "" {
		t.Skip("FUNCBOX_TEST_S3_ENDPOINT and/or FUNCBOX_TEST_S3_BUCKET not set; skipping S3 blob.Store conformance test")
	}

	ctx := context.Background()
	ensureBucket(ctx, t, endpoint, bucket)

	return func(t *testing.T) blob.Store {
		s, err := blobs3.New(ctx, blobs3.Options{
			Bucket: bucket,
			// Local S3-compatible servers (MinIO, LocalStack, kumo) need
			// path-style addressing and generally have no real AWS
			// account behind them, hence the well-known dummy pair below.
			Endpoint:        endpoint,
			PathStyle:       true,
			AccessKeyID:     envOr("FUNCBOX_TEST_S3_ACCESS_KEY_ID", "dummy"),
			SecretAccessKey: envOr("FUNCBOX_TEST_S3_SECRET_ACCESS_KEY", "dummy"),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return s
	}
}

// ensureBucket creates the test bucket if it doesn't already exist. A
// freshly started MinIO/LocalStack/kumo instance typically starts with no
// buckets at all, so the test creates its own rather than requiring the
// test environment to pre-provision one; "already exists" is treated as
// success so the test is safe to re-run against a persistent instance.
func ensureBucket(ctx context.Context, t *testing.T, endpoint, bucket string) {
	t.Helper()
	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			envOr("FUNCBOX_TEST_S3_ACCESS_KEY_ID", "dummy"),
			envOr("FUNCBOX_TEST_S3_SECRET_ACCESS_KEY", "dummy"),
			"",
		)),
	)
	if err != nil {
		t.Fatalf("load AWS config for bucket setup: %v", err)
	}
	client := awss3.NewFromConfig(awsCfg, func(o *awss3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})
	_, err = client.CreateBucket(ctx, &awss3.CreateBucketInput{Bucket: aws.String(bucket)})
	if err == nil {
		return
	}
	var owned *types.BucketAlreadyOwnedByYou
	var exists *types.BucketAlreadyExists
	if errors.As(err, &owned) || errors.As(err, &exists) {
		return
	}
	t.Fatalf("create test bucket %q: %v", bucket, err)
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
