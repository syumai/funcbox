package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/syumai/funcbox/server/internal/blob"
	blobfs "github.com/syumai/funcbox/server/internal/blob/fs"
	blobgcs "github.com/syumai/funcbox/server/internal/blob/gcs"
	blobs3 "github.com/syumai/funcbox/server/internal/blob/s3"
	"github.com/syumai/funcbox/server/internal/store"
	"github.com/syumai/funcbox/server/internal/store/dynamodb"
	"github.com/syumai/funcbox/server/internal/store/neon"
	"github.com/syumai/funcbox/server/internal/store/sqlite"
	"github.com/syumai/funcbox/server/internal/store/turso"
)

// openStore parses FUNCBOX_DB and opens the matching store.Store backend;
// see internal/config's Config.DB doc comment for the full scheme table.
// "postgres://..." (store/neon) is matched on its full URL rather than cut
// on the first ":", since a bare Cut on ":" would only strip "postgres"
// off the front and leave the driver an incomplete "//user:pass@host/db"
// DSN -- pgx needs the scheme prefix intact.
func openStore(dbConn string) (store.Store, error) {
	if dbConn == "" {
		dbConn = "sqlite:funcbox.db"
	}
	if strings.HasPrefix(dbConn, "postgres://") || strings.HasPrefix(dbConn, "postgresql://") {
		return neon.Open(dbConn)
	}

	scheme, rest, ok := strings.Cut(dbConn, ":")
	if !ok {
		return nil, fmt.Errorf("invalid FUNCBOX_DB %q: expected \"scheme:connection\"", dbConn)
	}
	switch scheme {
	case "sqlite":
		return sqlite.Open(rest)
	case "turso":
		return turso.Open(rest)
	case "dynamodb":
		params := parseParams(rest)
		table := params["table"]
		if table == "" {
			return nil, fmt.Errorf("invalid FUNCBOX_DB %q: dynamodb scheme requires \"table=NAME\"", dbConn)
		}
		return dynamodb.Open(context.Background(), dynamodb.Options{
			TableName: table,
			Endpoint:  params["endpoint"],
			Region:    params["region"],
		})
	default:
		return nil, fmt.Errorf("unsupported FUNCBOX_DB scheme %q (want sqlite, turso, postgres, or dynamodb)", scheme)
	}
}

// openBlob parses FUNCBOX_BLOB and opens the matching blob.Store backend;
// see internal/config's Config.Blob doc comment for the full scheme table.
func openBlob(blobConn string) (blob.Store, error) {
	if blobConn == "" {
		blobConn = "fs:./data/blobs"
	}
	scheme, rest, ok := strings.Cut(blobConn, ":")
	if !ok {
		return nil, fmt.Errorf("invalid FUNCBOX_BLOB %q: expected \"scheme:connection\"", blobConn)
	}
	switch scheme {
	case "fs":
		return blobfs.New(rest)
	case "s3":
		params := parseParams(rest)
		bucket := params["bucket"]
		if bucket == "" {
			return nil, fmt.Errorf("invalid FUNCBOX_BLOB %q: s3 scheme requires \"bucket=NAME\"", blobConn)
		}
		return blobs3.New(context.Background(), blobs3.Options{
			Bucket:    bucket,
			Endpoint:  params["endpoint"],
			Region:    params["region"],
			PathStyle: params["pathstyle"] == "1" || params["pathstyle"] == "true",
		})
	case "gcs":
		params := parseParams(rest)
		bucket := params["bucket"]
		if bucket == "" {
			return nil, fmt.Errorf("invalid FUNCBOX_BLOB %q: gcs scheme requires \"bucket=NAME\"", blobConn)
		}
		return blobgcs.New(context.Background(), blobgcs.Options{Bucket: bucket})
	default:
		return nil, fmt.Errorf("unsupported FUNCBOX_BLOB scheme %q (want fs, s3, or gcs)", scheme)
	}
}

// parseParams parses the ";"-separated "key=value" connection-string tail
// used by the dynamodb/s3/gcs schemes (e.g.
// "table=NAME;endpoint=URL;region=R"). Unknown keys are ignored by the
// caller rather than rejected here, so this stays a single, reusable
// parser instead of one per scheme.
func parseParams(s string) map[string]string {
	out := make(map[string]string)
	for _, part := range strings.Split(s, ";") {
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		out[k] = v
	}
	return out
}
