package store

import (
	"crypto/rand"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

// entropySource is a monotonic, cryptographically-seeded ULID entropy
// source shared (and mutex-guarded) across all ID generation in this
// process. ULIDs are lexicographically sortable by creation time, which
// keeps primary keys naturally ordered and is friendly to key-value
// backends such as DynamoDB (see tmp/06-data-model.md).
var (
	entropyMu sync.Mutex
	entropy   = ulid.Monotonic(rand.Reader, 0)
)

// NewID returns a new ULID string, suitable for use as the primary key of
// any entity in this package.
func NewID() string {
	entropyMu.Lock()
	defer entropyMu.Unlock()
	return ulid.MustNew(ulid.Timestamp(time.Now()), entropy).String()
}
