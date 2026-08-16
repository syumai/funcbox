package invoke

import (
	"os"
	"strconv"

	"github.com/syumai/funcbox/runtime/enginepool"
)

// FUNCBOX_MAX_REQUEST_BYTES optionally overrides
// enginepool.DefaultMaxRequestBody (bytes) for this process's invoke path.
// It is read directly here rather than threaded through
// server/internal/config, since this package is the only consumer of the
// value: both the Content-Length short-circuit in Serve (invoke.go) and
// the per-worker buffered-read cap a pool is built with (pool.go) must
// agree on the exact same limit, or a request just under the
// Content-Length check could still get rejected by the worker's cap (or
// vice versa).
const maxRequestBytesEnvVar = "FUNCBOX_MAX_REQUEST_BYTES"

// maxRequestBytes returns the effective request-body limit: the value of
// FUNCBOX_MAX_REQUEST_BYTES if it's set to a valid positive integer,
// otherwise enginepool.DefaultMaxRequestBody. An unset, empty, zero,
// negative, or unparseable value all fall back to the default rather than
// erroring -- this is a defense-in-depth memory knob, not a piece of
// config whose misconfiguration should take the process down.
func maxRequestBytes() int64 {
	v := os.Getenv(maxRequestBytesEnvVar)
	if v == "" {
		return enginepool.DefaultMaxRequestBody
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return enginepool.DefaultMaxRequestBody
	}
	return n
}
