package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestIncPoolEviction_IncrementsCounter is 14.2 Pool LRU's metrics
// requirement: runtime.WithEvictHook is meant to be wired directly to
// (*Metrics).IncPoolEviction (see cmd/funcbox-server/main.go), so every LRU
// eviction must land on funcbox_pool_evictions_total exactly once.
func TestIncPoolEviction_IncrementsCounter(t *testing.T) {
	m := New(true)

	if got := testutil.ToFloat64(m.poolEvictions); got != 0 {
		t.Fatalf("funcbox_pool_evictions_total before any eviction = %v, want 0", got)
	}

	// The callback signature takes the evicted key; the metric itself
	// carries no per-function label (see IncPoolEviction's doc comment),
	// so distinct keys should still just accumulate on one counter.
	m.IncPoolEviction("owner/fn-a@v1")
	m.IncPoolEviction("owner/fn-b@v3")
	m.IncPoolEviction("owner/fn-a@v1")

	if got := testutil.ToFloat64(m.poolEvictions); got != 3 {
		t.Fatalf("funcbox_pool_evictions_total after 3 evictions = %v, want 3", got)
	}
}

// TestIncPoolEviction_DisabledIsNoop mirrors every other recording method's
// contract (see the package doc comment on Metrics): FUNCBOX_METRICS=0
// (New(false)) must make IncPoolEviction a safe no-op, not a nil-pointer
// panic on the unbuilt poolEvictions counter.
func TestIncPoolEviction_DisabledIsNoop(t *testing.T) {
	m := New(false)
	m.IncPoolEviction("owner/fn-a@v1") // must not panic
	if m.Handler() != nil {
		t.Error("Handler() on a disabled Metrics = non-nil, want nil")
	}
}

// TestIncPoolEviction_NilReceiverIsNoop covers the nil-*Metrics case
// explicitly documented on the Metrics type (call sites like invoke.Invoker
// are often constructed without a Metrics field at all, e.g. in tests).
func TestIncPoolEviction_NilReceiverIsNoop(t *testing.T) {
	var m *Metrics
	m.IncPoolEviction("owner/fn-a@v1") // must not panic
}
