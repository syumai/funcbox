package dynamodb

import (
	"time"

	"github.com/oklog/ulid/v2"
)

// monthFloor is a hard stop for AuditRepo.List's backward month walk (see
// audit.go): no funcbox deployment could have audit data before this,
// so it bounds the walk to a finite number of DescribeTable-cheap Query
// calls even against a table with no audit data at all yet, without
// needing to know in advance how far back real data goes.
const monthFloor = "200001"

// monthKey formats t as the "yyyymm" partition suffix used by
// AUDIT#<yyyymm> (tmp/06-data-model.md).
func monthKey(t time.Time) string { return t.UTC().Format("200601") }

// prevMonthKey returns the "yyyymm" key immediately before month.
func prevMonthKey(month string) string {
	t, err := time.Parse("200601", month)
	if err != nil {
		return monthFloor
	}
	return monthKey(t.AddDate(0, -1, 0))
}

// monthFromULID returns the "yyyymm" partition an audit log ULID id was
// written into, derived from the timestamp ULIDs embed in their first 48
// bits — this is how AuditRepo.List resumes keyset pagination from a
// cursor without the caller needing to pass a month alongside it.
func monthFromULID(id string) string {
	parsed, err := ulid.ParseStrict(id)
	if err != nil {
		return monthKey(time.Now())
	}
	return monthKey(ulid.Time(parsed.Time()))
}
