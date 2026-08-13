package sqlcommon

import "time"

// nowUnix returns the current time as Unix seconds (UTC), the storage
// representation used for every timestamp column across every dialect this
// package supports.
func nowUnix() int64 { return time.Now().UTC().Unix() }

// toUnix converts a time.Time to its storage representation.
func toUnix(t time.Time) int64 { return t.UTC().Unix() }

// fromUnix converts a storage timestamp back to a time.Time in UTC.
func fromUnix(sec int64) time.Time { return time.Unix(sec, 0).UTC() }
