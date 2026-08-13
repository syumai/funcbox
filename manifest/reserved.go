package manifest

import "strings"

// ReservedNames are function/owner names that would collide with
// names and public User IDs.
//
// Anything starting with "_" is also reserved; check that separately
// with IsReserved.
var ReservedNames = []string{
	"dashboard",
	"api",
	"auth",
	"dev",
	"assets",
	"healthz",
	"metrics",
	"run",
	"www",
	"admin",
	"status",
	"favicon.ico",
	"robots.txt",
}

var reservedNameSet = func() map[string]struct{} {
	set := make(map[string]struct{}, len(ReservedNames))
	for _, n := range ReservedNames {
		set[n] = struct{}{}
	}
	return set
}()

// IsReserved reports whether name collides with a reserved top-level
// route: it's one of ReservedNames, or it starts with "_".
func IsReserved(name string) bool {
	if strings.HasPrefix(name, "_") || strings.HasPrefix(name, "xn--") {
		return true
	}
	_, reserved := reservedNameSet[name]
	return reserved
}
