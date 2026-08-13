package cli

import (
	"fmt"
	"io"
)

// RunLogs implements `funcbox logs <owner>/<name> [--follow]`. Not
// implemented in phase 5: the server has no invocation log storage yet
// (tmp/07-http-api.md §7.3 documents GET .../logs, but nothing populates
// it — that lands in a later phase alongside server-side log storage).
func RunLogs(args []string, stderr io.Writer) error {
	fmt.Fprintln(stderr, "funcbox logs: not implemented yet; server-side invocation log storage lands in a later phase")
	return errExitCode1
}

// errExitCode1 is a sentinel error whose only purpose is to make main.go
// exit(1) without printing an extra "funcbox: ..." line for a message
// RunLogs has already printed itself.
var errExitCode1 = &silentError{}

type silentError struct{}

func (*silentError) Error() string { return "" }

// IsSilent reports whether err is the sentinel used to request a bare
// exit(1) with no additional message.
func IsSilent(err error) bool {
	_, ok := err.(*silentError)
	return ok
}
