package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// logsPageSize is how many entries RunLogs asks the server for per call --
// both the initial page and each --follow poll.
const logsPageSize = 50

// documented "follow = poll every 2s using the last-seen cursor", rather
// than a live tail/stream).
const logsFollowInterval = 2 * time.Second

// RunLogs implements `funcbox logs <owner>/<name> [--follow]`
//
// GET .../logs is newest-first, keyset-paginated backwards via a "since"
// cursor (the same convention as GET .../versions and the org audit log:
// "since", when set, means "strictly before this ID", not "after" --
// matching store.AuditRepo/InvocationLogRepo.List). --follow therefore
// can't ask the server for "only what's new" directly; instead it polls
// the newest page on every tick and, since invocation log IDs are ULIDs
// (lexically sortable == chronologically sortable), filters out anything
// at or before the newest ID already printed.
func RunLogs(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	fs.SetOutput(stderr)
	follow := fs.Bool("follow", false, "keep polling for new log entries every 2s")
	positional, err := parseFlagsInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		fmt.Fprintln(stderr, "usage: funcbox logs <owner>/<name> [--follow]")
		return errExitCode1
	}
	owner, name, ok := strings.Cut(positional[0], "/")
	if !ok || owner == "" || name == "" {
		fmt.Fprintf(stderr, "funcbox logs: expected <owner>/<name>, got %q\n", positional[0])
		return errExitCode1
	}

	cfg, err := RequireConfig()
	if err != nil {
		return err
	}
	client := NewClient(cfg)

	lastSeenID, err := printLogsPage(stdout, client, owner, name, "")
	if err != nil {
		return err
	}

	if !*follow {
		return nil
	}
	for {
		time.Sleep(logsFollowInterval)
		newest, err := printLogsPage(stdout, client, owner, name, lastSeenID)
		if err != nil {
			return err
		}
		if newest != "" {
			lastSeenID = newest
		}
	}
}

// printLogsPage fetches the most recent logsPageSize log entries and
// prints only those newer than afterID (exclusive; pass "" on the very
// first call to print everything in the initial page), oldest-first for
// natural top-to-bottom terminal reading. It returns the newest ID printed
// (or afterID unchanged if nothing new was found), for the caller to pass
// back in as afterID on the next poll.
func printLogsPage(stdout io.Writer, client *Client, owner, name, afterID string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logs, err := client.Logs(ctx, owner, name, "", logsPageSize)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
			return "", fmt.Errorf("funcbox logs: %s/%s: %s", owner, name, apiErr.Message)
		}
		return "", err
	}

	// logs is newest-first; walk backwards to print oldest-first, and stop
	// (skip) anything at or before afterID.
	newest := afterID
	printed := false
	for i := len(logs) - 1; i >= 0; i-- {
		l := logs[i]
		if afterID != "" && l.ID <= afterID {
			continue
		}
		printLogLine(stdout, l)
		printed = true
		if newest == "" || l.ID > newest {
			newest = l.ID
		}
	}
	if !printed && afterID == "" && len(logs) == 0 {
		fmt.Fprintln(stdout, "no invocation logs yet")
	}
	return newest, nil
}

func printLogLine(stdout io.Writer, l LogDTO) {
	fmt.Fprintf(stdout, "%s %s %s %d %dms\n", l.CreatedAt, l.Method, l.Path, l.Status, l.DurationMS)
	if l.Stdout != "" {
		writeIndented(stdout, "stdout", l.Stdout)
	}
	if l.Stderr != "" {
		writeIndented(stdout, "stderr", l.Stderr)
	}
}

func writeIndented(stdout io.Writer, label, s string) {
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		fmt.Fprintf(stdout, "  [%s] %s\n", label, line)
	}
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
