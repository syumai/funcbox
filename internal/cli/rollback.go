package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"
)

// RunRollback implements `funcbox rollback <owner>/<name> --to <versionID>`
// (tmp/07-http-api.md §7.5), which calls the version activate endpoint.
func RunRollback(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	fs.SetOutput(stderr)
	to := fs.String("to", "", "version ID to activate")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: funcbox rollback <owner>/<name> --to <versionID>")
	}
	if *to == "" {
		return fmt.Errorf("--to <versionID> is required")
	}

	owner, name, ok := strings.Cut(fs.Arg(0), "/")
	if !ok || owner == "" || name == "" {
		return fmt.Errorf("expected <owner>/<name>, got %q", fs.Arg(0))
	}

	cfg, err := RequireConfig()
	if err != nil {
		return err
	}
	client := NewClient(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fn, err := client.Activate(ctx, owner, name, *to)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Rolled back %s/%s to version %s\n", owner, name, fn.ActiveVersionID)
	return nil
}
