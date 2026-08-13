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
func RunRollback(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	fs.SetOutput(stderr)
	to := fs.String("to", "", "version ID to activate")
	positional, err := parseFlagsInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return fmt.Errorf("usage: funcbox rollback <owner>/<name> --to <versionID>")
	}
	if *to == "" {
		return fmt.Errorf("--to <versionID> is required")
	}

	owner, name, ok := strings.Cut(positional[0], "/")
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
