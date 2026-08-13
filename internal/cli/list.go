package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"
	"time"
)

// RunList implements `funcbox list [--owner H]` (tmp/07-http-api.md §7.3's
// GET /api/v1/functions).
func RunList(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	owner := fs.String("owner", "", "restrict the listing to this owner handle")
	if _, err := parseFlagsInterspersed(fs, args); err != nil {
		return err
	}

	cfg, err := RequireConfig()
	if err != nil {
		return err
	}
	client := NewClient(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fns, err := client.List(ctx, *owner)
	if err != nil {
		return err
	}
	if len(fns) == 0 {
		fmt.Fprintln(stdout, "no functions found")
		return nil
	}

	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	if *owner != "" {
		fmt.Fprintln(tw, "OWNER\tNAME\tACTIVE VERSION\tUPDATED")
		for _, fn := range fns {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", fn.Owner, fn.Name, orDash(fn.ActiveVersionID), fn.UpdatedAt)
		}
	} else {
		// The API's unfiltered list response doesn't include each
		// function's owner handle (internal/api/functions.go's
		// handleList calls functionDTOs(fns, "") in that branch), so
		// there is no owner column to show here; pass --owner to see it.
		fmt.Fprintln(tw, "NAME\tACTIVE VERSION\tUPDATED")
		for _, fn := range fns {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", fn.Name, orDash(fn.ActiveVersionID), fn.UpdatedAt)
		}
	}
	return tw.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
