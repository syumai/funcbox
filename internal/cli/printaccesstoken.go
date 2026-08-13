// printaccesstoken.go implements `funcbox print-access-token` (§14.5 of
// tmp/14-auth-and-pool-improvements.md): mints a short-lived access token
// from the saved CLI login credential and prints ONLY the token to
// stdout, so it composes with `$()`:
//
//	export FUNCBOX_TOKEN=$(funcbox print-access-token)
//	curl -H "Authorization: Bearer $FUNCBOX_TOKEN" https://fb.example.com/data/report
//
// Every other message this command produces goes to stderr.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"
)

// printAccessTokenRequestTimeout bounds the single POST
// /api/v1/cli/access-token call this command makes.
const printAccessTokenRequestTimeout = 15 * time.Second

// RunPrintAccessToken mints a fresh access token from the saved CLI
// credential and writes it, alone, as a single line to stdout.
func RunPrintAccessToken(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("print-access-token", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ttlFlag := fs.String("ttl", "", "access token lifetime as a Go duration (e.g. 15m); default 15m, server maximum 1h")
	if _, err := parseFlagsInterspersed(fs, args); err != nil {
		return err
	}

	var ttl time.Duration
	if *ttlFlag != "" {
		d, err := time.ParseDuration(*ttlFlag)
		if err != nil {
			return fmt.Errorf("--ttl must be a valid Go duration (e.g. \"15m\"): %w", err)
		}
		ttl = d
	}

	cfg, err := RequireConfig()
	if err != nil {
		return err
	}
	client := NewClient(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), printAccessTokenRequestTimeout)
	defer cancel()

	token, expiresAt, err := client.MintAccessToken(ctx, ttl)
	if err != nil {
		return fmt.Errorf("mint access token: %w", err)
	}

	fmt.Fprintf(stderr, "Access token expires at %s\n", expiresAt.Format(time.RFC3339))
	fmt.Fprintln(stdout, token)
	return nil
}
