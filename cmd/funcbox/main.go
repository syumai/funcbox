// deploy, dev, rollback, list, and logs. It talks to a funcbox-server ONLY
// over the server's HTTP management API (never a database or blob store
// "バイナリ分離と依存の最小化").
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/syumai/funcbox/internal/cli"
)

const usage = `funcbox: local dev server and deploy tool for funcbox functions

Usage:
  funcbox login [--server URL]
  funcbox print-access-token [--ttl 15m]
  funcbox dev [dir] [--addr host:port] [--env KEY=VALUE]... [--env-file PATH]
  funcbox deploy [dir] [--owner OWNER] [--name NAME] [--note NOTE] [--dry-run]
  funcbox rollback <owner>/<name> --to <versionID>
  funcbox list [--owner OWNER]
  funcbox logs <owner>/<name> [--follow]
  funcbox mcp
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}

	cmd, rest := args[0], args[1:]
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		fmt.Fprint(os.Stdout, usage)
		return 0
	}

	var err error
	switch cmd {
	case "login":
		err = cli.RunLogin(rest, os.Stdin, os.Stdout, os.Stderr)
	case "print-access-token":
		err = cli.RunPrintAccessToken(rest, os.Stdout, os.Stderr)
	case "dev":
		err = cli.RunDev(rest, os.Stdout, os.Stderr)
	case "deploy":
		err = cli.RunDeploy(rest, os.Stdout, os.Stderr)
	case "rollback":
		err = cli.RunRollback(rest, os.Stdout, os.Stderr)
	case "list":
		err = cli.RunList(rest, os.Stdout, os.Stderr)
	case "logs":
		err = cli.RunLogs(rest, os.Stdout, os.Stderr)
	case "mcp":
		err = cli.RunMCP(rest, os.Stdin, os.Stdout, os.Stderr)
	default:
		fmt.Fprintf(os.Stderr, "funcbox: unknown command %q\n\n", cmd)
		fmt.Fprint(os.Stderr, usage)
		return 2
	}

	if err == nil {
		return 0
	}
	if cli.IsSilent(err) {
		return 1
	}
	if errors.Is(err, flag.ErrHelp) {
		return 2
	}
	fmt.Fprintf(os.Stderr, "funcbox: %v\n", err)
	return 1
}
