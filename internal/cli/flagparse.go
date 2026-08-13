package cli

import "flag"

// parseFlagsInterspersed parses args against fs, allowing flags to appear
// before, after, or between positional arguments.
//
// flag.FlagSet.Parse alone stops consuming flags at the first
// non-flag argument and treats everything after it (including any further
// "--flags") as positional (see https://pkg.go.dev/flag#FlagSet.Parse).
// funcbox's subcommands accept a positional argument (a directory, or an
// <owner>/<name> target) alongside optional flags, e.g. `funcbox deploy
// dir --owner acme` — a strict fs.Parse(args) silently drops --owner in
// that order, which used to be a documented CLI limitation (see the
// top-level README's former "flags must come before the directory
// argument" note).
//
// This loops flag.Parse, peeling off one positional argument at a time and
// re-parsing the remainder, until nothing unparsed remains. Flag values
// that take a separate-argument value (e.g. "--owner acme", as opposed to
// "--owner=acme") are handled correctly because each loop iteration hands
// the *entire* remaining tail back to fs.Parse, which still owns pairing a
// flag with its value; this function only ever peels off a single leading
// positional argument between iterations.
//
// It returns the positional arguments in the order they appeared; flag
// values are populated on fs as usual, so callers keep using fs.Lookup /
// the pointers returned by fs.String etc. Errors (unknown flag, missing
// value, -h/--help via flag.ErrHelp, ...) are returned unchanged, matching
// fs.Parse's own contract.
func parseFlagsInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	remaining := args
	for {
		if err := fs.Parse(remaining); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		remaining = rest[1:]
	}
}
