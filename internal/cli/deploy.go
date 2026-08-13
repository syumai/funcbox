package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/syumai/funcbox/bundle"
)

// deployTimeout bounds the whole deploy request (upload can be slow on a
// poor connection; the server itself caps the body at 5MiB compressed).
const deployTimeout = 2 * time.Minute

// meOwnerTimeout bounds the GET /api/v1/me round trip ResolveOwner falls
// back to when neither --owner nor the manifest declare an owner
// (tmp/07-http-api.md §7.5's owner precedence, final step).
const meOwnerTimeout = 15 * time.Second

// callerHandle looks up the caller's own handle via GET /api/v1/me, for
// ResolveOwner's final fallback step.
func callerHandle(client *Client) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), meOwnerTimeout)
	defer cancel()
	me, err := client.Me(ctx)
	if err != nil {
		return "", err
	}
	handle, _ := me["handle"].(string)
	return handle, nil
}

// RunDeploy implements `funcbox deploy [dir] [--owner H] [--name N]
// [--note S] [--dry-run]` (tmp/07-http-api.md §7.5).
func RunDeploy(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("deploy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	owner := fs.String("owner", "", "owner handle to deploy to (overrides the manifest's \"owner\" field)")
	name := fs.String("name", "", "function name (only used when the manifest doesn't declare one)")
	note := fs.String("note", "", "note to record on this version")
	dryRun := fs.Bool("dry-run", false, "validate only; does not create or activate a version")
	positional, err := parseFlagsInterspersed(fs, args)
	if err != nil {
		return err
	}

	dir := "."
	if len(positional) > 0 {
		dir = positional[0]
	}

	cfg, err := RequireConfig()
	if err != nil {
		return err
	}

	m, err := LoadProjectManifest(dir)
	if err != nil {
		return err
	}

	ignoreMatcher, err := LoadIgnoreMatcher(dir)
	if err != nil {
		return err
	}
	files, err := CollectFiles(dir, m.Compat.Nodejs, ignoreMatcher)
	if err != nil {
		return err
	}
	if err := CheckUnpackedSize(files); err != nil {
		return err
	}

	client := NewClient(cfg)
	resolvedOwner, err := ResolveOwner(*owner, m, func() (string, error) { return callerHandle(client) })
	if err != nil {
		return err
	}

	packed, err := bundle.Pack(files)
	if err != nil {
		return fmt.Errorf("cli: pack bundle: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), deployTimeout)
	defer cancel()

	resp, err := client.Deploy(ctx, DeployRequest{
		Bundle: packed,
		Owner:  resolvedOwner,
		Name:   *name,
		Note:   *note,
		DryRun: *dryRun,
	})
	if err != nil {
		return err
	}

	for _, w := range resp.Warnings {
		fmt.Fprintf(stderr, "warning: %s\n", w)
	}

	if resp.DryRun {
		fmt.Fprintln(stdout, "dry run OK: manifest is valid")
		return nil
	}

	if resp.Function == nil {
		fmt.Fprintln(stdout, "deploy succeeded")
		return nil
	}
	fmt.Fprintf(stdout, "Deployed %s/%s\n", resolvedOwner, resp.Function.Name)
	fmt.Fprintf(stdout, "URL: %s/%s/%s\n", client.Server, resolvedOwner, resp.Function.Name)
	if resp.Version != nil {
		fmt.Fprintf(stdout, "Version: %s\n", resp.Version.ID)
	}
	return nil
}
