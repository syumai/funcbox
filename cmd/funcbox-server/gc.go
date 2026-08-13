package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"sort"

	"github.com/syumai/funcbox/internal/blob"
	"github.com/syumai/funcbox/internal/config"
	"github.com/syumai/funcbox/internal/service"
	"github.com/syumai/funcbox/internal/store"
)

// runGC implements `funcbox-server gc [--apply]` (tmp/10-roadmap.md Phase
// 4): scan every function_version's bundle_hash across the store to build
// the set of blobs still referenced, list every blob actually present, and
// report (or, with --apply, delete) whatever's in the blob store but not
// referenced by any version.
//
// This is safe to run against a live server: bundles are content-addressed
// and function_versions are immutable (tmp/06-data-model.md), so the
// referenced set can only grow monotonically during a scan, never shrink
// out from under it -- the one race window is a deploy that completes
// AFTER the store scan but BEFORE the blob scan, whose freshly-Put blob
// would then look unreferenced. That can't happen: a deploy always Puts
// the blob before creating the function_version row that references it
// (see service.Deployer), so scanning the store first and the blob store
// second means any blob written by a deploy racing with gc is guaranteed
// to already be referenced in the store snapshot gc read.
func runGC(args []string, logger *slog.Logger, stdout io.Writer) error {
	fs := flag.NewFlagSet("gc", flag.ContinueOnError)
	apply := fs.Bool("apply", false, "actually delete unreferenced blobs (default: dry-run, list only)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}

	st, err := openStore(cfg.DB)
	if err != nil {
		return err
	}
	defer st.Close()
	// Migrate is idempotent (a no-op against an already-current schema),
	// so this is safe whether gc runs against a freshly created database
	// or years into a running server's life; it just means `gc` doesn't
	// require the server to have been started at least once first.
	if err := st.Migrate(context.Background()); err != nil {
		return fmt.Errorf("gc: migrate store: %w", err)
	}

	blobStore, err := openBlob(cfg.Blob)
	if err != nil {
		return err
	}
	if closer, ok := blobStore.(io.Closer); ok {
		defer closer.Close()
	}
	lister, ok := blobStore.(blob.Lister)
	if !ok {
		return fmt.Errorf("gc: the configured blob backend does not support listing (implements no blob.Lister), so gc cannot enumerate stored blobs")
	}

	ctx := context.Background()

	referenced, err := referencedBundleKeys(ctx, st)
	if err != nil {
		return fmt.Errorf("gc: scan function versions: %w", err)
	}
	logger.Info("gc: scanned store", "referenced_blobs", len(referenced))

	var unreferenced []string
	if err := lister.List(ctx, "bundles/sha256/", func(key string) error {
		if !referenced[key] {
			unreferenced = append(unreferenced, key)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("gc: list blobs: %w", err)
	}
	sort.Strings(unreferenced)

	if len(unreferenced) == 0 {
		fmt.Fprintln(stdout, "gc: no unreferenced blobs found")
		return nil
	}

	if !*apply {
		fmt.Fprintf(stdout, "gc: %d unreferenced blob(s) (dry-run; pass --apply to delete):\n", len(unreferenced))
		for _, key := range unreferenced {
			fmt.Fprintln(stdout, "  ", key)
		}
		return nil
	}

	fmt.Fprintf(stdout, "gc: deleting %d unreferenced blob(s):\n", len(unreferenced))
	var failed int
	for _, key := range unreferenced {
		if err := blobStore.Delete(ctx, key); err != nil {
			logger.Error("gc: delete failed", "key", key, "error", err)
			failed++
			continue
		}
		fmt.Fprintln(stdout, "  deleted", key)
	}
	if failed > 0 {
		return fmt.Errorf("gc: %d of %d deletes failed (see logs)", failed, len(unreferenced))
	}
	return nil
}

// referencedBundleKeys returns the set of blob.Store keys
// (service.BundleBlobKey) referenced by ANY function_version of ANY
// function in the store, across every owner -- ListAll (rather than
// ListVisibleTo/ListByOwner) is exactly the org-admin-unrestricted view gc
// needs, since it must never delete a blob just because gc itself has no
// particular caller identity to scope a listing by.
func referencedBundleKeys(ctx context.Context, st store.Store) (map[string]bool, error) {
	fns, err := st.Functions().ListAll(ctx)
	if err != nil {
		return nil, err
	}
	referenced := make(map[string]bool)
	for _, fn := range fns {
		// limit=0 means "no limit" (see store.FunctionRepo.ListVersions'
		// doc comment) -- gc needs every version ever created, including
		// ones no longer active, since rollback can repoint
		// active_version_id at any prior version at any time.
		versions, err := st.Functions().ListVersions(ctx, fn.ID, 0)
		if err != nil {
			return nil, fmt.Errorf("list versions for function %s: %w", fn.ID, err)
		}
		for _, v := range versions {
			referenced[service.BundleBlobKey(v.BundleHash)] = true
		}
	}
	return referenced, nil
}
