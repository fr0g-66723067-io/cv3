package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fr0g-66723067-io/cv3/internal/ingest"
	"github.com/fr0g-66723067-io/cv3/internal/report"
	"github.com/fr0g-66723067-io/cv3/internal/store"
)

// ingestFlags is the shared flag set of sync and update.
type ingestFlags struct {
	db        string
	cache     string
	keepCache bool
	workers   int
	years     string
	quiet     bool
	json      bool
	refresh   bool
}

func (f *ingestFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.db, "db", "", "database path")
	fs.StringVar(&f.cache, "cache", "", "download cache directory")
	fs.BoolVar(&f.keepCache, "keep-cache", false, "keep downloaded archives")
	fs.IntVar(&f.workers, "workers", 0, "parser workers (default min(8, NumCPU))")
	fs.StringVar(&f.years, "years", "", "NVD year range, e.g. 2015-2026")
	fs.BoolVar(&f.quiet, "quiet", false, "suppress progress output")
	fs.BoolVar(&f.refresh, "refresh", false, "re-download assets even when cached")
	fs.BoolVar(&f.json, "json", false, "emit JSON")
}

func (f *ingestFlags) options(stdout, stderr io.Writer) (ingest.Options, int) {
	dbPath, err := resolveDB(f.db)
	if err != nil {
		return ingest.Options{}, fail(stderr, exitData, "%v", err)
	}
	opts := ingest.Options{
		DBPath:    dbPath,
		CacheDir:  f.cache,
		KeepCache: f.keepCache,
		Workers:   f.workers,
		Refresh:   f.refresh,
	}
	if opts.CacheDir == "" {
		opts.CacheDir = filepath.Join(filepath.Dir(dbPath), "cache")
	}
	if !f.quiet {
		opts.Log = stderr
	}
	if f.years != "" {
		from, to, err := store.ParseYearRange(f.years)
		if err != nil {
			return ingest.Options{}, fail(stderr, exitUsage, "%v", err)
		}
		opts.YearsFrom, opts.YearsTo = from, to
	}
	return opts, exitOK
}

func runSync(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("sync")
	var f ingestFlags
	f.register(fs)
	if status, ok := parseFlags(fs, args, stdout, stderr); !ok {
		return status
	}
	opts, code := f.options(stdout, stderr)
	if code != exitOK {
		return code
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	sum, err := ingest.Sync(ctx, opts)
	if err != nil {
		return fail(stderr, exitData, "%v", err)
	}
	return reportIngest(stdout, stderr, "sync", sum, f.json)
}

func runUpdate(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("update")
	var f ingestFlags
	f.register(fs)
	if status, ok := parseFlags(fs, args, stdout, stderr); !ok {
		return status
	}
	// Year selection only applies to a full sync.
	if strings.TrimSpace(f.years) != "" {
		return fail(stderr, exitUsage, "update does not take -years; run 'cv3 sync' to change the corpus range")
	}
	opts, code := f.options(stdout, stderr)
	if code != exitOK {
		return code
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	sum, err := ingest.Update(ctx, opts)
	if err != nil {
		return fail(stderr, exitData, "%v", err)
	}
	return reportIngest(stdout, stderr, "update", sum, f.json)
}

func reportIngest(stdout, stderr io.Writer, kind string, sum ingest.Summary, jsonOut bool) int {
	doc := report.IngestDoc{
		CVEs:        sum.CVEs,
		Enriched:    sum.Enriched,
		CPEs:        sum.CPEs,
		Products:    sum.Products,
		CWEs:        sum.CWEs,
		Refs:        sum.Refs,
		ParseErrors: sum.ParseErrors,
		Warnings:    sum.Warnings,
		NewCVEs:     sum.NewCVEs,
		UpdatedCVEs: sum.UpdatedCVEs,
		DeltaTags:   sum.DeltaTags,
		DurationMS:  sum.Duration.Milliseconds(),
		DBSize:      sum.DBSize,
		DBPath:      sum.DBPath,
		Sources:     sum.Sources,
	}
	if jsonOut {
		if err := report.WriteJSON(stdout, report.IngestEnvelope{SchemaVersion: report.SchemaVersion, Summary: doc}); err != nil {
			return fail(stderr, exitData, "%v", err)
		}
		return exitOK
	}
	fmt.Fprintf(stderr, "cv3: %s complete in %s\n", kind, sum.Duration.Round(time.Second))
	fmt.Fprintf(stdout, "database:  %s (%s)\n", sum.DBPath, humanBytes(sum.DBSize))
	fmt.Fprintf(stdout, "cves:      %d (%d nvd-enriched, %d cvelistV5 only)\n", sum.CVEs, sum.Enriched, sum.CVEs-sum.Enriched)
	fmt.Fprintf(stdout, "cpe:       %d matches, %d cna products\n", sum.CPEs, sum.Products)
	fmt.Fprintf(stdout, "cwe:       %d catalog entries\n", sum.CWEs)
	fmt.Fprintf(stdout, "refs:      %d\n", sum.Refs)
	if sum.NewCVEs > 0 || sum.UpdatedCVEs > 0 {
		fmt.Fprintf(stdout, "changed:   %d new, %d updated\n", sum.NewCVEs, sum.UpdatedCVEs)
	}
	if len(sum.DeltaTags) > 0 {
		fmt.Fprintf(stdout, "deltas:    %s\n", strings.Join(sum.DeltaTags, ", "))
	}
	if sum.ParseErrors > 0 {
		fmt.Fprintf(stderr, "cv3: %d records could not be parsed\n", sum.ParseErrors)
	}
	for _, w := range sum.Warnings {
		fmt.Fprintf(stderr, "cv3: warning: %s\n", w)
	}
	return exitOK
}
