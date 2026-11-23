package ingest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/fr0g-66723067-io/cv3/internal/model"
	"github.com/fr0g-66723067-io/cv3/internal/store"
)

// Source names recorded in source_state.
const (
	SourceCVEList = "cvelistV5"
	SourceNVD     = "nvd"
	SourceCWE     = "cwe"
)

// nvdFeedBase is the CVE 2.0 feed directory; %s is a year, "recent" or
// "modified".
const nvdFeedBase = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-%s.json.gz"

// cweCatalogURL is the always-current MITRE CWE catalog archive.
const cweCatalogURL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

// Options configures a sync or update run. Every zero value has a working
// default; the URL/fetcher/API hooks exist for tests.
type Options struct {
	DBPath   string
	CacheDir string
	Token    string // GITHUB_TOKEN, only raises the API rate limit

	KeepCache bool
	Workers   int
	Log       io.Writer
	Refresh   bool // re-download assets even when the cache has them

	YearsFrom, YearsTo int
	MinFree            int64 // bytes required in the DB directory; 0 = default

	// Test hooks.
	Fetcher *Fetcher
	APIBase string
	FeedURL func(name string) string
	CWEURL  string
	Now     func() time.Time
}

func (o *Options) normalize() error {
	if o.DBPath == "" {
		return errors.New("ingest: no database path")
	}
	if o.Workers <= 0 {
		o.Workers = min(8, runtime.NumCPU())
	}
	if o.Workers > 32 {
		o.Workers = 32
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	if o.YearsTo <= 0 {
		o.YearsTo = now().Year()
	}
	if o.YearsFrom <= 0 {
		o.YearsFrom = 2002
	}
	if o.YearsFrom > o.YearsTo {
		return fmt.Errorf("ingest: year range %d-%d is backwards", o.YearsFrom, o.YearsTo)
	}
	if o.MinFree == 0 {
		o.MinFree = minimumFree
	}
	if o.CacheDir == "" {
		o.CacheDir = filepath.Join(filepath.Dir(o.DBPath), "cache")
	}
	if o.Fetcher == nil {
		o.Fetcher = &Fetcher{Dir: o.CacheDir, Retries: 3}
	}
	o.Fetcher.Dir = o.CacheDir
	o.Fetcher.Force = o.Refresh
	if o.FeedURL == nil {
		o.FeedURL = func(name string) string { return fmt.Sprintf(nvdFeedBase, name) }
	}
	if o.CWEURL == "" {
		o.CWEURL = cweCatalogURL
	}
	if o.APIBase == "" {
		o.APIBase = "https://api.github.com"
	}
	if o.Token == "" {
		o.Token = os.Getenv("GITHUB_TOKEN")
	}
	return nil
}

func (o *Options) releasesAPI() string {
	return o.APIBase + "/repos/CVEProject/cvelistV5/releases"
}

// Summary reports what a sync or update did.
type Summary struct {
	CVEs        int
	Enriched    int
	CPEs        int
	Products    int
	CWEs        int
	Refs        int
	ParseErrors int
	Warnings    []string
	NewCVEs     int
	UpdatedCVEs int
	DeltaTags   []string
	Duration    time.Duration
	DBSize      int64
	Sources     map[string]string
	DBPath      string
}

// minimumFree is the disk space a full sync requires in the database directory:
// the cvelistV5 archive (647 MB) plus the database itself.
const minimumFree = 8 << 30

// Sync builds a new database from scratch and renames it over DBPath. A failure
// leaves any existing database untouched.
func Sync(ctx context.Context, o Options) (Summary, error) {
	started := time.Now()
	if err := o.normalize(); err != nil {
		return Summary{}, err
	}
	log := o.Log
	dir := filepath.Dir(o.DBPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return Summary{}, fmt.Errorf("ingest: sync: %w", err)
	}
	if err := checkFree(dir, o.MinFree); err != nil {
		return Summary{}, err
	}
	if err := os.MkdirAll(o.CacheDir, 0o750); err != nil {
		return Summary{}, fmt.Errorf("ingest: sync: %w", err)
	}
	release, err := latestReleaseAt(ctx, o.releasesAPI(), o.Token)
	if err != nil {
		return Summary{}, err
	}
	allURL, ok := release.AllCVEsAsset()
	if !ok {
		return Summary{}, fmt.Errorf("ingest: sync: release %s has no all-CVEs asset", release.Tag)
	}
	allZip := filepath.Join(o.CacheDir, "cvelistV5-"+release.Tag+".zip")
	if !o.KeepCache {
		defer os.Remove(allZip)
	}
	if log != nil {
		fmt.Fprintf(log, "cv3: cvelistV5 %s: downloading all-CVEs archive\n", release.Tag)
	}
	if err := o.Fetcher.Get(ctx, allURL, allZip, log); err != nil {
		return Summary{}, err
	}
	prefetchDone := make(chan error, 1)
	go func() { prefetchDone <- prefetchFeeds(ctx, o, log) }()

	newPath := o.DBPath + ".new"
	if err := os.Remove(newPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Summary{}, fmt.Errorf("ingest: sync: %w", err)
	}
	w, err := store.Create(newPath)
	if err != nil {
		return Summary{}, err
	}
	fail := func(err error) (Summary, error) {
		w.Close()
		os.Remove(newPath)
		return Summary{}, err
	}

	// Base corpus.
	written, failed, err := runPipeline(ctx, o.Workers, 512,
		func(yield func([]byte) error) error {
			_, _, err := WalkCVEZip(ctx, allZip, func(id string, raw []byte) error {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return yield(raw)
			})
			return err
		}, ParseCVEListV5, w)
	if err != nil {
		return fail(err)
	}
	if written == 0 {
		return fail(fmt.Errorf("ingest: sync: cvelistV5 archive yielded no writable records"))
	}
	if log != nil {
		fmt.Fprintf(log, "cv3: cvelistV5: %d records parsed, %d unparsable\n", written, failed)
	}
	totalFailed := failed
	if err := <-prefetchDone; err != nil {
		return fail(err)
	}

	// NVD enrichment, oldest year first so the rolling feeds land last. The
	// feeds were fetched concurrently while the base corpus was parsed.
	nvdTimestamp := ""
	for year := o.YearsFrom; year <= o.YearsTo; year++ {
		failed, ts, err := ingestFeed(ctx, o, w, fmt.Sprint(year), false, log)
		if err != nil {
			return fail(err)
		}
		totalFailed += failed
		nvdTimestamp = ts
	}
	warnings := []string{}
	for _, name := range []string{"recent", "modified"} {
		failed, ts, err := ingestFeed(ctx, o, w, name, false, log)
		if err != nil {
			// A rolling feed disappears upstream from time to time (measured
			// 2026-10-31: nvdcve-2.0-modified.json.gz answered 404 while
			// -recent.json.gz answered 200). Losing one loses freshness, not
			// corpus completeness, so the sync continues and reports it.
			warnings = append(warnings, fmt.Sprintf("%s feed unavailable: %v", name, err))
			continue
		}
		totalFailed += failed
		nvdTimestamp = ts
	}

	// CWE catalog.
	cweZip := filepath.Join(o.CacheDir, "cwec_latest.xml.zip")
	if !o.KeepCache {
		defer os.Remove(cweZip)
	}
	if err := o.Fetcher.Get(ctx, o.CWEURL, cweZip, log); err != nil {
		return fail(err)
	}
	entries, version, err := ParseCWEZip(cweZip)
	if err != nil {
		return fail(err)
	}
	models := make([]*model.CWE, len(entries))
	for i := range entries {
		models[i] = &entries[i]
	}
	if err := w.PutCWEAll(ctx, models); err != nil {
		return fail(err)
	}
	if log != nil {
		fmt.Fprintf(log, "cv3: cwe: %d entries from catalog %s\n", len(models), version)
	}

	if err := w.BuildDerived(ctx); err != nil {
		return fail(err)
	}
	if err := w.SetSourceState(ctx, SourceCVEList, release.Tag); err != nil {
		return fail(err)
	}
	if nvdTimestamp == "" {
		return fail(fmt.Errorf("ingest: sync: no NVD feed timestamp"))
	}
	if err := w.SetSourceState(ctx, SourceNVD, feedWatermark(nvdTimestamp)); err != nil {
		return fail(err)
	}
	if err := w.SetSourceState(ctx, SourceCWE, version); err != nil {
		return fail(err)
	}
	if err := w.SetMeta(ctx, "built_at", time.Now().UTC().Format(time.RFC3339)); err != nil {
		return fail(err)
	}
	if err := w.Close(); err != nil {
		return fail(fmt.Errorf("ingest: sync: %w", err))
	}
	if err := os.Rename(newPath, o.DBPath); err != nil {
		os.Remove(newPath)
		return Summary{}, fmt.Errorf("ingest: sync: %w", err)
	}

	sum := Summary{
		ParseErrors: totalFailed,
		Warnings:    warnings,
		Duration:    time.Since(started),
		DBPath:      o.DBPath,
		Sources:     map[string]string{SourceCVEList: release.Tag, SourceCWE: version},
	}
	if err := fillSummary(&sum); err != nil {
		return sum, err
	}
	return sum, nil
}

// feedDest is the cache path of one NVD feed.
func feedDest(o Options, name string) string {
	return filepath.Join(o.CacheDir, "nvdcve-2.0-"+name+".json.gz")
}

// prefetchFeeds downloads the NVD feeds concurrently while the cvelistV5 pass
// runs. NVD serves about 200 KB/s per connection, so the corpus download is
// slower than parsing it; overlapping the two removes the download from the
// critical path.
func prefetchFeeds(ctx context.Context, o Options, log io.Writer) error {
	names := make([]string, 0, 8)
	for year := o.YearsFrom; year <= o.YearsTo; year++ {
		names = append(names, fmt.Sprint(year))
	}
	names = append(names, "recent", "modified")

	const parallel = 4
	sem := make(chan struct{}, parallel)
	errCh := make(chan error, len(names))
	var wg sync.WaitGroup
	for _, name := range names {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			}
			defer func() { <-sem }()
			if err := o.Fetcher.Get(ctx, o.FeedURL(name), feedDest(o, name), log); err != nil {
				errCh <- err
			}
		}(name)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

// feedWatermark normalises a feed timestamp. ParseNVDFeed rejects a feed that
// carries none, so an empty result means there is no usable feed and the caller
// must not record freshness.
func feedWatermark(ts string) string {
	return model.NormalizeTime(ts)
}

// ingestFeed downloads and applies one NVD feed (a year, "recent" or
// "modified"). It returns the number of unparsable records and the feed's own
// timestamp, which becomes the NVD watermark.
func ingestFeed(ctx context.Context, o Options, w *store.DB, name string, fresh bool, log io.Writer) (failed int, timestamp string, err error) {
	url := o.FeedURL(name)
	dest := feedDest(o, name)
	if fresh {
		err = o.Fetcher.GetFresh(ctx, url, dest, log)
	} else {
		err = o.Fetcher.Get(ctx, url, dest, log)
	}
	if err != nil {
		return 0, "", err
	}
	if !o.KeepCache {
		defer os.Remove(dest)
	}
	f, err := openFile(dest)
	if err != nil {
		return 0, "", fmt.Errorf("ingest: nvd %s: %w", name, err)
	}
	defer f.Close()
	var seen int
	_, failed, err = runPipeline(ctx, o.Workers, 512,
		func(yield func([]byte) error) error {
			count, ts, err := ParseNVDFeed(f, func(raw []byte) error {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return yield(raw)
			})
			seen, timestamp = count, ts
			return err
		}, ParseNVDRecord, w)
	if err != nil {
		return failed, timestamp, err
	}
	if log != nil {
		fmt.Fprintf(log, "cv3: nvd %s: %d records applied\n", name, seen)
	}
	return failed, timestamp, nil
}

// Update applies cvelistV5 hourly deltas published since the stored watermark,
// then the rolling NVD modified/recent feeds.
func Update(ctx context.Context, o Options) (Summary, error) {
	started := time.Now()
	if err := o.normalize(); err != nil {
		return Summary{}, err
	}
	log := o.Log
	w, err := store.Open(o.DBPath, false)
	if err != nil {
		return Summary{}, err
	}
	defer w.Close()

	state, err := w.SourceState(ctx)
	if err != nil {
		return Summary{}, err
	}
	watermark := state[SourceCVEList]
	if watermark == "" {
		return Summary{}, fmt.Errorf("ingest: update: no cvelistV5 watermark; run `cv3 sync`")
	}
	wm, err := tagTime(watermark)
	if err != nil {
		return Summary{}, err
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	if now().Sub(wm) > 8*24*time.Hour {
		return Summary{}, fmt.Errorf("ingest: update: cvelistV5 watermark %q is older than 8 days; run `cv3 sync`", watermark)
	}

	before := countRows(ctx, w, `SELECT count(*) FROM cve`)

	releases, err := listReleasesAt(ctx, o.releasesAPI(), o.Token)
	if err != nil {
		return Summary{}, err
	}
	var pending []Release
	for _, r := range releases {
		if r.Published.After(wm) {
			pending = append(pending, r)
		}
	}
	if len(pending) > 100 {
		return Summary{}, fmt.Errorf("ingest: update: %d pending cvelistV5 releases; run `cv3 sync`", len(pending))
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].Published.Before(pending[j].Published) })

	sum := Summary{
		DBPath:  o.DBPath,
		Sources: map[string]string{},
	}
	if err := os.MkdirAll(o.CacheDir, 0o750); err != nil {
		return sum, fmt.Errorf("ingest: update: %w", err)
	}
	for _, r := range pending {
		url, ok := r.DeltaAsset()
		if !ok {
			continue
		}
		dest := filepath.Join(o.CacheDir, "cvelistV5-delta-"+r.Tag+".zip")
		if err := o.Fetcher.Get(ctx, url, dest, log); err != nil {
			return sum, err
		}
		written, failed, err := runPipeline(ctx, o.Workers, 512,
			func(yield func([]byte) error) error {
				_, _, err := WalkCVEZip(ctx, dest, func(id string, raw []byte) error {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					return yield(raw)
				})
				return err
			}, ParseCVEListV5, w)
		if !o.KeepCache {
			os.Remove(dest)
		}
		if err != nil {
			return sum, err
		}
		sum.ParseErrors += failed
		sum.UpdatedCVEs += written
		sum.DeltaTags = append(sum.DeltaTags, r.Tag)
		if log != nil {
			fmt.Fprintf(log, "cv3: cvelistV5 %s: %d records\n", r.Tag, written)
		}
		if err := w.SetSourceState(ctx, SourceCVEList, r.Tag); err != nil {
			return sum, err
		}
	}

	nvdTimestamp := ""
	for _, name := range []string{"modified", "recent"} {
		failed, ts, err := ingestFeed(ctx, o, w, name, true, log)
		if err != nil {
			sum.Warnings = append(sum.Warnings, fmt.Sprintf("%s feed unavailable: %v", name, err))
			continue
		}
		sum.ParseErrors += failed
		nvdTimestamp = ts
	}
	if nvdTimestamp != "" {
		if err := w.SetSourceState(ctx, SourceNVD, feedWatermark(nvdTimestamp)); err != nil {
			return sum, err
		}
	}
	if err := w.SetMeta(ctx, "updated_at", now().UTC().Format(time.RFC3339)); err != nil {
		return sum, err
	}

	after := countRows(ctx, w, `SELECT count(*) FROM cve`)
	sum.NewCVEs = max(0, after-before)
	sum.UpdatedCVEs = max(0, sum.UpdatedCVEs-sum.NewCVEs)
	sum.Duration = time.Since(started)
	if st, err := w.SourceState(ctx); err == nil {
		sum.Sources = st
	}
	if err := fillSummary(&sum); err != nil {
		return sum, err
	}
	return sum, nil
}

func countRows(ctx context.Context, w *store.DB, query string) int {
	n := 0
	if err := w.SQL().QueryRowContext(ctx, query).Scan(&n); err != nil {
		return 0
	}
	return n
}

func fillSummary(sum *Summary) error {
	r, err := store.Open(sum.DBPath, true)
	if err != nil {
		return err
	}
	defer r.Close()
	st, err := r.Stats(context.Background(), store.StatsFilter{})
	if err != nil {
		return err
	}
	sum.CVEs, sum.Enriched = st.CVEs, st.Enriched
	sum.CPEs, sum.Products, sum.CWEs, sum.Refs = st.CPEMatches, st.CVEProducts, st.CWECatalog, st.Refs
	sum.DBSize = st.DBSize
	if sum.Sources == nil || len(sum.Sources) == 0 {
		sum.Sources = st.SourceState
	}
	return nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for n/div >= unit && exp < 4 {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}

// runPipeline parses records in parallel and writes them through a single
// writer in batches. SQLite takes one writer at a time, so the parallelism is
// in the parse (JSON decode is the expensive half) while the transaction stays
// serialized and coarse.
func runPipeline(ctx context.Context, workers, batchSize int,
	produce func(yield func([]byte) error) error,
	parse func([]byte) (*model.CVE, error),
	w *store.DB,
) (written, failed int, err error) {
	type result struct {
		cve *model.CVE
		err error
	}
	jobs := make(chan []byte, workers*4)
	results := make(chan result, workers*4)

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for raw := range jobs {
				c, perr := parse(raw)
				results <- result{cve: c, err: perr}
			}
		}()
	}

	var (
		batch    = make([]*model.CVE, 0, batchSize)
		writeErr error
		count    int
		bad      int
	)
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		flush := func() error {
			if len(batch) == 0 {
				return nil
			}
			if err := w.UpsertCVEAll(ctx, batch); err != nil {
				return err
			}
			count += len(batch)
			batch = batch[:0]
			return nil
		}
		for r := range results {
			if r.err != nil {
				bad++
				continue
			}
			if writeErr != nil {
				continue // drain so the workers never block
			}
			batch = append(batch, r.cve)
			if len(batch) >= batchSize {
				if err := flush(); err != nil {
					writeErr = err
				}
			}
		}
		if writeErr == nil {
			writeErr = flush()
		}
	}()

	prodErr := produce(func(raw []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		jobs <- raw
		return nil
	})
	close(jobs)
	wg.Wait()
	close(results)
	<-writerDone

	switch {
	case prodErr != nil:
		return count, bad, prodErr
	case writeErr != nil:
		return count, bad, writeErr
	}
	return count, bad, nil
}

func latestReleaseAt(ctx context.Context, api, token string) (Release, error) {
	var g ghRelease
	if err := githubGet(ctx, api+"/latest", token, &g); err != nil {
		return Release{}, err
	}
	return toRelease(g)
}

func listReleasesAt(ctx context.Context, api, token string) ([]Release, error) {
	var g []ghRelease
	if err := githubGet(ctx, api+"?per_page=100", token, &g); err != nil {
		return nil, err
	}
	out := make([]Release, 0, len(g))
	for _, item := range g {
		r, err := toRelease(item)
		if err != nil {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Published.After(out[j].Published) })
	return out, nil
}
