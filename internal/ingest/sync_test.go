package ingest

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fr0g-66723067-io/cv3/internal/model"
	"github.com/fr0g-66723067-io/cv3/internal/store"
)

// zipBytes builds an in-memory archive from a name->body map.
func zipBytes(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range members {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// fixtureServer serves the cvelistV5 release API, its archives, the NVD feed
// and the CWE catalog so Sync and Update can run without the network.
type fixtureServer struct {
	t        *testing.T
	server   *httptest.Server
	mu       sync.Mutex
	releases []Release
	archives map[string][]byte // path -> body
	feedGz   []byte
	cweZip   []byte
}

func newFixtureServer(t *testing.T) *fixtureServer {
	t.Helper()
	f := &fixtureServer{
		t:        t,
		archives: map[string][]byte{},
		feedGz:   readFixture(t, "nvd", "feed-fragment.json.gz"),
		cweZip: zipBytes(t, map[string][]byte{
			"cwec_v5.0.xml": readFixture(t, "cwe", "cwec-fragment.xml"),
		}),
	}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fixtureServer) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	releases := append([]Release(nil), f.releases...)
	f.mu.Unlock()

	switch {
	case r.URL.Path == "/repos/CVEProject/cvelistV5/releases/latest":
		if len(releases) == 0 {
			http.NotFound(w, r)
			return
		}
		writeRelease(w, releases[0])
	case r.URL.Path == "/repos/CVEProject/cvelistV5/releases":
		writeReleases(w, releases)
	case r.URL.Path == "/feed/recent.json.gz" || r.URL.Path == "/feed/modified.json.gz" ||
		len(r.URL.Path) > len("/feed/") && r.URL.Path[:len("/feed/")] == "/feed/":
		f.mu.Lock()
		body := f.feedGz
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/gzip")
		w.Write(body)
	case r.URL.Path == "/cwec_latest.xml.zip":
		f.mu.Lock()
		body := f.cweZip
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/zip")
		w.Write(body)
	default:
		f.mu.Lock()
		body, ok := f.archives[r.URL.Path]
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Write(body)
	}
}

type ghAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

type ghReleaseJSON struct {
	TagName     string    `json:"tag_name"`
	PublishedAt string    `json:"published_at"`
	Assets      []ghAsset `json:"assets"`
}

func releaseJSON(r Release) ghReleaseJSON {
	item := ghReleaseJSON{TagName: r.Tag, PublishedAt: r.Published.Format(time.RFC3339)}
	for name, url := range r.Assets {
		item.Assets = append(item.Assets, ghAsset{Name: name, URL: url})
	}
	return item
}

// writeRelease renders the single-release form served by /releases/latest.
func writeRelease(w http.ResponseWriter, r Release) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(releaseJSON(r))
}

func writeReleases(w http.ResponseWriter, releases []Release) {
	out := make([]ghReleaseJSON, 0, len(releases))
	for _, r := range releases {
		out = append(out, releaseJSON(r))
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// addRelease registers an all-CVEs release for tag and serves archive under
// /assets/<file>.
func (f *fixtureServer) addRelease(tag, assetName, assetPath string, body []byte) {
	f.t.Helper()
	ts, err := tagTime(tag)
	if err != nil {
		f.t.Fatalf("tagTime(%q): %v", tag, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.archives[assetPath] = body
	f.releases = append([]Release{{
		Tag:       tag,
		Published: ts,
		Assets:    map[string]string{assetName: f.server.URL + assetPath},
	}}, f.releases...)
}

func (f *fixtureServer) addDelta(tag, assetPath string, body []byte) {
	f.t.Helper()
	ts, err := tagTime(tag)
	if err != nil {
		f.t.Fatalf("tagTime(%q): %v", tag, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.archives[assetPath] = body
	f.releases = append([]Release{{
		Tag:       tag,
		Published: ts,
		Assets:    map[string]string{"2026-10-30_delta_CVEs_at_" + ts.Format("1504Z") + ".zip": f.server.URL + assetPath},
	}}, f.releases...)
}

func (f *fixtureServer) options(dbPath, cacheDir string) Options {
	return Options{
		DBPath:    dbPath,
		CacheDir:  cacheDir,
		Workers:   2,
		YearsFrom: 2024,
		YearsTo:   2024,
		MinFree:   1 << 20,
		Fetcher: &Fetcher{
			Dir:     cacheDir,
			Retries: 1,
			backoff: []time.Duration{time.Millisecond},
		},
		APIBase: f.server.URL,
		FeedURL: func(name string) string { return f.server.URL + "/feed/" + name + ".json.gz" },
		CWEURL:  f.server.URL + "/cwec_latest.xml.zip",
	}
}

func TestSyncBuildsDatabase(t *testing.T) {
	f := newFixtureServer(t)
	allZip := zipBytes(t, map[string][]byte{
		"cves/2024/3xxx/CVE-2024-3094.json":   readFixture(t, "cvelist", "CVE-2024-3094.json"),
		"cves/2026/31xxx/CVE-2026-31419.json": readFixture(t, "cvelist", "adp-cpe.json"),
	})
	f.addRelease("cve_2026-10-30_1800Z", "2026-10-30_all_CVEs_at_midnight.zip.zip", "/assets/all-1800.zip", allZip)

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cv3.db")
	sum, err := Sync(context.Background(), f.options(dbPath, filepath.Join(dir, "cache")))
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if sum.ParseErrors != 0 {
		t.Fatalf("ParseErrors = %d", sum.ParseErrors)
	}
	// cvelistV5 contributes two ids; the NVD fragment contributes a third
	// (CVE-2024-51346) that the release does not carry.
	if sum.CVEs != 3 || sum.Enriched != 2 {
		t.Fatalf("summary cves=%d enriched=%d, want 3/2", sum.CVEs, sum.Enriched)
	}
	if sum.CWEs != 3 {
		t.Fatalf("summary cwes = %d", sum.CWEs)
	}
	if sum.Sources[SourceCVEList] != "cve_2026-10-30_1800Z" || sum.Sources[SourceCWE] != "5.0" {
		t.Fatalf("sources = %v", sum.Sources)
	}
	if _, err := os.Stat(dbPath + ".new"); !os.IsNotExist(err) {
		t.Fatalf("staged database left behind: %v", err)
	}
	if sum.DBSize <= 0 {
		t.Fatalf("db size = %d", sum.DBSize)
	}

	ro, err := store.Open(dbPath, true)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer ro.Close()
	ctx := context.Background()

	c, err := ro.Get(ctx, "CVE-2024-3094")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !c.Enriched || c.NVDStatus != "Modified" {
		t.Fatalf("enrichment = %v/%q", c.Enriched, c.NVDStatus)
	}
	if c.Best == nil || c.Best.Score != 10.0 || c.BestVersion != model.VerV31 {
		t.Fatalf("best = %+v", c.Best)
	}
	if c.SummarySrc != "nvd" {
		t.Fatalf("summary source = %q, want nvd", c.SummarySrc)
	}
	// NVD contributes two exact-version tukaani:xz rows; cvelist contributes
	// ADP rows for the Red Hat products.
	var tukaani, redhat int
	for _, m := range c.CPEs {
		switch m.Name.Vendor {
		case "tukaani":
			tukaani++
		case "redhat":
			redhat++
		}
	}
	if tukaani != 2 || redhat == 0 {
		t.Fatalf("cpe rows: tukaani=%d redhat=%d", tukaani, redhat)
	}
	var cwe506 bool
	for _, w := range c.CWEs {
		if w.ID == "CWE-506" {
			cwe506 = true
		}
	}
	if !cwe506 {
		t.Fatalf("CWE-506 missing: %+v", c.CWEs)
	}

	// The id only NVD knows about still exists.
	if _, err := ro.Get(ctx, "CVE-2024-51346"); err != nil {
		t.Fatalf("Get(NVD-only): %v", err)
	}

	res, err := ro.Search(ctx, store.SearchQuery{Query: "malicious"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if res.Total == 0 {
		t.Fatal("search found nothing")
	}
	hits, err := ro.ByCPE(ctx, store.CPEFilter{Vendor: "tukaani", Product: "xz", Version: "5.6.1"})
	if err != nil {
		t.Fatalf("ByCPE: %v", err)
	}
	if len(hits) != 1 || hits[0].CVE != "CVE-2024-3094" || hits[0].MatchKind != "exact" {
		t.Fatalf("ByCPE = %+v", hits)
	}
}

func TestUpdateAppliesDeltasAndFeeds(t *testing.T) {
	f := newFixtureServer(t)
	allZip := zipBytes(t, map[string][]byte{
		"cves/2024/3xxx/CVE-2024-3094.json": readFixture(t, "cvelist", "CVE-2024-3094.json"),
	})
	f.addRelease("cve_2026-10-30_1800Z", "2026-10-30_all_CVEs_at_midnight.zip.zip", "/assets/all-1800.zip", allZip)

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cv3.db")
	cacheDir := filepath.Join(dir, "cache")
	opts := f.options(dbPath, cacheDir)
	if _, err := Sync(context.Background(), opts); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// One new CVE arrives in the next hourly delta.
	delta := zipBytes(t, map[string][]byte{
		"deltaCves/CVE-2024-7777.json": []byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1",
			"cveMetadata":{"cveId":"CVE-2024-7777","state":"PUBLISHED","assignerShortName":"example",
			"datePublished":"2026-10-30T19:00:00.000Z","dateUpdated":"2026-10-30T19:00:00.000Z"},
			"containers":{"cna":{"descriptions":[{"lang":"en","value":"Delta-only record for update testing."}],
			"metrics":[{"cvssV3_1":{"version":"3.1","baseScore":7.5,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}],
			"problemTypes":[{"descriptions":[{"type":"CWE","cweId":"CWE-79","lang":"en"}]}]}}}`),
	})
	f.addDelta("cve_2026-10-30_1900Z", "/assets/delta-1900.zip", delta)

	opts.Now = func() time.Time { return time.Date(2026, 10, 30, 19, 30, 0, 0, time.UTC) }
	sum, err := Update(context.Background(), opts)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if len(sum.DeltaTags) != 1 || sum.DeltaTags[0] != "cve_2026-10-30_1900Z" {
		t.Fatalf("delta tags = %v", sum.DeltaTags)
	}
	if sum.NewCVEs != 1 {
		t.Fatalf("NewCVEs = %d, want 1", sum.NewCVEs)
	}
	if got := sum.Sources[SourceCVEList]; got != "cve_2026-10-30_1900Z" {
		t.Fatalf("watermark = %q", got)
	}

	ro, err := store.Open(dbPath, true)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	c, err := ro.Get(context.Background(), "CVE-2024-7777")
	ro.Close()
	if err != nil {
		t.Fatalf("Get(new): %v", err)
	}
	if c.Best == nil || c.Best.Score != 7.5 || c.Best.Severity != "high" {
		t.Fatalf("new record metric = %+v", c.Best)
	}
	if len(c.CWEs) != 1 || c.CWEs[0].ID != "CWE-79" {
		t.Fatalf("new record cwes = %+v", c.CWEs)
	}

	// A second run with no newer release and the same rolling feeds changes no
	// row counts.
	before := countRows(context.Background(), mustOpen(t, dbPath), `SELECT count(*) FROM cve`)
	sum2, err := Update(context.Background(), opts)
	if err != nil {
		t.Fatalf("Update(second): %v", err)
	}
	if len(sum2.DeltaTags) != 0 || sum2.NewCVEs != 0 {
		t.Fatalf("second update = %+v", sum2)
	}
	after := countRows(context.Background(), mustOpen(t, dbPath), `SELECT count(*) FROM cve`)
	if before != after {
		t.Fatalf("row count changed on no-op update: %d -> %d", before, after)
	}
}

func mustOpen(t *testing.T, path string) *store.DB {
	t.Helper()
	d, err := store.Open(path, true)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestUpdateRefusesStaleWatermark(t *testing.T) {
	f := newFixtureServer(t)
	allZip := zipBytes(t, map[string][]byte{
		"cves/2024/3xxx/CVE-2024-3094.json": readFixture(t, "cvelist", "CVE-2024-3094.json"),
	})
	f.addRelease("cve_2026-10-01_0000Z", "2026-10-01_all_CVEs_at_midnight.zip.zip", "/assets/all-oct1.zip", allZip)

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cv3.db")
	opts := f.options(dbPath, filepath.Join(dir, "cache"))
	if _, err := Sync(context.Background(), opts); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	opts.Now = func() time.Time { return time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC) }
	if _, err := Update(context.Background(), opts); err == nil {
		t.Fatal("Update accepted a watermark older than 8 days")
	} else if got := fmt.Sprint(err); !contains(got, "run `cv3 sync`") {
		t.Fatalf("error = %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && bytes.Contains([]byte(s), []byte(sub))
}
