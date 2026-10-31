package ingest

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fr0g-66723067-io/cv3/internal/store"
)

// gzipFragment wraps one NVD vulnerability object in a feed envelope.
func gzipFragment(t *testing.T, vuln string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	head := `{"CVE_data_format":"NVD_CVE","version":"2.0","timestamp":"2026-10-30T20:00:00.000","totalResults":1,"vulnerabilities":[`
	if _, err := zw.Write([]byte(head + vuln + `]}`)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func openRO(t *testing.T, path string) *store.DB {
	t.Helper()
	d, err := store.Open(path, true)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// TestUpdateRefetchesRollingFeeds pins the difference between a cached
// year archive (immutable once published) and the rolling modified/recent
// feeds, which are re-published under the same file name and must never be
// served from the cache.
func TestUpdateRefetchesRollingFeeds(t *testing.T) {
	f := newFixtureServer(t)
	allZip := zipBytes(t, map[string][]byte{
		"cves/2024/3xxx/CVE-2024-3094.json": readFixture(t, "cvelist", "CVE-2024-3094.json"),
	})
	f.addRelease("cve_2026-10-30_1800Z", "2026-10-30_all_CVEs_at_midnight.zip.zip", "/assets/all-1800.zip", allZip)

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cv3.db")
	opts := f.options(dbPath, filepath.Join(dir, "cache"))
	// Keeping the cache is what makes the rolling-feed distinction matter: a
	// naive cache-first fetch would then replay yesterday's modified feed.
	opts.KeepCache = true
	if _, err := Sync(context.Background(), opts); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if _, err := os.Stat(feedDest(opts, "modified")); err != nil {
		t.Fatalf("feed not cached after sync: %v", err)
	}

	// A later NVD snapshot carries a record the first one did not.
	f.mu.Lock()
	f.feedGz = gzipFragment(t, `{"cve":{
		"id":"CVE-2024-8888","vulnStatus":"Analyzed",
		"published":"2024-09-01T00:00:00.000","lastModified":"2024-09-02T00:00:00.000",
		"descriptions":[{"lang":"en","value":"Rolling feed refresh record."}],
		"metrics":{"cvssMetricV31":[{"source":"nvd@nist.gov","type":"Primary",
			"cvssData":{"version":"3.1","baseScore":8.1,"baseSeverity":"HIGH",
			"vectorString":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}}`)
	f.mu.Unlock()

	opts.Now = func() time.Time { return time.Date(2026, 10, 30, 19, 30, 0, 0, time.UTC) }
	if _, err := Update(context.Background(), opts); err != nil {
		t.Fatalf("Update: %v", err)
	}
	c, err := openRO(t, dbPath).Get(context.Background(), "CVE-2024-8888")
	if err != nil {
		t.Fatalf("Get(refreshed record): %v", err)
	}
	if c.Best == nil || c.Best.Score != 8.1 || c.SummarySrc != "nvd" {
		t.Fatalf("record = %+v", c.Best)
	}
	if !c.Enriched {
		t.Fatal("refreshed record not marked enriched")
	}
}

// TestUpdateSurvivesMissingRollingFeed pins the 2026-10-31 upstream behaviour:
// nvdcve-2.0-modified.json.gz answered 404 while -recent.json.gz answered 200.
// A missing rolling feed loses freshness, not completeness, so the update
// completes and reports a warning.
func TestUpdateSurvivesMissingRollingFeed(t *testing.T) {
	f := newFixtureServer(t)
	allZip := zipBytes(t, map[string][]byte{
		"cves/2024/3xxx/CVE-2024-3094.json": readFixture(t, "cvelist", "CVE-2024-3094.json"),
	})
	f.addRelease("cve_2026-10-30_1800Z", "2026-10-30_all_CVEs_at_midnight.zip.zip", "/assets/all-1800.zip", allZip)

	dir := t.TempDir()
	opts := f.options(filepath.Join(dir, "cv3.db"), filepath.Join(dir, "cache"))
	if _, err := Sync(context.Background(), opts); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	f.mu.Lock()
	f.missing["modified"] = true
	f.mu.Unlock()

	opts.Now = func() time.Time { return time.Date(2026, 10, 30, 19, 30, 0, 0, time.UTC) }
	sum, err := Update(context.Background(), opts)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if len(sum.Warnings) != 1 || !strings.Contains(sum.Warnings[0], "modified") {
		t.Fatalf("warnings = %v", sum.Warnings)
	}
	if sum.CVEs == 0 {
		t.Fatalf("summary not filled: %+v", sum)
	}
}
