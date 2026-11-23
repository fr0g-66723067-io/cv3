package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/fr0g-66723067-io/cv3/internal/cpe"
	"github.com/fr0g-66723067-io/cv3/internal/model"
)

func mustCPE(t *testing.T, s string) cpe.Name {
	t.Helper()
	n, err := cpe.Parse(s)
	if err != nil {
		t.Fatalf("cpe.Parse(%q): %v", s, err)
	}
	return n
}

// fixtureCVEs returns three records: one NVD-enriched with a CPE version range,
// one that exists only in cvelistV5, and one rejected.
func fixtureCVEs(t *testing.T) []*model.CVE {
	t.Helper()
	enriched := &model.CVE{
		ID:         "CVE-2024-3094",
		State:      "PUBLISHED",
		NVDStatus:  "Modified",
		Published:  "2024-03-29T17:15:21Z",
		Modified:   "2024-04-01T10:00:00Z",
		Assigner:   "mitre",
		Summary:    "Malicious code in the xz upstream tarballs creates a backdoor.",
		SummarySrc: "nvd",
		Metrics: map[string]model.Metric{
			model.VerV31: {Score: 10.0, Severity: "critical", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", Source: "nvd-primary"},
		},
		CWEs: []model.CWERef{{ID: "CWE-506", Source: "nvd"}},
		CPEs: []model.CPEMatch{{
			Criteria:   mustCPE(t, "cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*").Criteria(),
			Name:       mustCPE(t, "cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*"),
			Vulnerable: true,
			MatchID:    "MATCH-1",
			StartIncl:  "5.6.0",
			EndExcl:    "5.6.2",
			Source:     "nvd",
		}},
		Refs:     []model.Reference{{URL: "https://example.test/xz-backdoor", Tags: "vendor-advisory"}},
		KEV:      &model.KEV{Added: "2024-04-02", Due: "2024-04-23", Name: "XZ Utils Backdoor"},
		Enriched: true,
	}
	cnaOnly := &model.CVE{
		ID:         "CVE-2099-0001",
		State:      "PUBLISHED",
		Published:  "2099-01-02T00:00:00Z",
		Assigner:   "example",
		Summary:    "OpenSSL accepts a malformed certificate chain in this release.",
		SummarySrc: "cna",
		Metrics: map[string]model.Metric{
			model.VerV31: {Score: 5.3, Severity: "medium", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", Source: "cna"},
		},
		CWEs:     []model.CWERef{{ID: "CWE-79", Source: "cna"}},
		Products: []model.Product{{Vendor: "OpenSSL", Product: "OpenSSL", Versions: `[{"version":"3.0.0","status":"affected"}]`, Source: "cna"}},
		Refs:     []model.Reference{{URL: "https://example.test/openssl-advisory"}},
	}
	rejected := &model.CVE{
		ID:        "CVE-2020-0001",
		State:     "REJECTED",
		Published: "2020-01-01T00:00:00Z",
		Summary:   "Rejected reason: duplicate.",
	}
	return []*model.CVE{enriched, cnaOnly, rejected}
}

// buildDB creates a database at dir/cv3.db, writes the fixtures and returns the
// writable handle (closed) and the path.
func buildDB(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "cv3.db")
	w, err := Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	ctx := context.Background()
	if err := w.UpsertCVEAll(ctx, fixtureCVEs(t)); err != nil {
		w.Close()
		t.Fatalf("UpsertCVEAll: %v", err)
	}
	if err := w.PutCWEAll(ctx, []*model.CWE{
		{
			ID: "CWE-506", Name: "Embedded Malicious Code", Abstraction: "Base", Status: "Incomplete",
			Description: "The product contains code that appears to be malicious.",
		},
		{
			ID: "CWE-79", Name: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
			Abstraction: "Base", Status: "Stable", Description: "The product does not neutralize user-controllable input.",
			Parents: []string{"CWE-74"},
		},
	}); err != nil {
		w.Close()
		t.Fatalf("PutCWEAll: %v", err)
	}
	if err := w.BuildDerived(ctx); err != nil {
		w.Close()
		t.Fatalf("BuildDerived: %v", err)
	}
	if err := w.SetSourceState(ctx, "cvelistV5", "cve_2026-10-30_1900Z"); err != nil {
		w.Close()
		t.Fatalf("SetSourceState: %v", err)
	}
	if err := w.SetMeta(ctx, "built_at", "2026-10-30T19:00:00Z"); err != nil {
		w.Close()
		t.Fatalf("SetMeta: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

func openRO(t *testing.T, path string) *DB {
	t.Helper()
	d, err := Open(path, true)
	if err != nil {
		t.Fatalf("Open(read): %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestUpsertIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := buildDB(t, dir)
	ctx := context.Background()

	// Rewrite the same fixtures through the update profile.
	w, err := Open(path, false)
	if err != nil {
		t.Fatalf("Open(rw): %v", err)
	}
	for range 3 {
		if err := w.UpsertCVEAll(ctx, fixtureCVEs(t)); err != nil {
			w.Close()
			t.Fatalf("UpsertCVEAll: %v", err)
		}
	}
	counts := map[string]int{}
	for _, tbl := range []string{"cve", "cpe_match", "cve_cwe", "cve_product", "cve_ref", "cve_fts"} {
		var n int
		if err := w.db.QueryRow(`SELECT count(*) FROM ` + tbl).Scan(&n); err != nil {
			w.Close()
			t.Fatalf("count %s: %v", tbl, err)
		}
		counts[tbl] = n
	}
	w.Close()
	want := map[string]int{"cve": 3, "cpe_match": 1, "cve_cwe": 2, "cve_product": 1, "cve_ref": 2, "cve_fts": 3}
	for tbl, n := range want {
		if counts[tbl] != n {
			t.Errorf("%s rows = %d, want %d (all: %v)", tbl, counts[tbl], n, counts)
		}
	}
}

func TestSearchRanksAndFilters(t *testing.T) {
	path := buildDB(t, t.TempDir())
	d := openRO(t, path)
	ctx := context.Background()

	res, err := d.Search(ctx, SearchQuery{Query: "backdoor"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if res.Total != 1 || len(res.Hits) != 1 || res.Hits[0].ID != "CVE-2024-3094" {
		t.Fatalf("Search(backdoor) = %+v", res)
	}
	if res.Hits[0].Score == nil || *res.Hits[0].Score != 10.0 {
		t.Fatalf("hit score = %v", res.Hits[0].Score)
	}
	if res.Hits[0].Snippet == "" {
		t.Fatal("hit snippet empty")
	}
	if len(res.Hits[0].CWEs) != 1 || res.Hits[0].CWEs[0] != "CWE-506" {
		t.Fatalf("hit cwes = %v", res.Hits[0].CWEs)
	}

	// Severity + year + CWE combine.
	res, err = d.Search(ctx, SearchQuery{
		Severities: []string{"critical"}, YearsFrom: 2024, YearsTo: 2024, CWEs: []string{"CWE-506"},
	})
	if err != nil {
		t.Fatalf("Search(filters): %v", err)
	}
	if res.Total != 1 || res.Hits[0].ID != "CVE-2024-3094" {
		t.Fatalf("Search(filters) = %+v", res)
	}

	// Unenriched-only finds the cvelistV5-only record.
	res, err = d.Search(ctx, SearchQuery{UnenrichedOnly: true})
	if err != nil {
		t.Fatalf("Search(unenriched): %v", err)
	}
	if res.Total != 2 {
		t.Fatalf("Search(unenriched) total = %d, want 2", res.Total)
	}
	for _, h := range res.Hits {
		if h.Enriched {
			t.Fatalf("unenriched search returned enriched row %s", h.ID)
		}
	}

	// Vendor filter reaches the CNA product table.
	res, err = d.Search(ctx, SearchQuery{Vendors: []string{"openssl"}, Products: []string{"openssl"}})
	if err != nil {
		t.Fatalf("Search(vendor): %v", err)
	}
	if res.Total != 1 || res.Hits[0].ID != "CVE-2099-0001" {
		t.Fatalf("Search(vendor) = %+v", res)
	}

	// Total is the unpaged count while the page is limited.
	res, err = d.Search(ctx, SearchQuery{Limit: 1})
	if err != nil {
		t.Fatalf("Search(limit): %v", err)
	}
	if res.Total != 3 || len(res.Hits) != 1 {
		t.Fatalf("Search(limit) total=%d hits=%d", res.Total, len(res.Hits))
	}

	// KEV filter.
	res, err = d.Search(ctx, SearchQuery{KEVOnly: true})
	if err != nil {
		t.Fatalf("Search(kev): %v", err)
	}
	if res.Total != 1 || res.Hits[0].ID != "CVE-2024-3094" {
		t.Fatalf("Search(kev) = %+v", res)
	}

	// A hostile query must not surface an SQL error as a panic.
	if _, err := d.Search(ctx, SearchQuery{Query: `"unbalanced ( AND NEAR*`}); err != nil {
		t.Fatalf("Search(hostile): %v", err)
	}
}

func TestShorthandQueries(t *testing.T) {
	path := buildDB(t, t.TempDir())
	d := openRO(t, path)
	ctx := context.Background()

	// Prefix query: users type "openssl" but the summary says "OpenSSL".
	res, err := d.Search(ctx, SearchQuery{Query: "openssl"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if res.Total != 1 || res.Hits[0].ID != "CVE-2099-0001" {
		t.Fatalf("Search(openssl) = %+v", res)
	}

	// The products FTS column makes CPE vendor/product searchable without a
	// structured filter.
	res, err = d.Search(ctx, SearchQuery{Query: "tukaani"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if res.Total != 1 || res.Hits[0].ID != "CVE-2024-3094" {
		t.Fatalf("Search(tukaani) = %+v", res)
	}
}

func TestCPERangeMatching(t *testing.T) {
	path := buildDB(t, t.TempDir())
	d := openRO(t, path)
	ctx := context.Background()

	in, err := d.ByCPE(ctx, CPEFilter{Vendor: "tukaani", Product: "xz", Version: "5.6.1"})
	if err != nil {
		t.Fatalf("ByCPE: %v", err)
	}
	if len(in) != 1 || in[0].CVE != "CVE-2024-3094" || in[0].MatchKind != "range" {
		t.Fatalf("ByCPE(5.6.1) = %+v", in)
	}
	if got := in[0].Range; got != ">=5.6.0, <5.6.2" {
		t.Fatalf("range = %q", got)
	}

	out, err := d.ByCPE(ctx, CPEFilter{Vendor: "tukaani", Product: "xz", Version: "5.6.2"})
	if err != nil {
		t.Fatalf("ByCPE: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("ByCPE(5.6.2) = %+v, want none (exclusive end)", out)
	}

	// No version requested: the row is still applicable.
	all, err := d.ByCPE(ctx, CPEFilter{Vendor: "tukaani", Product: "xz"})
	if err != nil {
		t.Fatalf("ByCPE: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("ByCPE(no version) = %+v", all)
	}

	// CNA-only product rows appear as unversioned product matches.
	prod, err := d.ByCPE(ctx, CPEFilter{Vendor: "openssl", Product: "openssl"})
	if err != nil {
		t.Fatalf("ByCPE: %v", err)
	}
	if len(prod) != 1 || prod[0].CVE != "CVE-2099-0001" || prod[0].MatchKind != "product" {
		t.Fatalf("ByCPE(openssl) = %+v", prod)
	}
}

func TestGetAndMissing(t *testing.T) {
	path := buildDB(t, t.TempDir())
	d := openRO(t, path)
	ctx := context.Background()

	c, err := d.Get(ctx, "CVE-2099-0001")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if c.Enriched {
		t.Fatal("unenriched record reported as enriched")
	}
	if c.SummarySrc != "cna" || c.NVDStatus != "" {
		t.Fatalf("summary src %q nvd status %q", c.SummarySrc, c.NVDStatus)
	}
	if c.Best == nil || c.Best.Score != 5.3 || c.BestVersion != model.VerV31 {
		t.Fatalf("best = %+v version %q", c.Best, c.BestVersion)
	}
	if len(c.Products) != 1 || c.Products[0].Vendor != "openssl" {
		t.Fatalf("products = %+v", c.Products)
	}

	if _, err := d.Get(ctx, "CVE-1999-9999"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(missing) error = %v, want ErrNotFound", err)
	}

	kev, err := d.Get(ctx, "CVE-2024-3094")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if kev.KEV == nil || kev.KEV.Name != "XZ Utils Backdoor" {
		t.Fatalf("kev = %+v", kev.KEV)
	}
	if len(kev.CPEs) != 1 || kev.CPEs[0].StartIncl != "5.6.0" || kev.CPEs[0].EndExcl != "5.6.2" {
		t.Fatalf("cpes = %+v", kev.CPEs)
	}
	if len(kev.CWEs) != 1 || kev.CWEs[0].ID != "CWE-506" {
		t.Fatalf("cwes = %+v", kev.CWEs)
	}
}

func TestMergePrecedence(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "cv3.db")
	w, err := Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer w.Close()

	base := &model.CVE{
		ID: "CVE-2024-3094", State: "PUBLISHED", Published: "2024-03-29T00:00:00Z",
		Assigner: "mitre", Summary: "CNA summary.", SummarySrc: "cna",
		Metrics: map[string]model.Metric{
			model.VerV31: {Score: 5.0, Severity: "medium", Source: "cna"},
		},
		Refs: []model.Reference{{URL: "https://cna.test/1", Tags: "vendor"}},
	}
	if err := w.UpsertCVE(ctx, base); err != nil {
		t.Fatalf("UpsertCVE(base): %v", err)
	}
	nvd := &model.CVE{
		ID: "CVE-2024-3094", State: "PUBLISHED", NVDStatus: "Modified",
		Published: "2024-03-29T17:15:21Z", Modified: "2024-04-01T00:00:00Z",
		Summary: "NVD summary.", SummarySrc: "nvd",
		Metrics: map[string]model.Metric{
			model.VerV31: {Score: 10.0, Severity: "critical", Source: "nvd-primary"},
			model.VerV2:  {Score: 9.3, Severity: "high", Source: "nvd-primary"},
		},
		Refs:     []model.Reference{{URL: "https://nvd.test/1"}},
		Enriched: true,
	}
	if err := w.UpsertCVE(ctx, nvd); err != nil {
		t.Fatalf("UpsertCVE(nvd): %v", err)
	}
	// Re-applying the cvelistV5 base must not downgrade the NVD data.
	if err := w.UpsertCVE(ctx, base); err != nil {
		t.Fatalf("UpsertCVE(base again): %v", err)
	}
	ro, err := Open(path, true)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer ro.Close()
	c, err := ro.Get(ctx, "CVE-2024-3094")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if m := c.Metrics[model.VerV31]; m.Score != 10.0 || m.Source != "nvd-primary" {
		t.Fatalf("v31 metric = %+v, want NVD primary 10.0", m)
	}
	if c.SummarySrc != "nvd" || c.Summary != "NVD summary." {
		t.Fatalf("summary = %q from %q, want NVD", c.Summary, c.SummarySrc)
	}
	if !c.Enriched {
		t.Fatal("enriched flag lost on re-merge")
	}
	if c.BestVersion != model.VerV31 || c.Best == nil || c.Best.Score != 10.0 {
		t.Fatalf("best = %+v (%s)", c.Best, c.BestVersion)
	}
	// Both reference sets survive: dependent rows are per source, not merged.
	if len(c.Refs) != 2 {
		t.Fatalf("refs = %+v, want both sources", c.Refs)
	}
}

func TestCWELookup(t *testing.T) {
	path := buildDB(t, t.TempDir())
	d := openRO(t, path)
	ctx := context.Background()

	info, err := d.CWE(ctx, "CWE-79")
	if err != nil {
		t.Fatalf("CWE: %v", err)
	}
	if info.Name == "" || info.CVECount != 1 {
		t.Fatalf("CWE-79 = %+v", info)
	}
	if len(info.Parents) != 1 || info.Parents[0] != "CWE-74" {
		t.Fatalf("parents = %v", info.Parents)
	}
	if _, err := d.CWE(ctx, "CWE-999999"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("CWE(missing) error = %v", err)
	}
	found, err := d.CWESearch(ctx, "malicious", 10)
	if err != nil {
		t.Fatalf("CWESearch: %v", err)
	}
	if len(found) != 1 || found[0].ID != "CWE-506" {
		t.Fatalf("CWESearch = %+v", found)
	}
}

func TestStats(t *testing.T) {
	path := buildDB(t, t.TempDir())
	d := openRO(t, path)
	ctx := context.Background()

	s, err := d.Stats(ctx, StatsFilter{})
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if s.CVEs != 3 || s.Enriched != 1 || s.Unenriched != 2 || s.Rejected != 1 {
		t.Fatalf("stats = %+v", s)
	}
	if s.CPEMatches != 1 || s.CVEProducts != 1 || s.CWECatalog != 2 || s.FTSRows != 3 {
		t.Fatalf("stats counts = %+v", s)
	}
	if s.SourceState["cvelistV5"] != "cve_2026-10-30_1900Z" {
		t.Fatalf("source state = %v", s.SourceState)
	}
	if s.ByYear[2024] != 1 || s.BySeverity["critical"] != 1 {
		t.Fatalf("stats maps = %v %v", s.ByYear, s.BySeverity)
	}
	if s.DBSize <= 0 {
		t.Fatalf("db size = %d", s.DBSize)
	}

	crit, err := d.Stats(ctx, StatsFilter{Severities: []string{"critical"}})
	if err != nil {
		t.Fatalf("Stats(critical): %v", err)
	}
	if crit.CVEs != 1 || crit.Enriched != 1 || crit.FTSRows != 1 {
		t.Fatalf("severity-filtered counts = %+v", crit)
	}
	if len(crit.BySeverity) != 1 || crit.BySeverity["critical"] != 1 {
		t.Fatalf("filtered severities = %v", crit.BySeverity)
	}
	if crit.ByYear[2024] != 1 || len(crit.ByYear) != 1 {
		t.Fatalf("filtered years = %v", crit.ByYear)
	}
	if crit.CWECatalog != 2 {
		t.Fatalf("catalog size must stay global, got %d", crit.CWECatalog)
	}
	if len(crit.Severities) != 1 || crit.Severities[0] != "critical" {
		t.Fatalf("filter echo = %v", crit.Severities)
	}

	// "unknown" is the band of records with no CVSS metric at all.
	unk, err := d.Stats(ctx, StatsFilter{Severities: []string{"unknown"}})
	if err != nil {
		t.Fatalf("Stats(unknown): %v", err)
	}
	if unk.CVEs != 1 || unk.BySeverity["unknown"] != 1 {
		t.Fatalf("unknown band = %+v", unk)
	}
	missing, err := d.Stats(ctx, StatsFilter{Severities: []string{"low"}})
	if err != nil {
		t.Fatalf("Stats(low): %v", err)
	}
	if missing.CVEs != 0 || len(missing.BySeverity) != 0 || len(missing.ByYear) != 0 {
		t.Fatalf("empty band = %+v", missing)
	}
}

func TestDependentOwnership(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "cv3.db")
	w, err := Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer w.Close()

	adpName := mustCPE(t, "cpe:2.3:o:redhat:enterprise_linux:10.1:*:*:*:*:*:*:*")
	published := &model.CVE{
		ID: "CVE-2024-1000", State: "PUBLISHED", Assigner: "example",
		Summary: "Initial description.", SummarySrc: "cna",
		CPEs: []model.CPEMatch{{Criteria: adpName.Criteria(), Name: adpName, Vulnerable: true, Source: "adp"}},
		Refs: []model.Reference{{URL: "https://example.test/a"}},
	}
	if err := w.UpsertCVE(ctx, published); err != nil {
		t.Fatalf("UpsertCVE(published): %v", err)
	}
	// The same record republished without its ADP CPEs must not leave them
	// behind, and its reference set is replaced rather than merged.
	republished := &model.CVE{
		ID: "CVE-2024-1000", State: "PUBLISHED", Assigner: "example",
		Summary: "Updated description.", SummarySrc: "cna",
		Refs: []model.Reference{{URL: "https://example.test/b"}},
	}
	if err := w.UpsertCVE(ctx, republished); err != nil {
		t.Fatalf("UpsertCVE(republished): %v", err)
	}

	ro, err := Open(path, true)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer ro.Close()
	c, err := ro.Get(ctx, "CVE-2024-1000")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(c.CPEs) != 0 {
		t.Fatalf("stale CPE rows survived: %+v", c.CPEs)
	}
	if len(c.Refs) != 1 || c.Refs[0].URL != "https://example.test/b" {
		t.Fatalf("refs = %+v, want only the republished one", c.Refs)
	}
}

func TestStateTransition(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "cv3.db")
	w, err := Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer w.Close()

	if err := w.UpsertCVE(ctx, &model.CVE{
		ID: "CVE-2024-1001", State: "PUBLISHED", Summary: "published", SummarySrc: "cna",
	}); err != nil {
		t.Fatalf("UpsertCVE(published): %v", err)
	}
	// cvelistV5 can reject a published id; the state must follow.
	if err := w.UpsertCVE(ctx, &model.CVE{
		ID: "CVE-2024-1001", State: "REJECTED", Summary: "Rejected reason: duplicate.", SummarySrc: "cna",
	}); err != nil {
		t.Fatalf("UpsertCVE(rejected): %v", err)
	}
	// An NVD record (which carries no state) must not reset it.
	if err := w.UpsertCVE(ctx, &model.CVE{
		ID: "CVE-2024-1001", NVDStatus: "Rejected", Summary: "nvd summary", SummarySrc: "nvd", Enriched: true,
	}); err != nil {
		t.Fatalf("UpsertCVE(nvd): %v", err)
	}

	ro, err := Open(path, true)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer ro.Close()
	c, err := ro.Get(ctx, "CVE-2024-1001")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if c.State != "REJECTED" {
		t.Fatalf("state = %q, want REJECTED", c.State)
	}
	if !c.Enriched || c.NVDStatus != "Rejected" {
		t.Fatalf("enrichment = %v/%q", c.Enriched, c.NVDStatus)
	}
}

// TestCWESearchLimitCap pins the shared page-size rule: a limit above 500 is
// capped at 500, not silently reset to the 25 default.
func TestCWESearchLimitCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cv3.db")
	d, err := Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	ctx := context.Background()
	entries := make([]*model.CWE, 0, 600)
	for i := 0; i < 600; i++ {
		entries = append(entries, &model.CWE{
			ID:          fmt.Sprintf("CWE-%d", 1000+i),
			Name:        "Shared Weakness",
			Abstraction: "Base",
			Status:      "Stable",
			Description: "every entry matches the same search terms",
		})
	}
	if err := d.PutCWEAll(ctx, entries); err != nil {
		t.Fatalf("PutCWEAll: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ro, err := Open(path, true)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer ro.Close()

	got, err := ro.CWESearch(ctx, "same search terms", 1000)
	if err != nil {
		t.Fatalf("CWESearch: %v", err)
	}
	if len(got) != 500 {
		t.Fatalf("CWESearch(limit=1000) returned %d rows, want the 500 cap", len(got))
	}
	def, err := ro.CWESearch(ctx, "same search terms", 0)
	if err != nil {
		t.Fatalf("CWESearch default: %v", err)
	}
	if len(def) != 25 {
		t.Fatalf("CWESearch(limit=0) returned %d rows, want the 25 default", len(def))
	}
}

// TestSearchHostileFilter proves a filter value that looks like SQL is bound as
// data: the query returns no rows instead of matching everything.
func TestSearchHostileFilter(t *testing.T) {
	path := buildDB(t, t.TempDir())
	d := openRO(t, path)
	res, err := d.Search(context.Background(), SearchQuery{
		Vendors: []string{"' OR 1=1 --"},
		Limit:   5,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if res.Total != 0 || len(res.Hits) != 0 {
		t.Fatalf("hostile filter matched: total=%d hits=%d", res.Total, len(res.Hits))
	}
}
