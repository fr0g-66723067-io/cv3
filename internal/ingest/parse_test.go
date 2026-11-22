package ingest

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/cv3/internal/model"
)

func readFixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	path := filepath.Join(append([]string{"..", "..", "testdata"}, parts...)...)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return raw
}

func TestParseCVEListV5EnrichedRecord(t *testing.T) {
	c, err := ParseCVEListV5(readFixture(t, "cvelist", "CVE-2024-3094.json"))
	if err != nil {
		t.Fatalf("ParseCVEListV5: %v", err)
	}
	if c.ID != "CVE-2024-3094" || c.Year != 2024 {
		t.Fatalf("id/year = %s/%d", c.ID, c.Year)
	}
	if c.State != "PUBLISHED" || c.Assigner != "redhat" {
		t.Fatalf("state/assigner = %q/%q", c.State, c.Assigner)
	}
	if c.SummarySrc != "cna" || c.Summary == "" {
		t.Fatalf("summary src = %q, empty=%v", c.SummarySrc, c.Summary == "")
	}
	if c.Enriched {
		t.Fatal("cvelistV5 record reported as NVD-enriched")
	}
	m, ok := c.Metrics[model.VerV31]
	if !ok || m.Score != 10.0 || m.Severity != "critical" || m.Source != "cna" {
		t.Fatalf("v31 metric = %+v (present=%v)", m, ok)
	}
	if len(c.CWEs) != 1 || c.CWEs[0].ID != "CWE-506" || c.CWEs[0].Source != "cna" {
		t.Fatalf("cwes = %+v", c.CWEs)
	}
	// CNA affected entries carry cpe:/ URI bindings mixed with plain products.
	var uriCPEs int
	for _, m := range c.CPEs {
		if m.Source != "cna" || m.Name.Vendor == "" || m.Name.Product == "" {
			t.Fatalf("bad cpe row %+v", m)
		}
		if m.Name.Part == "o" {
			uriCPEs++
		}
	}
	if uriCPEs == 0 {
		t.Fatal("no operating-system CPE parsed from cpe:/ URI bindings")
	}
	if len(c.Products) == 0 {
		t.Fatal("no CNA products recorded")
	}
}

func TestParseCVEListV5ADPCPEBindings(t *testing.T) {
	c, err := ParseCVEListV5(readFixture(t, "cvelist", "adp-cpe.json"))
	if err != nil {
		t.Fatalf("ParseCVEListV5: %v", err)
	}
	var redhat, osPart int
	for _, m := range c.CPEs {
		if m.Name.Vendor == "redhat" {
			redhat++
			if m.Name.Part == "o" {
				osPart++
			}
		}
		if m.Criteria == "" || m.Name.Criteria() != m.Criteria {
			t.Fatalf("criteria not normalised: %q vs %q", m.Criteria, m.Name.Criteria())
		}
	}
	if redhat == 0 || osPart == 0 {
		t.Fatalf("redhat cpes=%d os part=%d, want both", redhat, osPart)
	}

	// A 2.3 formatted-string CPE in an ADP affected entry normalises to the
	// same shape as a URI binding.
	adp23 := []byte(`{"cveMetadata":{"cveId":"CVE-2024-9999","state":"PUBLISHED"},
		"containers":{"cna":{"descriptions":[{"lang":"en","value":"synthetic"}]},
		"adp":[{"title":"CISA ADP Vulnrichment","affected":[{"vendor":"linux","product":"linux_kernel",
		"cpes":["cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"],
		"defaultStatus":"affected","versions":[{"version":"0","status":"affected"}]}]}]}}`)
	c23, err := ParseCVEListV5(adp23)
	if err != nil {
		t.Fatalf("ParseCVEListV5(synthetic): %v", err)
	}
	if len(c23.CPEs) != 1 || c23.CPEs[0].Name.Vendor != "linux" || c23.CPEs[0].Name.Part != "o" ||
		c23.CPEs[0].Name.Version != "-" || !c23.CPEs[0].Vulnerable || c23.CPEs[0].Source != "adp" {
		t.Fatalf("2.3 ADP cpe = %+v", c23.CPEs)
	}
}

func TestParseNVDFeed(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "testdata", "nvd", "feed-fragment.json.gz"))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	var got []*model.CVE
	count, ts, err := ParseNVDFeed(f, func(raw []byte) error {
		c, err := ParseNVDRecord(raw)
		if err != nil {
			return err
		}
		got = append(got, c)
		return nil
	})
	if err != nil {
		t.Fatalf("ParseNVDFeed: %v", err)
	}
	if count != 2 || len(got) != 2 {
		t.Fatalf("count = %d, records = %d", count, len(got))
	}
	if ts == "" {
		t.Fatal("feed timestamp not captured")
	}
	backdoor := got[0]
	if backdoor.ID != "CVE-2024-3094" || !backdoor.Enriched || backdoor.NVDStatus == "" {
		t.Fatalf("record = %+v", backdoor)
	}
	m, ok := backdoor.Metrics[model.VerV31]
	if !ok || m.Score != 10.0 || m.Source != "nvd-primary" {
		t.Fatalf("v31 = %+v (present=%v)", m, ok)
	}
	// This record carries only a v3.1 metric; the SSVC object must not be
	// mistaken for one.
	if _, ok := backdoor.Metrics[model.VerV2]; ok {
		t.Fatalf("unexpected v2 metric: %+v", backdoor.Metrics)
	}
	if _, ok := backdoor.Metrics[model.VerV40]; ok {
		t.Fatalf("unexpected v4 metric: %+v", backdoor.Metrics)
	}
	var found bool
	for _, cwe := range backdoor.CWEs {
		if cwe.ID == "CWE-506" && cwe.Source == "nvd" {
			found = true
		}
	}
	if !found {
		t.Fatalf("CWE-506 missing from %+v", backdoor.CWEs)
	}
	if len(backdoor.CPEs) == 0 {
		t.Fatal("no CPE rows")
	}
	for _, m := range backdoor.CPEs {
		if m.Source != "nvd" || !m.Vulnerable {
			t.Fatalf("cpe row = %+v", m)
		}
		if m.Name.Vendor != "tukaani" || m.Name.Product != "xz" {
			t.Fatalf("cpe vendor/product = %s/%s", m.Name.Vendor, m.Name.Product)
		}
	}
	if backdoor.KEV != nil {
		t.Fatalf("unexpected KEV annotation: %+v", backdoor.KEV)
	}
	if got[1].NVDStatus != "Awaiting Analysis" {
		t.Fatalf("second record status = %q", got[1].NVDStatus)
	}
}

func TestParseCWECatalog(t *testing.T) {
	entries, version, err := ParseCWEFile(filepath.Join("..", "..", "testdata", "cwe", "cwec-fragment.xml"))
	if err != nil {
		t.Fatalf("ParseCWEFile: %v", err)
	}
	if version != "5.0" {
		t.Fatalf("version = %q", version)
	}
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(entries))
	}
	byID := map[string]model.CWE{}
	for _, e := range entries {
		byID[e.ID] = e
	}
	xss, ok := byID["CWE-79"]
	if !ok {
		t.Fatalf("CWE-79 missing: %+v", entries)
	}
	if xss.Name != "Improper Neutralization of Input During Web Page Generation" {
		t.Fatalf("CWE-79 name = %q", xss.Name)
	}
	var has74, dup bool
	seen := map[string]bool{}
	for _, p := range xss.Parents {
		if seen[p] {
			dup = true
		}
		seen[p] = true
		if p == "CWE-74" {
			has74 = true
		}
	}
	if !has74 || dup {
		t.Fatalf("CWE-79 parents = %v", xss.Parents)
	}
	if xss.Description == "" || containsAngle(xss.Description) {
		t.Fatalf("description not cleaned: %q", xss.Description)
	}
	if _, ok := byID["CWE-506"]; !ok {
		t.Fatal("CWE-506 missing")
	}
}

func containsAngle(s string) bool {
	for _, r := range s {
		if r == '<' || r == '>' {
			return true
		}
	}
	return false
}

func TestWalkCVEZip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cves.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	zw := zip.NewWriter(f)
	members := map[string]string{
		"cves/2024/3xxx/CVE-2024-3094.json":     `{"cveMetadata":{"cveId":"CVE-2024-3094"}}`,
		"deltaCves/CVE-2024-0001.json":          `{"cveMetadata":{"cveId":"CVE-2024-0001"}}`,
		"release_notes.md":                      "notes",
		"cves/2024/3xxx/not-a-cve.txt":          "x",
		"cves/2024/3xxx/CVE-2024-3094.sig.json": "signature",
	}
	for name, body := range members {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create: %v", err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	var ids []string
	parsed, skipped, err := WalkCVEZip(context.Background(), path, func(id string, raw []byte) error {
		ids = append(ids, id)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkCVEZip: %v", err)
	}
	if parsed != 2 || skipped != 3 {
		t.Fatalf("parsed=%d skipped=%d, want 2/3", parsed, skipped)
	}
	sort.Strings(ids)
	if len(ids) != 2 || ids[0] != "CVE-2024-0001" || ids[1] != "CVE-2024-3094" {
		t.Fatalf("ids = %v", ids)
	}
}

func TestWalkCVEZipEmptyArchiveFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.zip")
	body := zipBytes(t, map[string][]byte{
		"readme.md":            []byte("no cves here"),
		"cves/2024/3xxx/x.txt": []byte("still not a cve"),
	})
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := WalkCVEZip(context.Background(), path, func(id string, raw []byte) error { return nil }); err == nil {
		t.Fatal("WalkCVEZip accepted an archive with no CVE records")
	}
}

func TestTagTime(t *testing.T) {
	got, err := tagTime("cve_2026-10-30_1900Z")
	if err != nil {
		t.Fatalf("tagTime: %v", err)
	}
	if got.Year() != 2026 || got.Month() != 10 || got.Day() != 30 || got.Hour() != 19 || got.Minute() != 0 {
		t.Fatalf("tagTime = %v", got)
	}
	if _, err := tagTime("not-a-tag"); err == nil {
		t.Fatal("tagTime accepted an invalid tag")
	}
}

func TestWalkCVEZipNested(t *testing.T) {
	inner := zipBytes(t, map[string][]byte{
		"cves/2024/3xxx/CVE-2024-3094.json": []byte(`{"cveMetadata":{"cveId":"CVE-2024-3094"}}`),
		"cves/2024/3xxx/CVE-2024-3095.json": []byte(`{"cveMetadata":{"cveId":"CVE-2024-3095"}}`),
	})
	outer := zipBytes(t, map[string][]byte{"cves.zip": inner})
	path := filepath.Join(t.TempDir(), "all.zip")
	if err := os.WriteFile(path, outer, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	var ids []string
	parsed, _, err := WalkCVEZip(context.Background(), path, func(id string, raw []byte) error {
		ids = append(ids, id)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkCVEZip(nested): %v", err)
	}
	if parsed != 2 || len(ids) != 2 {
		t.Fatalf("parsed=%d ids=%v", parsed, ids)
	}
	if _, err := os.Stat(path + ".inner"); !os.IsNotExist(err) {
		t.Fatalf("temporary inner archive left behind: %v", err)
	}
}

func TestWalkCVEZipNestedLimit(t *testing.T) {
	old := maxNestedArchiveBytes
	maxNestedArchiveBytes = 1024
	defer func() { maxNestedArchiveBytes = old }()

	pad := make([]byte, 4096)
	if _, err := rand.Read(pad); err != nil {
		t.Fatalf("rand: %v", err)
	}
	inner := zipBytes(t, map[string][]byte{"pad.bin": pad})
	outer := zipBytes(t, map[string][]byte{"cves.zip": inner})
	path := filepath.Join(t.TempDir(), "all.zip")
	if err := os.WriteFile(path, outer, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, _, err := WalkCVEZip(context.Background(), path, func(id string, raw []byte) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "nested archive") || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("WalkCVEZip error = %v, want the nested-archive limit", err)
	}
	if _, statErr := os.Stat(path + ".inner"); !os.IsNotExist(statErr) {
		t.Fatalf("oversized inner archive left behind: %v", statErr)
	}
}

func TestWalkCVEZipHonoursContext(t *testing.T) {
	inner := zipBytes(t, map[string][]byte{
		"cves/2024/3xxx/CVE-2024-3094.json": []byte(`{"cveMetadata":{"cveId":"CVE-2024-3094"}}`),
	})
	outer := zipBytes(t, map[string][]byte{"cves.zip": inner})
	path := filepath.Join(t.TempDir(), "all.zip")
	if err := os.WriteFile(path, outer, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := WalkCVEZip(ctx, path, func(id string, raw []byte) error { return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("WalkCVEZip error = %v, want context.Canceled", err)
	}
}
