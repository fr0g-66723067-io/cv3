// Package storetest builds throwaway cv3 databases for tests in other packages.
// It is imported only by _test.go files.
package storetest

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/fr0g-66723067-io/cv3/internal/cpe"
	"github.com/fr0g-66723067-io/cv3/internal/model"
	"github.com/fr0g-66723067-io/cv3/internal/store"
)

// Names are the records Build writes, so assertions can refer to them.
const (
	EnrichedID  = "CVE-2024-3094"
	CNAOnlyID   = "CVE-2099-0001"
	RejectedID  = "CVE-2020-0001"
	XZProduct   = "xz"
	XZVendor    = "tukaani"
	CrossSiteID = "CWE-79"
)

// Build creates a database under t.TempDir(), writes a small corpus and returns
// its path. The returned database is closed; open it with store.Open.
func Build(t testing.TB) string {
	t.Helper()
	return BuildAt(t, filepath.Join(t.TempDir(), "cv3.db"))
}

// BuildAt writes the same corpus to an explicit path, for tests that care where
// the database lives.
func BuildAt(t testing.TB, path string) string {
	t.Helper()
	w, err := store.Create(path)
	if err != nil {
		t.Fatalf("storetest: create: %v", err)
	}
	ctx := context.Background()
	if err := w.UpsertCVEAll(ctx, fixtures(t)); err != nil {
		w.Close()
		t.Fatalf("storetest: upsert: %v", err)
	}
	if err := w.PutCWEAll(ctx, []*model.CWE{
		{
			ID: "CWE-506", Name: "Embedded Malicious Code", Abstraction: "Base", Status: "Incomplete",
			Description: "The product contains code that appears to be malicious in nature.",
		},
		{
			ID: CrossSiteID, Name: "Improper Neutralization of Input During Web Page Generation",
			Abstraction: "Base", Status: "Stable",
			Description: "The product does not neutralize user-controllable input.",
			Parents:     []string{"CWE-74"},
		},
	}); err != nil {
		w.Close()
		t.Fatalf("storetest: cwe: %v", err)
	}
	if err := w.BuildDerived(ctx); err != nil {
		w.Close()
		t.Fatalf("storetest: derived: %v", err)
	}
	if err := w.SetSourceState(ctx, "cvelistV5", "cve_2026-10-30_1900Z"); err != nil {
		w.Close()
		t.Fatalf("storetest: source state: %v", err)
	}
	if err := w.SetMeta(ctx, "built_at", "2026-10-30T19:00:00Z"); err != nil {
		w.Close()
		t.Fatalf("storetest: meta: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("storetest: close: %v", err)
	}
	return path
}

// Open opens the database read-only and closes it when the test ends.
func Open(t testing.TB, path string) *store.DB {
	t.Helper()
	d, err := store.Open(path, true)
	if err != nil {
		t.Fatalf("storetest: open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func fixtures(t testing.TB) []*model.CVE {
	t.Helper()
	rangeName := parse(t, "cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*")
	enriched := &model.CVE{
		ID:         EnrichedID,
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
			Criteria:   rangeName.Criteria(),
			Name:       rangeName,
			Vulnerable: true,
			MatchID:    "MATCH-1",
			StartIncl:  "5.6.0",
			EndExcl:    "5.6.2",
			Source:     "nvd",
		}},
		Refs:     []model.Reference{{URL: "https://example.test/xz-backdoor", Tags: "vendor-advisory"}},
		KEV:      &model.KEV{Added: "2024-04-02T00:00:00Z", Due: "2024-04-23T00:00:00Z", Name: "XZ Utils Backdoor"},
		Enriched: true,
	}
	cnaOnly := &model.CVE{
		ID:         CNAOnlyID,
		State:      "PUBLISHED",
		Published:  "2099-01-02T00:00:00Z",
		Assigner:   "example",
		Summary:    "OpenSSL accepts a malformed certificate chain in this release.",
		SummarySrc: "cna",
		Metrics: map[string]model.Metric{
			model.VerV31: {Score: 5.3, Severity: "medium", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", Source: "cna"},
		},
		CWEs:     []model.CWERef{{ID: CrossSiteID, Source: "cna"}},
		Products: []model.Product{{Vendor: "OpenSSL", Product: "OpenSSL", Versions: `[{"version":"3.0.0","status":"affected"}]`, Source: "cna"}},
		Refs:     []model.Reference{{URL: "https://example.test/openssl-advisory"}},
	}
	rejected := &model.CVE{
		ID:        RejectedID,
		State:     "REJECTED",
		Published: "2020-01-01T00:00:00Z",
		Summary:   "Rejected reason: duplicate.",
	}
	return []*model.CVE{enriched, cnaOnly, rejected}
}

func parse(t testing.TB, s string) cpe.Name {
	t.Helper()
	n, err := cpe.Parse(s)
	if err != nil {
		t.Fatalf("storetest: cpe.Parse(%q): %v", s, err)
	}
	return n
}
