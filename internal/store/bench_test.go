package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/fr0g-66723067-io/cv3/internal/cpe"
	"github.com/fr0g-66723067-io/cv3/internal/model"
)

// sink keeps benchmark results observable to the optimiser.
var sink any

const benchCVEs = 50000

var benchWords = []string{
	"openssl", "kernel", "overflow", "deserialization", "scripting", "injection",
	"use-after-free", "server", "client", "library", "parsing", "authentication",
}

// buildBenchDB writes a corpus shaped like the real one: one summary, a handful
// of CPE rows, and a CVSS metric per record.
func buildBenchDB(b *testing.B) *DB {
	b.Helper()
	path := filepath.Join(b.TempDir(), "cv3.db")
	w, err := Create(path)
	if err != nil {
		b.Fatalf("Create: %v", err)
	}
	ctx := context.Background()
	const batchSize = 512
	for start := 0; start < benchCVEs; start += batchSize {
		batch := make([]*model.CVE, 0, batchSize)
		end := min(start+batchSize, benchCVEs)
		for i := start; i < end; i++ {
			summary := fmt.Sprintf("%s vulnerability in %s allows %s of %s data",
				benchWords[i%len(benchWords)], benchWords[(i+3)%len(benchWords)],
				benchWords[(i+7)%len(benchWords)], benchWords[(i+5)%len(benchWords)])
			c := &model.CVE{
				ID:         fmt.Sprintf("CVE-2024-%05d", i),
				State:      "PUBLISHED",
				NVDStatus:  "Analyzed",
				Published:  "2024-01-01T00:00:00Z",
				Summary:    summary,
				SummarySrc: "nvd",
				Metrics: map[string]model.Metric{
					model.VerV31: {Score: float64(i%100) / 10, Severity: "medium", Source: "nvd-primary"},
				},
				CWEs:     []model.CWERef{{ID: fmt.Sprintf("CWE-%d", 79+i%20), Source: "nvd"}},
				Refs:     []model.Reference{{URL: fmt.Sprintf("https://example.test/%d", i), Tags: "vendor-advisory"}},
				Enriched: i%2 == 0,
			}
			for j := range 8 {
				name := cpe.Name{
					Part: "a", Vendor: benchWords[(i+j)%len(benchWords)],
					Product: benchWords[(i+j*3)%len(benchWords)], Version: "5.6.1",
					Update: cpe.Any, Edition: cpe.Any, Language: cpe.Any,
					SwEdition: cpe.Any, TargetSw: cpe.Any, TargetHw: cpe.Any, Other: cpe.Any,
				}
				c.CPEs = append(c.CPEs, model.CPEMatch{
					Criteria: name.Criteria(), Name: name, Vulnerable: true, Source: "nvd",
				})
			}
			batch = append(batch, c)
		}
		if err := w.UpsertCVEAll(ctx, batch); err != nil {
			w.Close()
			b.Fatalf("UpsertCVEAll: %v", err)
		}
	}
	if err := w.BuildDerived(ctx); err != nil {
		w.Close()
		b.Fatalf("BuildDerived: %v", err)
	}
	if err := w.Close(); err != nil {
		b.Fatalf("Close: %v", err)
	}
	ro, err := Open(path, true)
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	b.Cleanup(func() { ro.Close() })
	return ro
}

func BenchmarkSearch(b *testing.B) {
	d := buildBenchDB(b)
	ctx := context.Background()
	queries := []SearchQuery{
		{Query: "openssl overflow"},
		{Query: "use-after-free", Severities: []string{"high", "critical"}},
		{Severities: []string{"critical"}, YearsFrom: 2024, YearsTo: 2024},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		res, err := d.Search(ctx, queries[i%len(queries)])
		if err != nil {
			b.Fatalf("Search: %v", err)
		}
		sink = res.Total
	}
}

func BenchmarkGet(b *testing.B) {
	d := buildBenchDB(b)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		c, err := d.Get(ctx, fmt.Sprintf("CVE-2024-%05d", i%benchCVEs))
		if err != nil {
			b.Fatalf("Get: %v", err)
		}
		sink = len(c.CPEs)
	}
}

func BenchmarkByCPE(b *testing.B) {
	d := buildBenchDB(b)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		hits, err := d.ByCPE(ctx, CPEFilter{Vendor: benchWords[i%len(benchWords)], Version: "5.6.1", Limit: 100})
		if err != nil {
			b.Fatalf("ByCPE: %v", err)
		}
		sink = len(hits)
	}
}
