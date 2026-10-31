// Package model holds the source-independent record shapes shared by the
// ingest, storage and report layers.
package model

import "github.com/fr0g-66723067-io/cv3/internal/cpe"

// CVSS version keys used in CVE.Metrics and by the store column suffixes.
const (
	VerV2  = "v2"
	VerV30 = "v30"
	VerV31 = "v31"
	VerV40 = "v40"
)

// Metric is one CVSS base metric as published by a source.
type Metric struct {
	Score    float64
	Severity string // as published; empty when the source omitted it
	Vector   string
	Source   string // nvd-primary | nvd-secondary | cna | adp
}

// CWERef is a CWE identifier plus the source that stated it.
type CWERef struct {
	ID     string
	Source string // nvd | cna | adp
}

// CPEMatch is one CPE applicability entry with its optional version bounds.
type CPEMatch struct {
	Criteria   string
	Name       cpe.Name
	Vulnerable bool
	MatchID    string
	StartIncl  string
	StartExcl  string
	EndIncl    string
	EndExcl    string
	Source     string // nvd | adp
}

// Product is a CNA-reported affected vendor/product with no CPE binding.
type Product struct {
	Vendor      string
	Product     string
	PackageName string
	Versions    string // raw JSON of the upstream versions array
	Source      string // cna
}

// Reference is an advisory URL with its upstream tags.
type Reference struct {
	URL  string
	Tags string
	Name string
}

// KEV is the CISA Known Exploited Vulnerabilities annotation carried by the
// NVD feed.
type KEV struct {
	Added      string
	Due        string
	Name       string
	Ransomware string
}

// CVE is a merged record. Fields are filled by whichever source has them; see
// the package doc for precedence.
type CVE struct {
	ID         string
	Year       int
	State      string // PUBLISHED | REJECTED | RESERVED | UNKNOWN
	NVDStatus  string // empty when NVD never enriched the record
	Published  string
	Modified   string
	Reserved   string
	Assigner   string
	CNATitle   string
	Summary    string
	SummarySrc string // nvd | cna
	Metrics    map[string]Metric
	CWEs       []CWERef
	CPEs       []CPEMatch
	Products   []Product
	Refs       []Reference
	KEV        *KEV
	Enriched   bool

	// Best is the representative metric: the highest CVSS version present.
	Best        *Metric
	BestVersion string
}

// Rank orders metric sources by authority: NVD primary, NVD secondary, CNA,
// ADP. A metric never replaces a higher-ranked one, which is what makes
// re-applying a cvelistV5 record idempotent after NVD enrichment.
func (m Metric) Rank() int {
	switch m.Source {
	case "nvd-primary":
		return 4
	case "nvd-secondary":
		return 3
	case "cna":
		return 2
	case "adp":
		return 1
	}
	return 0
}

// Metric returns the metric for the given version key and whether it exists.
func (c *CVE) Metric(version string) (Metric, bool) {
	m, ok := c.Metrics[version]
	return m, ok
}

// CWE is one entry of the MITRE CWE catalog.
type CWE struct {
	ID          string
	Name        string
	Abstraction string
	Status      string
	Description string
	Parents     []string
}
