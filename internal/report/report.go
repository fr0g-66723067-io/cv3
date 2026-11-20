// Package report holds the JSON envelopes shared by the CLI's -json output and
// the HTTP API, so the two surfaces can never drift apart.
package report

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/fr0g-66723067-io/cv3/internal/cpe"
	"github.com/fr0g-66723067-io/cv3/internal/model"
	"github.com/fr0g-66723067-io/cv3/internal/store"
)

// SchemaVersion is carried by every envelope; consumers pin it.
const SchemaVersion = "1"

// WriteJSON writes v as indented JSON with HTML escaping disabled.
func WriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// CVSSDoc is one CVSS metric.
type CVSSDoc struct {
	Score    float64 `json:"score"`
	Severity string  `json:"severity,omitempty"`
	Vector   string  `json:"vector,omitempty"`
	Source   string  `json:"source,omitempty"`
}

// BestDoc is the representative metric.
type BestDoc struct {
	Version  string  `json:"version"`
	Score    float64 `json:"score"`
	Severity string  `json:"severity,omitempty"`
}

// CWERefDoc is one CWE classification with the sources that stated it.
type CWERefDoc struct {
	ID      string   `json:"id"`
	Name    string   `json:"name,omitempty"`
	Sources []string `json:"sources,omitempty"`
}

// CPEDoc is one CPE applicability row.
type CPEDoc struct {
	Criteria       string `json:"criteria"`
	Part           string `json:"part"`
	Vendor         string `json:"vendor"`
	Product        string `json:"product"`
	Version        string `json:"version"`
	Vulnerable     bool   `json:"vulnerable"`
	Source         string `json:"source"`
	MatchID        string `json:"matchId,omitempty"`
	StartIncluding string `json:"startIncluding,omitempty"`
	StartExcluding string `json:"startExcluding,omitempty"`
	EndIncluding   string `json:"endIncluding,omitempty"`
	EndExcluding   string `json:"endExcluding,omitempty"`
	Range          string `json:"range,omitempty"`
}

// ProductDoc is a CNA-reported product without a CPE binding.
type ProductDoc struct {
	Vendor      string `json:"vendor"`
	Product     string `json:"product"`
	PackageName string `json:"packageName,omitempty"`
	Versions    string `json:"versions,omitempty"`
	Source      string `json:"source"`
}

// RefDoc is one advisory reference.
type RefDoc struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags,omitempty"`
	Name string   `json:"name,omitempty"`
}

// KEVDoc is the CISA KEV annotation.
type KEVDoc struct {
	Added      string `json:"added,omitempty"`
	Due        string `json:"due,omitempty"`
	Name       string `json:"name,omitempty"`
	Ransomware string `json:"ransomware,omitempty"`
}

// SourceDoc says which upstream sources contributed to a record.
type SourceDoc struct {
	CVEListV5 bool `json:"cvelistV5"`
	NVD       bool `json:"nvd"`
}

// CVEDoc is a full record.
type CVEDoc struct {
	ID            string       `json:"id"`
	Year          int          `json:"year"`
	State         string       `json:"state"`
	NVDStatus     string       `json:"nvdStatus,omitempty"`
	Published     string       `json:"published,omitempty"`
	Modified      string       `json:"modified,omitempty"`
	Reserved      string       `json:"reserved,omitempty"`
	Assigner      string       `json:"assigner,omitempty"`
	Title         string       `json:"title,omitempty"`
	Summary       string       `json:"summary,omitempty"`
	SummarySource string       `json:"summarySource,omitempty"`
	Best          *BestDoc     `json:"best"`
	CVSS          []CVSSDoc    `json:"cvss,omitempty"`
	CWE           []CWERefDoc  `json:"cwe,omitempty"`
	CPE           []CPEDoc     `json:"cpe,omitempty"`
	Products      []ProductDoc `json:"products,omitempty"`
	References    []RefDoc     `json:"references,omitempty"`
	KEV           *KEVDoc      `json:"kev"`
	Enriched      bool         `json:"enriched"`
	Sources       SourceDoc    `json:"sources"`
}

// GetEnvelope wraps one record.
type GetEnvelope struct {
	SchemaVersion string `json:"schemaVersion"`
	CVE           CVEDoc `json:"cve"`
}

// FromModel converts a stored record. names maps CWE ids to catalog names.
func FromModel(c *model.CVE, names map[string]string) CVEDoc {
	doc := CVEDoc{
		ID:            c.ID,
		Year:          c.Year,
		State:         c.State,
		NVDStatus:     c.NVDStatus,
		Published:     c.Published,
		Modified:      c.Modified,
		Reserved:      c.Reserved,
		Assigner:      c.Assigner,
		Title:         c.CNATitle,
		Summary:       c.Summary,
		SummarySource: c.SummarySrc,
		Enriched:      c.Enriched,
		Sources:       SourceDoc{CVEListV5: c.State != "UNKNOWN", NVD: c.Enriched},
	}
	if c.Best != nil {
		doc.Best = &BestDoc{Version: c.BestVersion, Score: c.Best.Score, Severity: c.Best.Severity}
	}
	for _, ver := range []string{model.VerV40, model.VerV31, model.VerV30, model.VerV2} {
		if m, ok := c.Metrics[ver]; ok {
			doc.CVSS = append(doc.CVSS, CVSSDoc{Score: m.Score, Severity: m.Severity, Vector: m.Vector, Source: m.Source})
		}
	}
	byID := map[string]*CWERefDoc{}
	var order []string
	for _, w := range c.CWEs {
		ref, ok := byID[w.ID]
		if !ok {
			ref = &CWERefDoc{ID: w.ID, Name: names[w.ID]}
			byID[w.ID] = ref
			order = append(order, w.ID)
		}
		dup := false
		for _, s := range ref.Sources {
			if s == w.Source {
				dup = true
			}
		}
		if !dup {
			ref.Sources = append(ref.Sources, w.Source)
		}
	}
	sort.Strings(order)
	for _, id := range order {
		doc.CWE = append(doc.CWE, *byID[id])
	}
	for _, m := range c.CPEs {
		var r cpe.Range
		switch {
		case m.StartIncl != "":
			r.Start = m.StartIncl
		case m.StartExcl != "":
			r.Start, r.StartExclusive = m.StartExcl, true
		}
		switch {
		case m.EndIncl != "":
			r.End = m.EndIncl
		case m.EndExcl != "":
			r.End, r.EndExclusive = m.EndExcl, true
		}
		if r.Start == "" && r.End == "" && !cpe.IsAny(m.Name.Version) && !cpe.IsNA(m.Name.Version) {
			r.Exact = m.Name.Version
		}
		doc.CPE = append(doc.CPE, CPEDoc{
			Criteria:       m.Criteria,
			Part:           m.Name.Part,
			Vendor:         m.Name.Vendor,
			Product:        m.Name.Product,
			Version:        m.Name.Version,
			Vulnerable:     m.Vulnerable,
			Source:         m.Source,
			MatchID:        m.MatchID,
			StartIncluding: m.StartIncl,
			StartExcluding: m.StartExcl,
			EndIncluding:   m.EndIncl,
			EndExcluding:   m.EndExcl,
			Range:          r.String(),
		})
	}
	for _, p := range c.Products {
		doc.Products = append(doc.Products, ProductDoc{
			Vendor: p.Vendor, Product: p.Product, PackageName: p.PackageName,
			Versions: p.Versions, Source: p.Source,
		})
	}
	for _, r := range c.Refs {
		tags := splitTags(r.Tags)
		doc.References = append(doc.References, RefDoc{URL: r.URL, Tags: tags, Name: r.Name})
	}
	if c.KEV != nil {
		doc.KEV = &KEVDoc{Added: c.KEV.Added, Due: c.KEV.Due, Name: c.KEV.Name, Ransomware: c.KEV.Ransomware}
	}
	return doc
}

func splitTags(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

// SearchQueryDoc echoes the query an envelope answers.
type SearchQueryDoc struct {
	Terms    string   `json:"terms,omitempty"`
	Or       bool     `json:"or,omitempty"`
	Severity []string `json:"severity,omitempty"`
	State    []string `json:"state,omitempty"`
	Status   []string `json:"status,omitempty"`
	CWE      []string `json:"cwe,omitempty"`
	Vendor   []string `json:"vendor,omitempty"`
	Product  []string `json:"product,omitempty"`
	YearFrom int      `json:"yearFrom,omitempty"`
	YearTo   int      `json:"yearTo,omitempty"`
	MinScore *float64 `json:"minScore,omitempty"`
	MaxScore *float64 `json:"maxScore,omitempty"`
	CVSS     string   `json:"cvss,omitempty"`
	KEV      bool     `json:"kev,omitempty"`
	NoNVD    bool     `json:"noNvd,omitempty"`
	After    string   `json:"after,omitempty"`
	Before   string   `json:"before,omitempty"`
	Sort     string   `json:"sort,omitempty"`
}

// SearchItem is one search hit.
type SearchItem struct {
	ID        string   `json:"id"`
	Score     *float64 `json:"score"`
	Severity  string   `json:"severity,omitempty"`
	CVSS      string   `json:"cvssVersion,omitempty"`
	Published string   `json:"published,omitempty"`
	State     string   `json:"state,omitempty"`
	Enriched  bool     `json:"enriched"`
	CWE       []string `json:"cwe,omitempty"`
	Snippet   string   `json:"snippet,omitempty"`
	Summary   string   `json:"summary,omitempty"`
}

// SearchEnvelope is the search response.
type SearchEnvelope struct {
	SchemaVersion string         `json:"schemaVersion"`
	Query         SearchQueryDoc `json:"query"`
	Total         int            `json:"total"`
	Limit         int            `json:"limit"`
	Offset        int            `json:"offset"`
	Results       []SearchItem   `json:"results"`
}

// SearchFromStore builds the envelope from a store result.
func SearchFromStore(q SearchQueryDoc, res store.SearchResult, limit, offset int) SearchEnvelope {
	env := SearchEnvelope{
		SchemaVersion: SchemaVersion,
		Query:         q,
		Total:         res.Total,
		Limit:         limit,
		Offset:        offset,
		Results:       make([]SearchItem, 0, len(res.Hits)),
	}
	for _, h := range res.Hits {
		env.Results = append(env.Results, SearchItem{
			ID:        h.ID,
			Score:     h.Score,
			Severity:  h.Severity,
			CVSS:      h.CVSSVer,
			Published: h.Published,
			State:     h.State,
			Enriched:  h.Enriched,
			CWE:       h.CWEs,
			Snippet:   h.Snippet,
			Summary:   h.Summary,
		})
	}
	return env
}

// CPEFilterDoc echoes a CPE query.
type CPEFilterDoc struct {
	Vendor  string `json:"vendor,omitempty"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
	Part    string `json:"part,omitempty"`
	CPE     string `json:"cpe,omitempty"`
}

// CPEItem is one applicability hit.
type CPEItem struct {
	CVE       string   `json:"cve"`
	Score     *float64 `json:"score"`
	Severity  string   `json:"severity,omitempty"`
	Published string   `json:"published,omitempty"`
	State     string   `json:"state,omitempty"`
	Match     string   `json:"match"`
	Range     string   `json:"range,omitempty"`
	Criteria  string   `json:"criteria,omitempty"`
	Vendor    string   `json:"vendor,omitempty"`
	Product   string   `json:"product,omitempty"`
	Version   string   `json:"version,omitempty"`
	Source    string   `json:"source,omitempty"`
}

// CPEEnvelope is the CPE response.
type CPEEnvelope struct {
	SchemaVersion string       `json:"schemaVersion"`
	Query         CPEFilterDoc `json:"query"`
	Total         int          `json:"total"`
	Results       []CPEItem    `json:"results"`
}

// CPEFromStore builds the envelope from store hits.
func CPEFromStore(q CPEFilterDoc, hits []store.CPEHit) CPEEnvelope {
	env := CPEEnvelope{SchemaVersion: SchemaVersion, Query: q, Total: len(hits), Results: make([]CPEItem, 0, len(hits))}
	for _, h := range hits {
		env.Results = append(env.Results, CPEItem{
			CVE: h.CVE, Score: h.Score, Severity: h.Severity, Published: h.Published,
			State: h.State, Match: h.MatchKind, Range: h.Range, Criteria: h.Criteria,
			Vendor: h.Vendor, Product: h.Product, Version: h.Version, Source: h.Src,
		})
	}
	return env
}

// CWEDoc is one catalog entry.
type CWEDoc struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Abstraction string   `json:"abstraction,omitempty"`
	Status      string   `json:"status,omitempty"`
	Description string   `json:"description,omitempty"`
	Parents     []string `json:"parents,omitempty"`
	CVECount    int      `json:"cveCount"`
}

// CWEEnvelope wraps one entry.
type CWEEnvelope struct {
	SchemaVersion string `json:"schemaVersion"`
	CWE           CWEDoc `json:"cwe"`
}

// CWEListEnvelope wraps a search result.
type CWEListEnvelope struct {
	SchemaVersion string   `json:"schemaVersion"`
	Total         int      `json:"total"`
	Results       []CWEDoc `json:"results"`
}

// CWEFromStore converts a catalog entry.
func CWEFromStore(info *store.CWEInfo) CWEDoc {
	return CWEDoc{
		ID:          info.ID,
		Name:        info.Name,
		Abstraction: info.Abstraction,
		Status:      info.Status,
		Description: info.Description,
		Parents:     info.Parents,
		CVECount:    info.CVECount,
	}
}

// StatsEnvelope is the corpus summary.
type StatsEnvelope struct {
	SchemaVersion string   `json:"schemaVersion"`
	Stats         StatsDoc `json:"stats"`
}

// StatsDoc mirrors store.Stats with stable JSON names.
type StatsDoc struct {
	CVEs        int               `json:"cves"`
	Enriched    int               `json:"enriched"`
	Unenriched  int               `json:"unenriched"`
	Rejected    int               `json:"rejected"`
	Reserved    int               `json:"reserved"`
	KEV         int               `json:"kev"`
	CPEMatches  int               `json:"cpeMatches"`
	CVEProducts int               `json:"cveProducts"`
	CWECatalog  int               `json:"cweCatalog"`
	Refs        int               `json:"refs"`
	FTSRows     int               `json:"ftsRows"`
	DBSize      int64             `json:"dbSize"`
	DBPath      string            `json:"dbPath"`
	BuiltAt     string            `json:"builtAt,omitempty"`
	Severities  []string          `json:"severities,omitempty"`
	SourceState map[string]string `json:"sourceState"`
	ByYear      map[string]int    `json:"byYear"`
	BySeverity  map[string]int    `json:"bySeverity"`
}

// StatsFromStore converts a store summary.
func StatsFromStore(s *store.Stats) StatsDoc {
	doc := StatsDoc{
		CVEs:        s.CVEs,
		Enriched:    s.Enriched,
		Unenriched:  s.Unenriched,
		Rejected:    s.Rejected,
		Reserved:    s.Reserved,
		KEV:         s.KEV,
		CPEMatches:  s.CPEMatches,
		CVEProducts: s.CVEProducts,
		CWECatalog:  s.CWECatalog,
		Refs:        s.Refs,
		FTSRows:     s.FTSRows,
		DBSize:      s.DBSize,
		DBPath:      s.DBPath,
		BuiltAt:     s.BuiltAt,
		Severities:  s.Severities,
		SourceState: s.SourceState,
		ByYear:      map[string]int{},
		BySeverity:  s.BySeverity,
	}
	for y, n := range s.ByYear {
		doc.ByYear[itoa(y)] = n
	}
	return doc
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// IngestEnvelope reports a sync or update run.
type IngestEnvelope struct {
	SchemaVersion string    `json:"schemaVersion"`
	Summary       IngestDoc `json:"summary"`
}

// IngestDoc is the summary payload.
type IngestDoc struct {
	CVEs        int               `json:"cves"`
	Enriched    int               `json:"enriched"`
	CPEs        int               `json:"cpes"`
	Products    int               `json:"products"`
	CWEs        int               `json:"cwes"`
	Refs        int               `json:"refs"`
	ParseErrors int               `json:"parseErrors"`
	Warnings    []string          `json:"warnings,omitempty"`
	NewCVEs     int               `json:"newCves"`
	UpdatedCVEs int               `json:"updatedCves"`
	DeltaTags   []string          `json:"deltaTags,omitempty"`
	DurationMS  int64             `json:"durationMs"`
	DBSize      int64             `json:"dbSize"`
	DBPath      string            `json:"dbPath"`
	Sources     map[string]string `json:"sources,omitempty"`
}
