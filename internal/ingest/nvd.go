package ingest

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/fr0g-66723067-io/cv3/internal/cpe"
	"github.com/fr0g-66723067-io/cv3/internal/model"
)

// NVD CVE 2.0 feed shapes. The feed is a JSON object whose "vulnerabilities"
// array holds one {"cve": {...}} element per record.

type nvdEnvelope struct {
	CVEDataFormat   string             `json:"CVE_data_format"`
	Timestamp       string             `json:"timestamp"`
	TotalResults    int                `json:"totalResults"`
	Vulnerabilities []nvdVulnerability `json:"vulnerabilities"`
}

type nvdVulnerability struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID                string         `json:"id"`
	SourceIdentifier  string         `json:"sourceIdentifier"`
	Published         string         `json:"published"`
	LastModified      string         `json:"lastModified"`
	VulnStatus        string         `json:"vulnStatus"`
	Descriptions      []nvdText      `json:"descriptions"`
	Metrics           nvdMetrics     `json:"metrics"`
	Weaknesses        []nvdWeakness  `json:"weaknesses"`
	Configurations    []nvdConfig    `json:"configurations"`
	References        []nvdReference `json:"references"`
	ExploitAdd        string         `json:"cisaExploitAdd"`
	ActionDue         string         `json:"cisaActionDue"`
	RequiredAction    string         `json:"cisaRequiredAction"`
	VulnerabilityName string         `json:"cisaVulnerabilityName"`
}

type nvdText struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	V2   []nvdMetric     `json:"cvssMetricV2"`
	V30  []nvdMetric     `json:"cvssMetricV30"`
	V31  []nvdMetric     `json:"cvssMetricV31"`
	V40  []nvdMetric     `json:"cvssMetricV40"`
	SSVC json.RawMessage `json:"ssvcV203"`
}

type nvdMetric struct {
	Source   string      `json:"source"`
	Type     string      `json:"type"`
	CvssData nvdCvssData `json:"cvssData"`
}

type nvdCvssData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type nvdWeakness struct {
	Source      string    `json:"source"`
	Type        string    `json:"type"`
	Description []nvdText `json:"description"`
}

type nvdConfig struct {
	Nodes []nvdNode `json:"nodes"`
}

type nvdNode struct {
	Operator string        `json:"operator"`
	Negate   bool          `json:"negate"`
	CpeMatch []nvdCPEMatch `json:"cpeMatch"`
	Children []nvdNode     `json:"children"`
}

type nvdCPEMatch struct {
	Vulnerable     bool   `json:"vulnerable"`
	Criteria       string `json:"criteria"`
	MatchID        string `json:"matchCriteriaId"`
	VersionStart   string `json:"versionStartIncluding"`
	StartExcluding string `json:"versionStartExcluding"`
	EndIncluding   string `json:"versionEndIncluding"`
	EndExcluding   string `json:"versionEndExcluding"`
}

type nvdReference struct {
	URL  string   `json:"url"`
	Name string   `json:"source,omitempty"`
	Tags []string `json:"tags"`
}

// ParseNVDFeed streams a gzipped NVD 2.0 feed, handing each record's raw JSON to
// fn. Streaming matters: the largest single year is a 42 MB gzip member that
// expands to hundreds of megabytes.
func ParseNVDFeed(r io.Reader, fn func(raw []byte) error) (count int, timestamp string, err error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return 0, "", fmt.Errorf("ingest: nvd feed: %w", err)
	}
	defer zr.Close()
	dec := json.NewDecoder(zr)
	tok, err := dec.Token()
	if err != nil {
		return 0, "", fmt.Errorf("ingest: nvd feed: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return 0, "", fmt.Errorf("ingest: nvd feed: expected a JSON object, got %v", tok)
	}
	sawVulns, sawTimestamp := false, false
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return count, timestamp, fmt.Errorf("ingest: nvd feed: %w", err)
		}
		key, _ := keyTok.(string)
		switch key {
		case "timestamp":
			if err := dec.Decode(&timestamp); err != nil {
				return count, timestamp, fmt.Errorf("ingest: nvd feed: %w", err)
			}
			sawTimestamp = true
		case "vulnerabilities":
			sawVulns = true
			if _, err := dec.Token(); err != nil { // '['
				return count, timestamp, fmt.Errorf("ingest: nvd feed: %w", err)
			}
			for dec.More() {
				var raw json.RawMessage
				if err := dec.Decode(&raw); err != nil {
					return count, timestamp, fmt.Errorf("ingest: nvd feed: %w", err)
				}
				if err := fn([]byte(raw)); err != nil {
					return count, timestamp, err
				}
				count++
			}
			if _, err := dec.Token(); err != nil { // ']'
				return count, timestamp, fmt.Errorf("ingest: nvd feed: %w", err)
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return count, timestamp, fmt.Errorf("ingest: nvd feed: %w", err)
			}
		}
	}
	tok, err = dec.Token()
	if err != nil {
		return count, timestamp, fmt.Errorf("ingest: nvd feed: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '}' {
		return count, timestamp, fmt.Errorf("ingest: nvd feed: expected end of object, got %v", tok)
	}
	if !sawTimestamp || !sawVulns {
		return count, timestamp, fmt.Errorf("ingest: nvd feed: missing timestamp or vulnerabilities")
	}
	if model.NormalizeTime(timestamp) == "" {
		return count, timestamp, fmt.Errorf("ingest: nvd feed: unusable timestamp %q", timestamp)
	}
	return count, timestamp, nil
}

// ParseNVDRecord decodes one feed element into the merged model shape.
func ParseNVDRecord(raw []byte) (*model.CVE, error) {
	var v nvdVulnerability
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("ingest: nvd record: %w", err)
	}
	c := fromNVD(v.CVE)
	if c.ID == "" {
		return nil, fmt.Errorf("ingest: nvd record: no id")
	}
	return c, nil
}

func fromNVD(n nvdCVE) *model.CVE {
	c := &model.CVE{
		ID:        n.ID,
		State:     "UNKNOWN", // cvelistV5 owns record state; NVD has none
		NVDStatus: n.VulnStatus,
		Published: model.NormalizeTime(n.Published),
		Modified:  model.NormalizeTime(n.LastModified),
		Assigner:  n.SourceIdentifier,
		Metrics:   map[string]model.Metric{},
		Enriched:  true,
	}
	if year, ok := yearOf(n.ID); ok {
		c.Year = year
	}
	for _, d := range n.Descriptions {
		if strings.EqualFold(d.Lang, "en") && strings.TrimSpace(d.Value) != "" {
			c.Summary = strings.TrimSpace(d.Value)
			c.SummarySrc = "nvd"
			break
		}
	}
	addNVDMetrics(c, model.VerV2, n.Metrics.V2)
	addNVDMetrics(c, model.VerV30, n.Metrics.V30)
	addNVDMetrics(c, model.VerV31, n.Metrics.V31)
	addNVDMetrics(c, model.VerV40, n.Metrics.V40)

	for _, w := range n.Weaknesses {
		for _, d := range w.Description {
			id := strings.TrimSpace(d.Value)
			if id == "" {
				continue
			}
			dup := false
			for _, existing := range c.CWEs {
				if existing.ID == id {
					dup = true
					break
				}
			}
			if dup {
				continue
			}
			c.CWEs = append(c.CWEs, model.CWERef{ID: id, Source: "nvd"})
		}
	}
	for _, r := range n.References {
		url := strings.TrimSpace(r.URL)
		if url == "" {
			continue
		}
		c.Refs = append(c.Refs, model.Reference{URL: url, Tags: strings.Join(r.Tags, ","), Name: r.Name})
	}
	for _, cfg := range n.Configurations {
		for _, node := range cfg.Nodes {
			addNVDNode(c, node)
		}
	}
	if strings.TrimSpace(n.ExploitAdd) != "" || strings.TrimSpace(n.VulnerabilityName) != "" {
		c.KEV = &model.KEV{
			Added:      model.NormalizeTime(n.ExploitAdd),
			Due:        model.NormalizeTime(n.ActionDue),
			Name:       n.VulnerabilityName,
			Ransomware: "",
		}
	}
	return c
}

// addNVDMetrics records every metric of one version, preferring the Primary
// entry over a Secondary one.
func addNVDMetrics(c *model.CVE, version string, metrics []nvdMetric) {
	for _, m := range metrics {
		source := "nvd-secondary"
		if strings.EqualFold(m.Type, "Primary") {
			source = "nvd-primary"
		}
		metric := model.Metric{
			Score:    m.CvssData.BaseScore,
			Severity: strings.ToLower(m.CvssData.BaseSeverity),
			Vector:   m.CvssData.VectorString,
			Source:   source,
		}
		cur, ok := c.Metrics[version]
		if ok && cur.Rank() >= metric.Rank() {
			continue
		}
		c.Metrics[version] = metric
	}
}

// addNVDNode flattens a configuration node and its children into CPE match
// rows. The NVD feed nests affected products under children, so recursing is
// required to see all of them.
func addNVDNode(c *model.CVE, node nvdNode) {
	for _, m := range node.CpeMatch {
		name, ok := cpe.ParseOK(m.Criteria)
		if !ok {
			continue
		}
		c.CPEs = append(c.CPEs, model.CPEMatch{
			Criteria:   name.Criteria(),
			Name:       name,
			Vulnerable: m.Vulnerable,
			MatchID:    m.MatchID,
			StartIncl:  m.VersionStart,
			StartExcl:  m.StartExcluding,
			EndIncl:    m.EndIncluding,
			EndExcl:    m.EndExcluding,
			Source:     "nvd",
		})
	}
	for _, child := range node.Children {
		addNVDNode(c, child)
	}
}
