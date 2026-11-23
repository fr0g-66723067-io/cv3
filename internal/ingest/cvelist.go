package ingest

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/fr0g-66723067-io/cv3/internal/cpe"
	"github.com/fr0g-66723067-io/cv3/internal/model"
)

// Release is one cvelistV5 GitHub release: a tag plus its downloadable assets.
type Release struct {
	Tag       string
	Published time.Time
	Assets    map[string]string // asset name -> browser download URL
}

// AllCVEsAsset returns the daily all-CVEs archive URL.
func (r Release) AllCVEsAsset() (string, bool) {
	for name, url := range r.Assets {
		if strings.HasSuffix(name, "_all_CVEs_at_midnight.zip.zip") {
			return url, true
		}
	}
	return "", false
}

// DeltaAsset returns the hourly delta archive URL.
func (r Release) DeltaAsset() (string, bool) {
	for name, url := range r.Assets {
		if strings.Contains(name, "_delta_CVEs_at_") && strings.HasSuffix(name, ".zip") {
			return url, true
		}
	}
	return "", false
}

// tagTime parses a cvelistV5 tag such as cve_2026-10-30_1900Z into UTC.
func tagTime(tag string) (time.Time, error) {
	const layout = "cve_2006-01-02_1504Z"
	t, err := time.Parse(layout, tag)
	if err != nil {
		return time.Time{}, fmt.Errorf("ingest: cvelistV5 tag %q: %w", tag, err)
	}
	return t.UTC(), nil
}

const releaseAPI = "https://api.github.com/repos/CVEProject/cvelistV5/releases"

func githubGet(ctx context.Context, url, token string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("ingest: github: %w", err)
	}
	req.Header.Set("User-Agent", "cv3/1.0")
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("ingest: github: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("ingest: github: rate limited (HTTP %d); set GITHUB_TOKEN", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ingest: github: HTTP %s", resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out); err != nil {
		return fmt.Errorf("ingest: github: %w", err)
	}
	return nil
}

type ghRelease struct {
	TagName     string    `json:"tag_name"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []struct {
		Name       string `json:"name"`
		BrowserURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func toRelease(g ghRelease) (Release, error) {
	t, err := tagTime(g.TagName)
	if err != nil {
		return Release{}, err
	}
	r := Release{Tag: g.TagName, Published: t, Assets: map[string]string{}}
	for _, a := range g.Assets {
		r.Assets[a.Name] = a.BrowserURL
	}
	return r, nil
}

// LatestRelease resolves the newest cvelistV5 release.
func LatestRelease(ctx context.Context, token string) (Release, error) {
	var g ghRelease
	if err := githubGet(ctx, releaseAPI+"/latest", token, &g); err != nil {
		return Release{}, err
	}
	return toRelease(g)
}

// ListReleases returns up to perPage recent releases, newest first.
func ListReleases(ctx context.Context, token string, perPage int) ([]Release, error) {
	if perPage <= 0 || perPage > 100 {
		perPage = 100
	}
	var g []ghRelease
	if err := githubGet(ctx, fmt.Sprintf("%s?per_page=%d", releaseAPI, perPage), token, &g); err != nil {
		return nil, err
	}
	out := make([]Release, 0, len(g))
	for _, item := range g {
		r, err := toRelease(item)
		if err != nil {
			continue // tags that are not hourly snapshots are not ours
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Published.After(out[j].Published) })
	return out, nil
}

var cveFileRE = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}\.json$`)

// maxNestedArchiveBytes bounds the decompressed size of the inner cves.zip.
// The real all-CVEs asset is 717 MB; 2 GiB leaves headroom. It is a variable so
// the limit test can shrink it.
var maxNestedArchiveBytes int64 = 2 << 30

// WalkCVEZip streams every CVE JSON member of a cvelistV5 archive. Members are
// read in place: the archive is never extracted wholesale, and only one record
// is held in memory at a time. Both known layouts match, because only the base
// name matters ("cves/YYYY/NNNNx/CVE-….json" and "deltaCves/CVE-….json").
//
// The daily all-CVEs asset is distributed as a zip that contains a single
// "cves.zip" member (verified 2026-10-30: 648 MB outer, 717 MB inner, 417 488
// CVE files), so a nested archive is unwrapped through a temporary file in the
// same directory.
func WalkCVEZip(ctx context.Context, archive string, fn func(id string, raw []byte) error) (parsed, skipped int, err error) {
	return walkZip(ctx, archive, fn, 0)
}

func walkZip(ctx context.Context, archive string, fn func(id string, raw []byte) error, depth int) (int, int, error) {
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	f, err := openFile(archive)
	if err != nil {
		return 0, 0, fmt.Errorf("ingest: cvelistV5: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, 0, fmt.Errorf("ingest: cvelistV5: %w", err)
	}
	zr, err := zip.NewReader(f, fi.Size())
	if err != nil {
		return 0, 0, fmt.Errorf("ingest: cvelistV5: %w", err)
	}

	matches := 0
	var nested *zip.File
	for _, zf := range zr.File {
		if err := ctx.Err(); err != nil {
			return 0, 0, err
		}
		if zf.FileInfo().IsDir() {
			continue
		}
		if cveFileRE.MatchString(path.Base(zf.Name)) {
			matches++
		}
	}
	if matches == 0 {
		for _, zf := range zr.File {
			if err := ctx.Err(); err != nil {
				return 0, 0, err
			}
			if zf.FileInfo().IsDir() || !strings.EqualFold(path.Ext(zf.Name), ".zip") {
				continue
			}
			if nested != nil {
				return 0, len(zr.File), fmt.Errorf("ingest: cvelistV5: %s: several nested archives", archive)
			}
			nested = zf
		}
		if nested == nil {
			return 0, len(zr.File), fmt.Errorf("ingest: cvelistV5: %s: no CVE records among %d entries", archive, len(zr.File))
		}
		if depth >= 1 {
			return 0, len(zr.File), fmt.Errorf("ingest: cvelistV5: %s: nested archives deeper than one level", archive)
		}
		inner := archive + ".inner"
		if err := extractMember(ctx, nested, inner); err != nil {
			return 0, len(zr.File), err
		}
		f.Close()
		parsed, skipped, err := walkZip(ctx, inner, fn, depth+1)
		os.Remove(inner)
		return parsed, skipped, err
	}

	parsedCount := 0
	skippedCount := 0
	for _, zf := range zr.File {
		if err := ctx.Err(); err != nil {
			return parsedCount, skippedCount, err
		}
		if zf.FileInfo().IsDir() {
			skippedCount++
			continue
		}
		if !cveFileRE.MatchString(path.Base(zf.Name)) {
			skippedCount++
			continue
		}
		id := strings.TrimSuffix(path.Base(zf.Name), ".json")
		rc, err := zf.Open()
		if err != nil {
			return parsedCount, skippedCount, fmt.Errorf("ingest: cvelistV5: %s: %w", zf.Name, err)
		}
		raw, err := io.ReadAll(io.LimitReader(rc, 4<<20))
		rc.Close()
		if err != nil {
			return parsedCount, skippedCount, fmt.Errorf("ingest: cvelistV5: %s: %w", zf.Name, err)
		}
		if err := fn(id, raw); err != nil {
			return parsedCount, skippedCount, err
		}
		parsedCount++
	}
	if parsedCount == 0 {
		// An archive that matches nothing is a broken download or an upstream
		// layout change; reporting success would silently leave the corpus
		// without its base records.
		return 0, skippedCount, fmt.Errorf("ingest: cvelistV5: %s: no CVE records among %d entries", archive, skippedCount)
	}
	return parsedCount, skippedCount, nil
}

// extractMember writes one archive member to dest, used only to make a nested
// archive addressable (zip readers need a ReaderAt). The decompressed size is
// bounded so a crafted inner archive cannot fill the cache filesystem.
func extractMember(ctx context.Context, zf *zip.File, dest string) error {
	if zf.UncompressedSize64 > uint64(maxNestedArchiveBytes) {
		return fmt.Errorf("ingest: cvelistV5: %s: nested archive of %d bytes exceeds the %d-byte limit",
			zf.Name, zf.UncompressedSize64, maxNestedArchiveBytes)
	}
	rc, err := zf.Open()
	if err != nil {
		return fmt.Errorf("ingest: cvelistV5: %s: %w", zf.Name, err)
	}
	defer rc.Close()
	out, err := createFile(dest)
	if err != nil {
		return fmt.Errorf("ingest: cvelistV5: %w", err)
	}
	fail := func(err error) error {
		out.Close()
		os.Remove(dest)
		return fmt.Errorf("ingest: cvelistV5: %s: %w", zf.Name, err)
	}
	buf := make([]byte, 32<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			out.Close()
			os.Remove(dest)
			return err
		}
		n, rerr := rc.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > maxNestedArchiveBytes {
				out.Close()
				os.Remove(dest)
				return fmt.Errorf("ingest: cvelistV5: %s: nested archive of %d bytes exceeds the %d-byte limit",
					zf.Name, total, maxNestedArchiveBytes)
			}
			if _, werr := out.Write(buf[:n]); werr != nil {
				return fail(werr)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return fail(rerr)
		}
	}
	if err := out.Close(); err != nil {
		os.Remove(dest)
		return fmt.Errorf("ingest: cvelistV5: %w", err)
	}
	return nil
}

// cvelistV5 JSON shapes, only the parts cv3 indexes.

type cveListDoc struct {
	DataType    string      `json:"dataType"`
	CveMetadata cveMetadata `json:"cveMetadata"`
	Containers  containers  `json:"containers"`
}

type cveMetadata struct {
	CveID             string `json:"cveId"`
	AssignerOrgID     string `json:"assignerOrgId"`
	AssignerShortName string `json:"assignerShortName"`
	State             string `json:"state"`
	DateReserved      string `json:"dateReserved"`
	DatePublished     string `json:"datePublished"`
	DateUpdated       string `json:"dateUpdated"`
}

type containers struct {
	CNA cnaContainer   `json:"cna"`
	ADP []adpContainer `json:"adp"`
}

type cnaContainer struct {
	Title           string        `json:"title"`
	Descriptions    []textValue   `json:"descriptions"`
	Affected        []affected    `json:"affected"`
	ProblemTypes    []problemType `json:"problemTypes"`
	Metrics         []metric      `json:"metrics"`
	References      []reference   `json:"references"`
	RejectedReasons []textValue   `json:"rejectedReasons"`
}

type adpContainer struct {
	Title        string        `json:"title"`
	Affected     []affected    `json:"affected"`
	ProblemTypes []problemType `json:"problemTypes"`
	Metrics      []metric      `json:"metrics"`
	References   []reference   `json:"references"`
}

type textValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type problemType struct {
	Descriptions []problemDescription `json:"descriptions"`
}

type problemDescription struct {
	Type        string `json:"type"`
	CWEID       string `json:"cweId"`
	Lang        string `json:"lang"`
	Description string `json:"description"`
}

type metric struct {
	CvssV2  *cvssMetric `json:"cvssV2_0"`
	CvssV30 *cvssMetric `json:"cvssV3_0"`
	CvssV31 *cvssMetric `json:"cvssV3_1"`
	CvssV40 *cvssMetric `json:"cvssV4_0"`
	Other   *struct {
		Type string `json:"type"`
	} `json:"other"`
	Scenario *struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"scenario"`
}

type cvssMetric struct {
	Version      string  `json:"version"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

type affected struct {
	Vendor        string       `json:"vendor"`
	Product       string       `json:"product"`
	PackageName   string       `json:"packageName"`
	CollectionURL string       `json:"collectionURL"`
	CPEs          []string     `json:"cpes"`
	DefaultStatus string       `json:"defaultStatus"`
	Versions      []affVersion `json:"versions"`
}

type affVersion struct {
	Version     string `json:"version"`
	Status      string `json:"status"`
	LessThan    string `json:"lessThan"`
	VersionType string `json:"versionType"`
}

type reference struct {
	URL  string   `json:"url"`
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

// ParseCVEListV5 decodes one cvelistV5 record into the merged model shape. It
// never fails on missing optional sections: REJECTED and RESERVED records have
// no description and are still part of the corpus.
func ParseCVEListV5(raw []byte) (*model.CVE, error) {
	var doc cveListDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("ingest: cvelistV5: %w", err)
	}
	id := doc.CveMetadata.CveID
	if id == "" {
		return nil, fmt.Errorf("ingest: cvelistV5: record without cveId")
	}
	c := &model.CVE{
		ID:       id,
		State:    strings.ToUpper(doc.CveMetadata.State),
		Assigner: doc.CveMetadata.AssignerShortName,
		Reserved: model.NormalizeTime(doc.CveMetadata.DateReserved),
		Metrics:  map[string]model.Metric{},
		CNATitle: doc.Containers.CNA.Title,
	}
	if c.State == "" {
		c.State = "UNKNOWN"
	}
	if year, ok := yearOf(id); ok {
		c.Year = year
	}
	c.Published = model.NormalizeTime(doc.CveMetadata.DatePublished)
	c.Modified = model.NormalizeTime(doc.CveMetadata.DateUpdated)
	for _, d := range doc.Containers.CNA.Descriptions {
		if strings.EqualFold(d.Lang, "en") && strings.TrimSpace(d.Value) != "" {
			c.Summary = strings.TrimSpace(d.Value)
			c.SummarySrc = "cna"
			break
		}
	}

	// ADP containers are lower authority than the CNA container; recording in
	// that order lets putMetric keep the stronger statement.
	for _, adp := range doc.Containers.ADP {
		for _, m := range adp.Metrics {
			addMetric(c.Metrics, m, "adp")
		}
		for _, pt := range adp.ProblemTypes {
			addCWEs(c, pt, "adp")
		}
		addAffected(c, adp.Affected, "adp")
	}
	for _, m := range doc.Containers.CNA.Metrics {
		addMetric(c.Metrics, m, "cna")
	}
	for _, pt := range doc.Containers.CNA.ProblemTypes {
		addCWEs(c, pt, "cna")
	}
	addAffected(c, doc.Containers.CNA.Affected, "cna")

	seenRef := map[string]bool{}
	addRef := func(r reference) {
		url := strings.TrimSpace(r.URL)
		if url == "" || seenRef[url] {
			return
		}
		seenRef[url] = true
		c.Refs = append(c.Refs, model.Reference{URL: url, Name: r.Name, Tags: strings.Join(r.Tags, ",")})
	}
	for _, r := range doc.Containers.CNA.References {
		addRef(r)
	}
	for _, adp := range doc.Containers.ADP {
		for _, r := range adp.References {
			addRef(r)
		}
	}
	return c, nil
}

// addMetric records one CVSS metric using source precedence: an existing
// higher-ranked metric wins.
func addMetric(dst map[string]model.Metric, m metric, source string) {
	pairs := []struct {
		key string
		val *cvssMetric
	}{
		{model.VerV2, m.CvssV2},
		{model.VerV30, m.CvssV30},
		{model.VerV31, m.CvssV31},
		{model.VerV40, m.CvssV40},
	}
	for _, p := range pairs {
		if p.val == nil {
			continue
		}
		metric := model.Metric{
			Score:    p.val.BaseScore,
			Severity: strings.ToLower(p.val.BaseSeverity),
			Vector:   p.val.VectorString,
			Source:   source,
		}
		cur, ok := dst[p.key]
		if ok && cur.Rank() >= metric.Rank() {
			continue
		}
		dst[p.key] = metric
	}
}

// addCWEs records CWE identifiers with their source, deduplicated by id.
func addCWEs(c *model.CVE, pt problemType, source string) {
	for _, d := range pt.Descriptions {
		if !strings.EqualFold(d.Type, "CWE") {
			continue
		}
		id := strings.TrimSpace(d.CWEID)
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
		c.CWEs = append(c.CWEs, model.CWERef{ID: id, Source: source})
	}
}

// addAffected records CNA product statements and any CPE strings the container
// carries. CPE strings appear in both bindings in the same record.
func addAffected(c *model.CVE, entries []affected, source string) {
	for _, a := range entries {
		vendor := strings.ToLower(strings.TrimSpace(a.Vendor))
		product := strings.ToLower(strings.TrimSpace(a.Product))
		if vendor != "" || product != "" {
			c.Products = append(c.Products, model.Product{
				Vendor:      vendor,
				Product:     product,
				PackageName: a.PackageName,
				Versions:    marshalVersions(a.Versions),
				Source:      "cna",
			})
		}
		vulnerable := strings.EqualFold(a.DefaultStatus, "affected")
		for _, v := range a.Versions {
			if strings.EqualFold(v.Status, "affected") {
				vulnerable = true
			}
		}
		for _, raw := range a.CPEs {
			name, ok := cpe.ParseOK(raw)
			if !ok {
				continue
			}
			c.CPEs = append(c.CPEs, model.CPEMatch{
				Criteria:   name.Criteria(),
				Name:       name,
				Vulnerable: vulnerable,
				Source:     source,
			})
		}
	}
}

func marshalVersions(vs []affVersion) string {
	if len(vs) == 0 {
		return ""
	}
	b, err := json.Marshal(vs)
	if err != nil {
		return ""
	}
	return string(b)
}

// yearOf extracts the year from a CVE identifier.
func yearOf(id string) (int, bool) {
	if !strings.HasPrefix(id, "CVE-") || len(id) < 10 {
		return 0, false
	}
	n := 0
	for _, r := range id[4:8] {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}
