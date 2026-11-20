package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/fr0g-66723067-io/cv3/internal/cpe"
	"github.com/fr0g-66723067-io/cv3/internal/model"
)

// QE = "query engine" helpers below build SQL with ordered placeholders so a
// caller never has to reason about argument positions.

type cond struct {
	sql  string
	args []any
}

func renderConds(conds []cond) (string, []any) {
	if len(conds) == 0 {
		return "", nil
	}
	parts := make([]string, 0, len(conds))
	var args []any
	for _, c := range conds {
		parts = append(parts, c.sql)
		args = append(args, c.args...)
	}
	return " WHERE " + strings.Join(parts, " AND "), args
}

func inClause(n int) string {
	if n <= 0 {
		return "(NULL)"
	}
	return "(" + strings.TrimSuffix(strings.Repeat("?,", n), ",") + ")"
}

func anyArgs[T any](vals []T) []any {
	out := make([]any, len(vals))
	for i, v := range vals {
		out[i] = v
	}
	return out
}

// SearchQuery is one structured query. Zero values mean "no filter".
type SearchQuery struct {
	Query string
	Or    bool

	CVEs                    []string
	YearsFrom, YearsTo      int
	Severities              []string
	States                  []string
	Statuses                []string
	MinScore, MaxScore      float64
	HasScore                bool
	CVSSVersion             string // "" (best) | v2 | v30 | v31 | v40
	CWEs                    []string
	Vendors, Products       []string
	KEVOnly, UnenrichedOnly bool
	PublishedAfter          string
	PublishedBefore         string

	Limit, Offset int
	Sort          string // relevance | score | date | id
}

func (q *SearchQuery) normalize() {
	q.Limit = ClampLimit(q.Limit, 20)
	if q.Offset < 0 {
		q.Offset = 0
	}
}

// ClampLimit applies the page-size rule shared by every listing query: a
// non-positive limit takes def, and anything above 500 is capped at 500.
func ClampLimit(n, def int) int {
	if n <= 0 {
		return def
	}
	if n > 500 {
		return 500
	}
	return n
}

// Hit is one search result row.
type Hit struct {
	ID        string
	Score     *float64
	Severity  string
	CVSSVer   string
	Published string
	State     string
	Enriched  bool
	CWEs      []string
	Summary   string
	Snippet   string
}

// SearchResult is a page of hits plus the unpaged total.
type SearchResult struct {
	Total int
	Hits  []Hit
}

// Search runs a full-text and/or structured query.
func (d *DB) Search(ctx context.Context, q SearchQuery) (SearchResult, error) {
	q.normalize()
	fts, err := ftsQuery(q.Query, q.Or)
	if err != nil {
		return SearchResult{}, err
	}
	conds := q.conds()

	from := "FROM cve c"
	snippet := "''"
	if fts != "" {
		from = "FROM cve_fts JOIN cve c ON c.rowid = cve_fts.rowid"
		snippet = "snippet(cve_fts, 0, '[', ']', '…', 24)"
		conds = append([]cond{{sql: "cve_fts MATCH ?", args: []any{fts}}}, conds...)
	}
	where, args := renderConds(conds)

	order := q.orderBy(fts != "")
	sel := `SELECT c.id, c.best_score, c.best_sev, c.best_ver, c.published, c.state, c.enriched,
		c.summary, ` + snippet + ` ` + from + where + ` ` + order + ` LIMIT ? OFFSET ?`
	rows, err := d.db.QueryContext(ctx, sel, append(args, q.Limit, q.Offset)...)
	if err != nil {
		return SearchResult{}, fmt.Errorf("store: search: %w", err)
	}
	defer rows.Close()
	res := SearchResult{Hits: make([]Hit, 0, q.Limit)}
	for rows.Next() {
		var (
			h       Hit
			score   sql.NullFloat64
			sev     sql.NullString
			ver     sql.NullString
			pub     sql.NullString
			state   sql.NullString
			snipRow sql.NullString
		)
		if err := rows.Scan(&h.ID, &score, &sev, &ver, &pub, &state, &h.Enriched,
			&h.Summary, &snipRow); err != nil {
			return SearchResult{}, fmt.Errorf("store: search: %w", err)
		}
		if score.Valid {
			s := score.Float64
			h.Score = &s
		}
		h.Severity = sev.String
		h.CVSSVer = ver.String
		h.Published = pub.String
		h.State = state.String
		h.Snippet = snipRow.String
		if h.Snippet == "" {
			h.Snippet = truncate(h.Summary, 240)
		}
		res.Hits = append(res.Hits, h)
	}
	if err := rows.Err(); err != nil {
		return SearchResult{}, fmt.Errorf("store: search: %w", err)
	}
	rows.Close()

	total, err := d.countSearch(ctx, from, where, args)
	if err != nil {
		return SearchResult{}, err
	}
	res.Total = total
	if err := d.fillCWEs(ctx, res.Hits); err != nil {
		return SearchResult{}, err
	}
	return res, nil
}

func (d *DB) countSearch(ctx context.Context, from, where string, args []any) (int, error) {
	var n int
	if err := d.db.QueryRowContext(ctx, `SELECT count(*) `+from+where, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count: %w", err)
	}
	return n, nil
}

func (d *DB) fillCWEs(ctx context.Context, hits []Hit) error {
	if len(hits) == 0 {
		return nil
	}
	ids := make([]string, len(hits))
	idx := make(map[string]int, len(hits))
	for i := range hits {
		ids[i] = hits[i].ID
		idx[hits[i].ID] = i
	}
	// DISTINCT: a CWE stated by both sources is one row per (cve, cwe, src), and
	// a hit lists identifiers, not provenance.
	rows, err := d.db.QueryContext(ctx,
		`SELECT DISTINCT cve_id, cwe_id FROM cve_cwe WHERE cve_id IN `+inClause(len(ids))+` ORDER BY cwe_id`,
		anyArgs(ids)...)
	if err != nil {
		return fmt.Errorf("store: hit cwes: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cveID, cweID string
		if err := rows.Scan(&cveID, &cweID); err != nil {
			return fmt.Errorf("store: hit cwes: %w", err)
		}
		if i, ok := idx[cveID]; ok {
			hits[i].CWEs = append(hits[i].CWEs, cweID)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store: hit cwes: %w", err)
	}
	return nil
}

// scoreColumn maps a CVSS version selector to its column.
func scoreColumn(version string) string {
	switch version {
	case model.VerV2:
		return "c.v2_score"
	case model.VerV30:
		return "c.v30_score"
	case model.VerV31:
		return "c.v31_score"
	case model.VerV40:
		return "c.v40_score"
	}
	return "c.best_score"
}

func (q *SearchQuery) conds() []cond {
	var out []cond
	if q.YearsFrom > 0 && q.YearsTo > 0 {
		out = append(out, cond{"c.year BETWEEN ? AND ?", []any{q.YearsFrom, q.YearsTo}})
	} else if q.YearsFrom > 0 {
		out = append(out, cond{"c.year >= ?", []any{q.YearsFrom}})
	} else if q.YearsTo > 0 {
		out = append(out, cond{"c.year <= ?", []any{q.YearsTo}})
	}
	if len(q.Severities) > 0 {
		out = append(out, cond{"c.best_sev IN " + inClause(len(q.Severities)), anyArgs(q.Severities)})
	}
	if len(q.States) > 0 {
		out = append(out, cond{"c.state IN " + inClause(len(q.States)), anyArgs(q.States)})
	}
	if len(q.Statuses) > 0 {
		out = append(out, cond{"c.nvd_status IN " + inClause(len(q.Statuses)), anyArgs(q.Statuses)})
	}
	col := scoreColumn(q.CVSSVersion)
	if q.HasScore {
		out = append(out, cond{col + " >= ?", []any{q.MinScore}})
	}
	if q.MaxScore > 0 {
		out = append(out, cond{col + " <= ?", []any{q.MaxScore}})
	}
	if len(q.CVEs) > 0 {
		out = append(out, cond{"c.id IN " + inClause(len(q.CVEs)), anyArgs(q.CVEs)})
	}
	if len(q.CWEs) > 0 {
		out = append(out, cond{
			"EXISTS (SELECT 1 FROM cve_cwe w WHERE w.cve_id = c.id AND w.cwe_id IN " + inClause(len(q.CWEs)) + ")",
			anyArgs(q.CWEs),
		})
	}
	if len(q.Vendors) > 0 || len(q.Products) > 0 {
		pm, pa := vendorProductPredicate("m", q.Vendors, q.Products)
		pp, pb := vendorProductPredicate("p", q.Vendors, q.Products)
		out = append(out, cond{
			"(EXISTS (SELECT 1 FROM cpe_match m WHERE m.cve_id = c.id AND " + pm + ")" +
				" OR EXISTS (SELECT 1 FROM cve_product p WHERE p.cve_id = c.id AND " + pp + "))",
			append(pa, pb...),
		})
	}
	if q.KEVOnly {
		out = append(out, cond{"c.kev = 1", nil})
	}
	if q.UnenrichedOnly {
		out = append(out, cond{"c.enriched = 0", nil})
	}
	if q.PublishedAfter != "" {
		out = append(out, cond{"c.published >= ?", []any{q.PublishedAfter}})
	}
	if q.PublishedBefore != "" {
		out = append(out, cond{"c.published <= ?", []any{q.PublishedBefore}})
	}
	return out
}

// vendorProductPredicate builds the vendor/product filter for one relation.
// A "*" (or empty) value means "any" and drops that side.
func vendorProductPredicate(alias string, vendors, products []string) (string, []any) {
	var parts []string
	var args []any
	if len(vendors) > 0 {
		filtered := withoutAny(vendors)
		if len(filtered) > 0 {
			parts = append(parts, alias+".vendor IN "+inClause(len(filtered)))
			args = append(args, anyArgs(filtered)...)
		}
	}
	if len(products) > 0 {
		filtered := withoutAny(products)
		if len(filtered) > 0 {
			parts = append(parts, alias+".product IN "+inClause(len(filtered)))
			args = append(args, anyArgs(filtered)...)
		}
	}
	if len(parts) == 0 {
		return "1", nil
	}
	return strings.Join(parts, " AND "), args
}

func withoutAny(vals []string) []string {
	out := make([]string, 0, len(vals))
	seen := map[string]bool{}
	for _, v := range vals {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" || v == "*" || v == "-" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func (q *SearchQuery) orderBy(hasFTS bool) string {
	switch q.Sort {
	case "score":
		return "ORDER BY c.best_score IS NULL, c.best_score DESC, c.id"
	case "date":
		return "ORDER BY c.published DESC, c.id"
	case "id":
		return "ORDER BY c.id"
	case "relevance":
		if hasFTS {
			return "ORDER BY bm25(cve_fts, 1.0, 0.4, 0.6), c.id"
		}
		return "ORDER BY c.best_score IS NULL, c.best_score DESC, c.id"
	}
	if hasFTS {
		return "ORDER BY bm25(cve_fts, 1.0, 0.4, 0.6), c.id"
	}
	return "ORDER BY c.best_score IS NULL, c.best_score DESC, c.id"
}

// ftsStop holds the boolean and column operators FTS5 would interpret, so a
// user query is always a plain conjunction of quoted tokens.
var ftsStop = map[string]bool{
	"and": true, "or": true, "not": true, "near": true, "col": true,
}

// ftsQuery turns free text into a safe FTS5 expression: every token quoted,
// joined by AND (or OR). An empty result means "run no MATCH".
func ftsQuery(q string, or bool) (string, error) {
	terms := ftsTokens(q)
	if len(terms) == 0 {
		return "", nil
	}
	quoted := make([]string, 0, len(terms))
	for _, t := range terms {
		quoted = append(quoted, `"`+strings.ReplaceAll(t, `"`, `""`)+`"`)
	}
	op := " AND "
	if or {
		op = " OR "
	}
	return strings.Join(quoted, op), nil
}

func ftsTokens(q string) []string {
	raw := strings.FieldsFunc(q, func(r rune) bool {
		return unicode.IsSpace(r) || r == '(' || r == ')' || r == ':' || r == '^' ||
			r == '"' || r == '*' || r == ','
	})
	out := make([]string, 0, len(raw))
	for _, t := range raw {
		t = strings.Trim(t, "-+.!?;'")
		t = strings.TrimPrefix(t, "-")
		if t == "" || ftsStop[strings.ToLower(t)] {
			continue
		}
		out = append(out, t)
	}
	return out
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	cut := maxLen
	for cut > 0 && !utf8RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

// Get loads one merged record with all dependent rows.
func (d *DB) Get(ctx context.Context, id string) (*model.CVE, error) {
	row := d.db.QueryRowContext(ctx, `SELECT `+cveColumns+` FROM cve WHERE id = ?`, id)
	c := &model.CVE{Metrics: map[string]model.Metric{}}
	var (
		kev                                  int
		bestScore                            sql.NullFloat64
		bestSev, bestVer                     sql.NullString
		cpeCount, refCount                   int
		mergedAt                             string
		kevAdded, kevDue, kevName, kevRansom string
		scores                               [4]sql.NullFloat64
		sevs, vecs, srcs                     [4]sql.NullString
		err                                  error
		year                                 int
	)
	err = row.Scan(&c.ID, &year, &c.State, &c.NVDStatus, &c.Published, &c.Modified,
		&c.Reserved, &c.Assigner, &c.CNATitle, &c.Summary, &c.SummarySrc,
		&scores[0], &sevs[0], &vecs[0], &srcs[0],
		&scores[1], &sevs[1], &vecs[1], &srcs[1],
		&scores[2], &sevs[2], &vecs[2], &srcs[2],
		&scores[3], &sevs[3], &vecs[3], &srcs[3],
		&bestScore, &bestSev, &bestVer,
		&kev, &kevAdded, &kevDue, &kevName, &kevRansom,
		&c.Enriched, &cpeCount, &refCount, &mergedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("store: get %s: %w", id, err)
	}
	c.Year = year
	c.BestVersion = bestVer.String
	if bestScore.Valid {
		score := bestScore.Float64
		c.Best = &model.Metric{Score: score, Severity: bestSev.String, Source: bestVer.String}
	}
	if kev != 0 {
		c.KEV = &model.KEV{Added: kevAdded, Due: kevDue, Name: kevName, Ransomware: kevRansom}
	}
	for i, ver := range []string{model.VerV2, model.VerV30, model.VerV31, model.VerV40} {
		if !scores[i].Valid {
			continue
		}
		c.Metrics[ver] = model.Metric{
			Score:    scores[i].Float64,
			Severity: sevs[i].String,
			Vector:   vecs[i].String,
			Source:   srcs[i].String,
		}
	}
	if err := d.loadDependents(ctx, c); err != nil {
		return nil, err
	}
	return c, nil
}

func (d *DB) loadDependents(ctx context.Context, c *model.CVE) error {
	rows, err := d.db.QueryContext(ctx,
		`SELECT cwe_id, src FROM cve_cwe WHERE cve_id = ? ORDER BY cwe_id, src`, c.ID)
	if err != nil {
		return fmt.Errorf("store: get %s: cwes: %w", c.ID, err)
	}
	for rows.Next() {
		var w model.CWERef
		if err := rows.Scan(&w.ID, &w.Source); err != nil {
			rows.Close()
			return fmt.Errorf("store: get %s: cwes: %w", c.ID, err)
		}
		c.CWEs = append(c.CWEs, w)
	}
	rows.Close()

	rows, err = d.db.QueryContext(ctx,
		`SELECT criteria, part, vendor, product, version, update_, edition, language,
			sw_edition, target_sw, target_hw, other, vulnerable, match_id,
			start_incl, start_excl, end_incl, end_excl, src
		 FROM cpe_match WHERE cve_id = ? ORDER BY criteria, src`, c.ID)
	if err != nil {
		return fmt.Errorf("store: get %s: cpes: %w", c.ID, err)
	}
	for rows.Next() {
		var (
			m                   model.CPEMatch
			update, edition     string
			language, swEdition string
			targetSw, targetHw  string
			other               string
			vulnerable          int
		)
		m.Name = cpe.Name{}
		if err := rows.Scan(&m.Criteria, &m.Name.Part, &m.Name.Vendor, &m.Name.Product, &m.Name.Version,
			&update, &edition, &language, &swEdition, &targetSw, &targetHw, &other,
			&vulnerable, &m.MatchID, &m.StartIncl, &m.StartExcl, &m.EndIncl, &m.EndExcl, &m.Source); err != nil {
			rows.Close()
			return fmt.Errorf("store: get %s: cpes: %w", c.ID, err)
		}
		m.Name.Update, m.Name.Edition, m.Name.Language = update, edition, language
		m.Name.SwEdition, m.Name.TargetSw, m.Name.TargetHw, m.Name.Other = swEdition, targetSw, targetHw, other
		m.Vulnerable = vulnerable != 0
		c.CPEs = append(c.CPEs, m)
	}
	rows.Close()

	rows, err = d.db.QueryContext(ctx,
		`SELECT vendor, product, package_name, versions, src
		 FROM cve_product WHERE cve_id = ? ORDER BY vendor, product, src`, c.ID)
	if err != nil {
		return fmt.Errorf("store: get %s: products: %w", c.ID, err)
	}
	for rows.Next() {
		var p model.Product
		if err := rows.Scan(&p.Vendor, &p.Product, &p.PackageName, &p.Versions, &p.Source); err != nil {
			rows.Close()
			return fmt.Errorf("store: get %s: products: %w", c.ID, err)
		}
		c.Products = append(c.Products, p)
	}
	rows.Close()

	rows, err = d.db.QueryContext(ctx,
		`SELECT url, tags, name, src FROM cve_ref WHERE cve_id = ? ORDER BY url`, c.ID)
	if err != nil {
		return fmt.Errorf("store: get %s: refs: %w", c.ID, err)
	}
	for rows.Next() {
		var (
			r   model.Reference
			src string
		)
		if err := rows.Scan(&r.URL, &r.Tags, &r.Name, &src); err != nil {
			rows.Close()
			return fmt.Errorf("store: get %s: refs: %w", c.ID, err)
		}
		c.Refs = append(c.Refs, r)
	}
	rows.Close()
	return nil
}

// CPEFilter selects CVEs affecting a product, optionally at a version.
type CPEFilter struct {
	Vendor, Product, Version, Part string
	Criteria                       string
	Limit                          int
}

// CPEHit is one applicability match.
type CPEHit struct {
	CVE       string
	Score     *float64
	Severity  string
	Published string
	State     string
	Criteria  string
	Part      string
	Vendor    string
	Product   string
	Version   string
	Src       string
	MatchKind string // exact | range | unversioned | product
	Range     string
}

// ByCPE returns the CVEs affecting the requested CPE or product. Version
// filtering happens in Go because NVD expresses applicability as range bounds
// (versionStartIncluding/versionEndExcluding/...) that no index can evaluate.
func (d *DB) ByCPE(ctx context.Context, f CPEFilter) ([]CPEHit, error) {
	f.Limit = ClampLimit(f.Limit, 100)
	f.Vendor = strings.ToLower(strings.TrimSpace(f.Vendor))
	f.Product = strings.ToLower(strings.TrimSpace(f.Product))
	f.Part = strings.ToLower(strings.TrimSpace(f.Part))
	f.Version = strings.TrimSpace(f.Version)

	var conds []cond
	if f.Criteria != "" {
		if n, err := cpe.Parse(f.Criteria); err == nil {
			conds = append(conds, cond{"m.criteria = ?", []any{n.Criteria()}})
		} else {
			conds = append(conds, cond{"m.criteria = ?", []any{f.Criteria}})
		}
	} else {
		if f.Part != "" && f.Part != "*" {
			conds = append(conds, cond{"m.part = ?", []any{f.Part}})
		}
		if f.Vendor != "" && f.Vendor != "*" {
			conds = append(conds, cond{"m.vendor = ?", []any{f.Vendor}})
		}
		if f.Product != "" && f.Product != "*" {
			conds = append(conds, cond{"m.product = ?", []any{f.Product}})
		}
	}
	conds = append(conds, cond{"m.vulnerable = 1", nil})
	where, args := renderConds(conds)

	rows, err := d.db.QueryContext(ctx,
		`SELECT c.id, c.best_score, c.best_sev, c.published, c.state,
			m.criteria, m.part, m.vendor, m.product, m.version,
			m.start_incl, m.start_excl, m.end_incl, m.end_excl, m.src
		 FROM cpe_match m JOIN cve c ON c.id = m.cve_id`+where+`
		 ORDER BY c.best_score IS NULL, c.best_score DESC, c.id
		 LIMIT 200000`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: cpe: %w", err)
	}
	var hits []CPEHit
	seen := map[string]bool{}
	for rows.Next() {
		var (
			h                                           CPEHit
			score                                       sql.NullFloat64
			sev, pub, state                             sql.NullString
			crit, part, vendor, product, ver            string
			startIncl, startExcl, endIncl, endExcl, src string
		)
		if err := rows.Scan(&h.CVE, &score, &sev, &pub, &state, &crit, &part, &vendor,
			&product, &ver, &startIncl, &startExcl, &endIncl, &endExcl, &src); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: cpe: %w", err)
		}
		if score.Valid {
			s := score.Float64
			h.Score = &s
		}
		h.Severity, h.Published, h.State = sev.String, pub.String, state.String
		h.Criteria, h.Part, h.Vendor, h.Product, h.Version, h.Src = crit, part, vendor, product, ver, src
		key := h.CVE + "\x00" + crit
		if seen[key] {
			continue
		}
		if len(hits) >= f.Limit {
			// Rows arrive in score order, so once the page is full the rest of
			// this vendor's matches cannot change the answer.
			break
		}
		var r cpe.Range
		switch {
		case startIncl != "":
			r.Start = startIncl
		case startExcl != "":
			r.Start, r.StartExclusive = startExcl, true
		}
		switch {
		case endIncl != "":
			r.End = endIncl
		case endExcl != "":
			r.End, r.EndExclusive = endExcl, true
		}
		switch {
		case r.Start != "" || r.End != "":
			h.MatchKind = "range"
		case cpe.IsAny(ver) || cpe.IsNA(ver):
			h.MatchKind = "unversioned"
		default:
			h.MatchKind = "exact"
			r.Exact = ver
		}
		if f.Version != "" {
			if h.MatchKind == "unversioned" {
				// keep, but the caller sees that no version logic applied
			} else if !r.Affects(f.Version) {
				continue
			}
		}
		h.Range = r.String()
		seen[key] = true
		hits = append(hits, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: cpe: %w", err)
	}

	if f.Version == "" && f.Criteria == "" {
		prodHits, err := d.byProduct(ctx, f)
		if err != nil {
			return nil, err
		}
		hits = append(hits, prodHits...)
	}
	// Hits already arrive ordered by score (SQL) and are truncated at the page
	// size while scanning, so no second sort is needed.
	return hits, nil
}

// byProduct returns CNA-reported product matches, which carry no version
// semantics.
func (d *DB) byProduct(ctx context.Context, f CPEFilter) ([]CPEHit, error) {
	var conds []cond
	if f.Vendor != "" && f.Vendor != "*" {
		conds = append(conds, cond{"p.vendor = ?", []any{f.Vendor}})
	}
	if f.Product != "" && f.Product != "*" {
		conds = append(conds, cond{"p.product = ?", []any{f.Product}})
	}
	if len(conds) == 0 {
		return nil, nil
	}
	where, args := renderConds(conds)
	rows, err := d.db.QueryContext(ctx,
		`SELECT c.id, c.best_score, c.best_sev, c.published, c.state, p.vendor, p.product, p.src
		 FROM cve_product p JOIN cve c ON c.id = p.cve_id`+where+`
		 ORDER BY c.best_score IS NULL, c.best_score DESC, c.id LIMIT 2000`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: cpe product: %w", err)
	}
	defer rows.Close()
	var out []CPEHit
	seen := map[string]bool{}
	for rows.Next() {
		var (
			h                    CPEHit
			score                sql.NullFloat64
			sev, pub, state, src sql.NullString
		)
		if err := rows.Scan(&h.CVE, &score, &sev, &pub, &state, &h.Vendor, &h.Product, &src); err != nil {
			return nil, fmt.Errorf("store: cpe product: %w", err)
		}
		key := h.CVE + "\x00product\x00" + h.Vendor + "\x00" + h.Product
		if seen[key] {
			continue
		}
		seen[key] = true
		if score.Valid {
			s := score.Float64
			h.Score = &s
		}
		h.Severity, h.Published, h.State, h.Src = sev.String, pub.String, state.String, src.String
		h.MatchKind = "product"
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: cpe product: %w", err)
	}
	return out, nil
}

// CWEInfo is a catalog entry plus its CVE count.
type CWEInfo struct {
	model.CWE
	CVECount int
}

// CWE loads one catalog entry.
func (d *DB) CWE(ctx context.Context, id string) (*CWEInfo, error) {
	id = strings.ToUpper(strings.TrimSpace(id))
	var info model.CWE
	err := d.db.QueryRowContext(ctx,
		`SELECT id, name, abstraction, status, description FROM cwe WHERE id = ?`, id).
		Scan(&info.ID, &info.Name, &info.Abstraction, &info.Status, &info.Description)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("store: cwe %s: %w", id, err)
	}
	rows, err := d.db.QueryContext(ctx, `SELECT parent FROM cwe_parent WHERE child = ? ORDER BY parent`, id)
	if err != nil {
		return nil, fmt.Errorf("store: cwe %s: parents: %w", id, err)
	}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: cwe %s: parents: %w", id, err)
		}
		info.Parents = append(info.Parents, p)
	}
	rows.Close()
	out := &CWEInfo{CWE: info}
	if err := d.db.QueryRowContext(ctx,
		`SELECT count(DISTINCT cve_id) FROM cve_cwe WHERE cwe_id = ?`, id).Scan(&out.CVECount); err != nil {
		return nil, fmt.Errorf("store: cwe %s: count: %w", id, err)
	}
	return out, nil
}

// CWESearch finds catalog entries whose name or description contains terms.
func (d *DB) CWESearch(ctx context.Context, terms string, limit int) ([]CWEInfo, error) {
	terms = strings.ToLower(strings.TrimSpace(terms))
	if terms == "" {
		return nil, errors.New("store: cwe search: empty terms")
	}
	limit = ClampLimit(limit, 25)
	like := "%" + terms + "%"
	rows, err := d.db.QueryContext(ctx,
		`SELECT id, name, abstraction, status, description FROM cwe
		 WHERE lower(name) LIKE ? OR lower(description) LIKE ?
		 ORDER BY id LIMIT ?`, like, like, limit)
	if err != nil {
		return nil, fmt.Errorf("store: cwe search: %w", err)
	}
	defer rows.Close()
	var out []CWEInfo
	for rows.Next() {
		var info model.CWE
		if err := rows.Scan(&info.ID, &info.Name, &info.Abstraction, &info.Status, &info.Description); err != nil {
			return nil, fmt.Errorf("store: cwe search: %w", err)
		}
		out = append(out, CWEInfo{CWE: info})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: cwe search: %w", err)
	}
	return out, nil
}

// CWENames resolves CWE ids to catalog names. Unknown ids are absent from the
// result rather than mapped to an empty name.
func (d *DB) CWENames(ctx context.Context, ids []string) (map[string]string, error) {
	out := map[string]string{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := d.db.QueryContext(ctx,
		`SELECT id, name FROM cwe WHERE id IN `+inClause(len(ids)), anyArgs(ids)...)
	if err != nil {
		return nil, fmt.Errorf("store: cwe names: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, fmt.Errorf("store: cwe names: %w", err)
		}
		out[id] = name
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: cwe names: %w", err)
	}
	return out, nil
}

// Stats is the corpus summary printed by `cv3 stats`.
type Stats struct {
	CVEs        int
	Enriched    int
	Unenriched  int
	Rejected    int
	Reserved    int
	KEV         int
	CPEMatches  int
	CVEProducts int
	CWECatalog  int
	Refs        int
	FTSRows     int
	DBSize      int64
	DBPath      string
	BuiltAt     string
	SourceState map[string]string
	ByYear      map[int]int
	BySeverity  map[string]int
}

// Stats queries the corpus summary.
func (d *DB) Stats(ctx context.Context) (*Stats, error) {
	s := &Stats{
		DBPath:      d.path,
		DBSize:      d.FileSize(),
		SourceState: map[string]string{},
		ByYear:      map[int]int{},
		BySeverity:  map[string]int{},
	}
	counts := []struct {
		dst *int
		sql string
	}{
		{&s.CVEs, `SELECT count(*) FROM cve`},
		{&s.Enriched, `SELECT count(*) FROM cve WHERE enriched = 1`},
		{&s.Unenriched, `SELECT count(*) FROM cve WHERE enriched = 0`},
		{&s.Rejected, `SELECT count(*) FROM cve WHERE state = 'REJECTED'`},
		{&s.Reserved, `SELECT count(*) FROM cve WHERE state = 'RESERVED'`},
		{&s.KEV, `SELECT count(*) FROM cve WHERE kev = 1`},
		{&s.CPEMatches, `SELECT count(*) FROM cpe_match`},
		{&s.CVEProducts, `SELECT count(*) FROM cve_product`},
		{&s.CWECatalog, `SELECT count(*) FROM cwe`},
		{&s.Refs, `SELECT count(*) FROM cve_ref`},
		{&s.FTSRows, `SELECT count(*) FROM cve_fts`},
	}
	for _, c := range counts {
		if err := d.db.QueryRowContext(ctx, c.sql).Scan(c.dst); err != nil {
			return nil, fmt.Errorf("store: stats: %w", err)
		}
	}
	rows, err := d.db.QueryContext(ctx, `SELECT year, count(*) FROM cve GROUP BY year ORDER BY year`)
	if err != nil {
		return nil, fmt.Errorf("store: stats: %w", err)
	}
	for rows.Next() {
		var y, n int
		if err := rows.Scan(&y, &n); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: stats: %w", err)
		}
		s.ByYear[y] = n
	}
	rows.Close()
	rows, err = d.db.QueryContext(ctx,
		`SELECT best_sev, count(*) FROM cve GROUP BY best_sev ORDER BY best_sev`)
	if err != nil {
		return nil, fmt.Errorf("store: stats: %w", err)
	}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: stats: %w", err)
		}
		if sev == "" {
			sev = "unknown"
		}
		s.BySeverity[sev] = n
	}
	rows.Close()
	built, err := d.Meta(ctx, "built_at")
	if err != nil {
		return nil, err
	}
	s.BuiltAt = built
	sources, err := d.SourceState(ctx)
	if err != nil {
		return nil, err
	}
	s.SourceState = sources
	return s, nil
}

// validSeverities are the qualitative bands the store can filter on.
var validSeverities = map[string]bool{
	"none": true, "low": true, "medium": true, "high": true, "critical": true,
}

// ParseSeverity normalises one severity name, rejecting anything outside the
// stored vocabulary.
func ParseSeverity(s string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	if !validSeverities[v] {
		return "", fmt.Errorf("store: unknown severity %q (none, low, medium, high, critical)", s)
	}
	return v, nil
}

// ParseCVSSVersion maps a user-facing CVSS version ("v2", "v3.0", "v3.1",
// "v4.0", also accepting the column suffixes v30/v31/v40) to a column selector.
func ParseCVSSVersion(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "best":
		return "", nil
	case "v2", "2", "2.0":
		return model.VerV2, nil
	case "v3.0", "3.0", "v30":
		return model.VerV30, nil
	case "v3.1", "3.1", "v31":
		return model.VerV31, nil
	case "v4.0", "4.0", "v40", "v4":
		return model.VerV40, nil
	}
	return "", fmt.Errorf("store: unknown cvss version %q (v2, v3.0, v3.1, v4.0)", s)
}

// ParseYearRange parses "2024" or "2020-2024". An empty string means no filter.
func ParseYearRange(s string) (int, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, nil
	}
	if i := strings.IndexByte(s, '-'); i > 0 {
		from, err := strconv.Atoi(strings.TrimSpace(s[:i]))
		if err != nil {
			return 0, 0, fmt.Errorf("store: bad year range %q", s)
		}
		to, err := strconv.Atoi(strings.TrimSpace(s[i+1:]))
		if err != nil {
			return 0, 0, fmt.Errorf("store: bad year range %q", s)
		}
		if from > to {
			return 0, 0, fmt.Errorf("store: year range %q is backwards", s)
		}
		return from, to, nil
	}
	y, err := strconv.Atoi(s)
	if err != nil || y < 1999 || y > 3000 {
		return 0, 0, fmt.Errorf("store: bad year %q", s)
	}
	return y, y, nil
}
