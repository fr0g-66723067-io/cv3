package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fr0g-66723067-io/cv3/internal/cvss"
	"github.com/fr0g-66723067-io/cv3/internal/model"
)

// versionPreference orders CVSS versions for the representative score: the
// highest version present wins, so -severity and -min-score mean the same thing
// for every row.
var versionPreference = []string{model.VerV40, model.VerV31, model.VerV30, model.VerV2}

// pickBest returns the representative CVSS version, score and severity.
func pickBest(metrics map[string]model.Metric) (version string, score *float64, severity string) {
	for _, v := range versionPreference {
		m, ok := metrics[v]
		if !ok {
			continue
		}
		s := m.Score
		sev := strings.ToLower(strings.TrimSpace(m.Severity))
		if sev == "" {
			sev = cvss.SeverityOf(v, s)
		}
		return v, &s, sev
	}
	return "", nil, ""
}

// rowSnap is the part of a stored row the merge needs. Dependent rows are not
// loaded: they are replaced per source, never merged field by field.
type rowSnap struct {
	state, assigner, reserved, cnaTitle string
	summary, summarySrc                 string
	published, modified, nvdStatus      string
	metrics                             map[string]model.Metric
	enriched                            bool
}

// Tx is a write transaction. All write statements are prepared once per
// transaction and reused, so batch writers pay the prepare cost once per batch.
type Tx struct {
	tx    *sql.Tx
	stmts *txStmts
}

type txStmts struct {
	selSnap   *sql.Stmt
	upsert    *sql.Stmt
	updCounts *sql.Stmt
	delCpe    *sql.Stmt
	insCpe    *sql.Stmt
	delCwe    *sql.Stmt
	insCwe    *sql.Stmt
	delProd   *sql.Stmt
	insProd   *sql.Stmt
	delRef    *sql.Stmt
	insRef    *sql.Stmt
	delFts    *sql.Stmt
	insFts    *sql.Stmt
	putCwe    *sql.Stmt
	delParent *sql.Stmt
	insParent *sql.Stmt
}

const cveColumns = `id, year, state, nvd_status, published, modified, reserved, assigner,
	cna_title, summary, summary_src,
	v2_score, v2_sev, v2_vec, v2_src,
	v30_score, v30_sev, v30_vec, v30_src,
	v31_score, v31_sev, v31_vec, v31_src,
	v40_score, v40_sev, v40_vec, v40_src,
	best_score, best_sev, best_ver,
	kev, kev_added, kev_due, kev_name, kev_ransomware,
	enriched, cpe_count, ref_count, merged_at`

// cveUpsertSQL writes the whole row and overwrites every column on conflict.
// The merge decision is made in Go (mergeCVE) rather than in SQL CASE
// expressions: sixteen metric columns and two timestamp rules are far easier to
// get right once, in code, than repeated in the statement.
var cveUpsertSQL = `INSERT INTO cve (` + cveColumns + `) VALUES (` +
	strings.TrimSuffix(strings.Repeat("?,", 39), ",") + `)
ON CONFLICT(id) DO UPDATE SET
  year=excluded.year, state=excluded.state, nvd_status=excluded.nvd_status,
  published=excluded.published, modified=excluded.modified, reserved=excluded.reserved,
  assigner=excluded.assigner, cna_title=excluded.cna_title,
  summary=excluded.summary, summary_src=excluded.summary_src,
  v2_score=excluded.v2_score, v2_sev=excluded.v2_sev, v2_vec=excluded.v2_vec, v2_src=excluded.v2_src,
  v30_score=excluded.v30_score, v30_sev=excluded.v30_sev, v30_vec=excluded.v30_vec, v30_src=excluded.v30_src,
  v31_score=excluded.v31_score, v31_sev=excluded.v31_sev, v31_vec=excluded.v31_vec, v31_src=excluded.v31_src,
  v40_score=excluded.v40_score, v40_sev=excluded.v40_sev, v40_vec=excluded.v40_vec, v40_src=excluded.v40_src,
  best_score=excluded.best_score, best_sev=excluded.best_sev, best_ver=excluded.best_ver,
  kev=excluded.kev, kev_added=excluded.kev_added, kev_due=excluded.kev_due,
  kev_name=excluded.kev_name, kev_ransomware=excluded.kev_ransomware,
  enriched=excluded.enriched, cpe_count=excluded.cpe_count, ref_count=excluded.ref_count,
  merged_at=excluded.merged_at`

// ftsRowSQL is the single-row form of the bulk FTS projection: summary from the
// row, every reference URL, and the distinct vendor/product pairs. It runs after
// the dependent rows are written.
const ftsRowSQL = `INSERT INTO cve_fts(rowid, summary, refs, products)
SELECT c.rowid, c.summary,
  COALESCE((SELECT group_concat(r.url, ' ') FROM cve_ref r WHERE r.cve_id = c.id), ''),
  COALESCE((SELECT group_concat(DISTINCT m.vendor || ' ' || m.product)
              FROM cpe_match m WHERE m.cve_id = c.id
               AND m.vendor NOT IN ('*', '-') AND m.product NOT IN ('*', '-')), '')
FROM cve c WHERE c.id = ?`

// ftsBulkSQL is the whole-corpus projection used once at the end of a full sync.
const ftsBulkSQL = `INSERT INTO cve_fts(rowid, summary, refs, products)
SELECT c.rowid, c.summary,
  COALESCE((SELECT group_concat(r.url, ' ') FROM cve_ref r WHERE r.cve_id = c.id), ''),
  COALESCE((SELECT group_concat(DISTINCT m.vendor || ' ' || m.product)
              FROM cpe_match m WHERE m.cve_id = c.id
               AND m.vendor NOT IN ('*', '-') AND m.product NOT IN ('*', '-')), '')
FROM cve c`

// InTx runs fn in a write transaction, rolling back on error.
func (d *DB) InTx(ctx context.Context, fn func(*Tx) error) error {
	if d.ro {
		return errors.New("store: database opened read-only")
	}
	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	t := &Tx{tx: tx}
	if err := t.prepare(); err != nil {
		tx.Rollback()
		return err
	}
	if err := fn(t); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

func (t *Tx) prepare() error {
	t.stmts = &txStmts{}
	targets := []struct {
		dst **sql.Stmt
		sql string
	}{
		{&t.stmts.selSnap, `SELECT state, assigner, reserved, cna_title, summary, summary_src,
			published, modified, nvd_status, enriched,
			v2_score, v2_sev, v2_vec, v2_src,
			v30_score, v30_sev, v30_vec, v30_src,
			v31_score, v31_sev, v31_vec, v31_src,
			v40_score, v40_sev, v40_vec, v40_src
			FROM cve WHERE id = ?`},
		{&t.stmts.upsert, cveUpsertSQL},
		{&t.stmts.updCounts, `UPDATE cve SET
			cpe_count = (SELECT count(*) FROM cpe_match WHERE cve_id = cve.id),
			ref_count = (SELECT count(*) FROM cve_ref WHERE cve_id = cve.id)
			WHERE id = ?`},
		{&t.stmts.delCpe, `DELETE FROM cpe_match WHERE cve_id = ? AND src IN (?, ?, ?)`},
		{&t.stmts.insCpe, `INSERT INTO cpe_match (
			cve_id, criteria, part, vendor, product, version, update_, edition, language,
			sw_edition, target_sw, target_hw, other, vulnerable, match_id,
			start_incl, start_excl, end_incl, end_excl, src)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`},
		{&t.stmts.delCwe, `DELETE FROM cve_cwe WHERE cve_id = ? AND src IN (?, ?, ?)`},
		{&t.stmts.insCwe, `INSERT OR IGNORE INTO cve_cwe (cve_id, cwe_id, src) VALUES (?, ?, ?)`},
		{&t.stmts.delProd, `DELETE FROM cve_product WHERE cve_id = ? AND src IN (?, ?, ?)`},
		{&t.stmts.insProd, `INSERT OR REPLACE INTO cve_product
			(cve_id, vendor, product, package_name, versions, src) VALUES (?, ?, ?, ?, ?, ?)`},
		{&t.stmts.delRef, `DELETE FROM cve_ref WHERE cve_id = ? AND src IN (?, ?, ?)`},
		{&t.stmts.insRef, `INSERT INTO cve_ref (cve_id, url, tags, name, src) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(cve_id, url) DO UPDATE SET
				src = CASE WHEN excluded.src = 'nvd' AND cve_ref.src != 'nvd' THEN 'nvd' ELSE cve_ref.src END,
				tags = CASE WHEN excluded.tags = '' THEN cve_ref.tags ELSE excluded.tags || ',' || cve_ref.tags END,
				name = CASE WHEN excluded.name = '' THEN cve_ref.name ELSE excluded.name END`},
		{&t.stmts.delFts, `DELETE FROM cve_fts WHERE rowid IN (SELECT rowid FROM cve WHERE id = ?)`},
		{&t.stmts.insFts, ftsRowSQL},
		{&t.stmts.putCwe, `INSERT INTO cwe (id, name, abstraction, status, description)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET name=excluded.name, abstraction=excluded.abstraction,
				status=excluded.status, description=excluded.description`},
		{&t.stmts.delParent, `DELETE FROM cwe_parent WHERE child = ?`},
		{&t.stmts.insParent, `INSERT OR IGNORE INTO cwe_parent (child, parent, nature) VALUES (?, ?, 'ChildOf')`},
	}
	for _, tgt := range targets {
		s, err := t.tx.Prepare(tgt.sql)
		if err != nil {
			return fmt.Errorf("store: prepare: %w", err)
		}
		*tgt.dst = s
	}
	return nil
}

// UpsertCVE writes one merged record in its own transaction. Batch writers
// should use InTx and Tx.UpsertCVE to amortise the commit.
func (d *DB) UpsertCVE(ctx context.Context, c *model.CVE) error {
	return d.InTx(ctx, func(t *Tx) error { return t.UpsertCVE(ctx, c) })
}

// UpsertCVEAll writes a batch of records in one transaction.
func (d *DB) UpsertCVEAll(ctx context.Context, cves []*model.CVE) error {
	return d.InTx(ctx, func(t *Tx) error {
		for _, c := range cves {
			if err := t.UpsertCVE(ctx, c); err != nil {
				return err
			}
		}
		return nil
	})
}

// UpsertCVE merges c into any stored row with the same id and replaces the
// dependent rows owned by c's sources.
func (t *Tx) UpsertCVE(ctx context.Context, c *model.CVE) error {
	if c == nil || c.ID == "" {
		return errors.New("store: upsert: record without id")
	}
	old, err := t.loadSnap(ctx, c.ID)
	if err != nil {
		return err
	}
	merged := mergeCVE(old, c)
	version, score, severity := pickBest(merged.Metrics)

	args, err := cveArgs(merged, version, score, severity)
	if err != nil {
		return err
	}
	if _, err := t.stmts.upsert.ExecContext(ctx, args...); err != nil {
		return fmt.Errorf("store: upsert %s: %w", c.ID, err)
	}

	sources := dependentSources(c)
	slots := sourceSlots(sources)
	for _, s := range []*sql.Stmt{t.stmts.delCpe, t.stmts.delCwe, t.stmts.delProd, t.stmts.delRef} {
		if _, err := s.ExecContext(ctx, c.ID, slots[0], slots[1], slots[2]); err != nil {
			return fmt.Errorf("store: upsert %s: clearing dependents: %w", c.ID, err)
		}
	}

	for _, m := range c.CPEs {
		n := m.Name
		if _, err := t.stmts.insCpe.ExecContext(ctx,
			c.ID, m.Criteria, n.Part, n.Vendor, n.Product, n.Version,
			n.Update, n.Edition, n.Language, n.SwEdition, n.TargetSw, n.TargetHw, n.Other,
			boolInt(m.Vulnerable), m.MatchID,
			m.StartIncl, m.StartExcl, m.EndIncl, m.EndExcl, m.Source); err != nil {
			return fmt.Errorf("store: upsert %s: cpe %s: %w", c.ID, m.Criteria, err)
		}
	}
	for _, w := range c.CWEs {
		if _, err := t.stmts.insCwe.ExecContext(ctx, c.ID, w.ID, w.Source); err != nil {
			return fmt.Errorf("store: upsert %s: cwe %s: %w", c.ID, w.ID, err)
		}
	}
	for _, p := range c.Products {
		if _, err := t.stmts.insProd.ExecContext(ctx,
			c.ID, strings.ToLower(p.Vendor), strings.ToLower(p.Product),
			p.PackageName, p.Versions, p.Source); err != nil {
			return fmt.Errorf("store: upsert %s: product %s/%s: %w", c.ID, p.Vendor, p.Product, err)
		}
	}
	refSource := "cna"
	if c.Enriched {
		refSource = "nvd"
	}
	for _, r := range c.Refs {
		if r.URL == "" {
			continue
		}
		if _, err := t.stmts.insRef.ExecContext(ctx, c.ID, r.URL, r.Tags, r.Name, refSource); err != nil {
			return fmt.Errorf("store: upsert %s: ref %s: %w", c.ID, r.URL, err)
		}
	}
	if _, err := t.stmts.updCounts.ExecContext(ctx, c.ID); err != nil {
		return fmt.Errorf("store: upsert %s: counters: %w", c.ID, err)
	}
	if err := t.refreshFTS(ctx, c.ID); err != nil {
		return err
	}
	return nil
}

func (t *Tx) refreshFTS(ctx context.Context, id string) error {
	if _, err := t.stmts.delFts.ExecContext(ctx, id); err != nil {
		return fmt.Errorf("store: fts delete %s: %w", id, err)
	}
	if _, err := t.stmts.insFts.ExecContext(ctx, id); err != nil {
		return fmt.Errorf("store: fts insert %s: %w", id, err)
	}
	return nil
}

// loadSnap reads the merge-relevant columns; a missing row yields (nil, nil).
func (t *Tx) loadSnap(ctx context.Context, id string) (*rowSnap, error) {
	var (
		s                                      rowSnap
		v2s, v2v, v2src, v30s, v30v, v30src    sql.NullString
		v31s, v31v, v31src, v40s, v40v, v40src sql.NullString
		v2sc, v30sc, v31sc, v40sc              sql.NullFloat64
		enriched                               int
	)
	err := t.stmts.selSnap.QueryRowContext(ctx, id).Scan(
		&s.state, &s.assigner, &s.reserved, &s.cnaTitle, &s.summary, &s.summarySrc,
		&s.published, &s.modified, &s.nvdStatus, &enriched,
		&v2sc, &v2s, &v2v, &v2src,
		&v30sc, &v30s, &v30v, &v30src,
		&v31sc, &v31s, &v31v, &v31src,
		&v40sc, &v40s, &v40v, &v40src,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: load %s: %w", id, err)
	}
	s.enriched = enriched != 0
	s.metrics = map[string]model.Metric{}
	addMetric := func(ver string, sc sql.NullFloat64, sev, vec, src sql.NullString) {
		if !sc.Valid {
			return
		}
		s.metrics[ver] = model.Metric{Score: sc.Float64, Severity: sev.String, Vector: vec.String, Source: src.String}
	}
	addMetric(model.VerV2, v2sc, v2s, v2v, v2src)
	addMetric(model.VerV30, v30sc, v30s, v30v, v30src)
	addMetric(model.VerV31, v31sc, v31s, v31v, v31src)
	addMetric(model.VerV40, v40sc, v40s, v40v, v40src)
	return &s, nil
}

// mergeCVE applies the source precedence rules documented in the package doc.
func mergeCVE(old *rowSnap, in *model.CVE) *model.CVE {
	out := *in
	out.Metrics = make(map[string]model.Metric, len(in.Metrics))
	for v, m := range in.Metrics {
		out.Metrics[v] = m
	}
	if old == nil {
		return &out
	}
	// A lower-ranked stored metric never replaces the incoming one, so
	// re-applying a cvelistV5 record cannot downgrade NVD data.
	for v, m := range old.metrics {
		cur, ok := out.Metrics[v]
		if !ok || m.Rank() > cur.Rank() {
			out.Metrics[v] = m
		}
	}
	if old.state != "" && old.state != "UNKNOWN" {
		out.State = old.state
	}
	if out.State == "" {
		out.State = "UNKNOWN"
	}
	if old.assigner != "" {
		out.Assigner = old.assigner
	}
	if old.reserved != "" {
		out.Reserved = old.reserved
	}
	if out.CNATitle == "" {
		out.CNATitle = old.cnaTitle
	}
	switch {
	case in.Summary != "" && in.SummarySrc == "nvd":
		// incoming NVD description wins, already in place
	case old.summarySrc == "nvd":
		out.Summary, out.SummarySrc = old.summary, old.summarySrc
	case in.Summary == "":
		out.Summary, out.SummarySrc = old.summary, old.summarySrc
	}
	switch {
	case in.Enriched:
		if in.Published == "" {
			out.Published = old.published
		}
		if in.Modified == "" {
			out.Modified = old.modified
		}
	case old.enriched:
		out.Published, out.Modified = old.published, old.modified
	default:
		if in.Published == "" {
			out.Published = old.published
		}
		if in.Modified == "" {
			out.Modified = old.modified
		}
	}
	if in.NVDStatus == "" {
		out.NVDStatus = old.nvdStatus
	}
	out.Enriched = in.Enriched || old.enriched
	return &out
}

// dependentSources is the set of dependent-row sources the incoming record
// owns. Anything outside it (typically the other upstream) is preserved.
func dependentSources(c *model.CVE) map[string]bool {
	src := map[string]bool{}
	for _, m := range c.CPEs {
		src[m.Source] = true
	}
	for _, w := range c.CWEs {
		src[w.Source] = true
	}
	for _, p := range c.Products {
		src[p.Source] = true
	}
	if len(c.Refs) > 0 {
		if c.Enriched {
			src["nvd"] = true
		} else {
			src["cna"] = true
		}
	}
	if len(src) == 0 {
		if c.Enriched {
			src["nvd"] = true
		} else {
			src["cna"] = true
			src["adp"] = true
		}
	}
	return src
}

// sourceSlots packs the source set into the three placeholders of the dependent
// delete statements. Unused slots carry an empty string, which no row can hold.
func sourceSlots(set map[string]bool) [3]string {
	var out [3]string
	i := 0
	for _, name := range []string{"nvd", "cna", "adp"} {
		if set[name] {
			out[i] = name
			i++
		}
	}
	return out
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// cveArgs flattens a merged record into the upsert's placeholder order.
func cveArgs(c *model.CVE, bestVersion string, bestScore *float64, bestSeverity string) ([]any, error) {
	year := c.Year
	if year == 0 {
		y, ok := yearOf(c.ID)
		if !ok {
			return nil, fmt.Errorf("store: upsert %s: cannot derive year", c.ID)
		}
		year = y
	}
	args := make([]any, 0, 39)
	args = append(args, c.ID, year, c.State, c.NVDStatus, c.Published, c.Modified,
		c.Reserved, c.Assigner, c.CNATitle, c.Summary, c.SummarySrc)
	for _, v := range []string{model.VerV2, model.VerV30, model.VerV31, model.VerV40} {
		m, ok := c.Metrics[v]
		if !ok {
			args = append(args, nil, "", "", "")
			continue
		}
		args = append(args, m.Score, strings.ToLower(m.Severity), m.Vector, m.Source)
	}
	args = append(args, bestScore, bestSeverity, bestVersion)
	var kev model.KEV
	if c.KEV != nil {
		kev = *c.KEV
	}
	args = append(args, boolInt(c.KEV != nil), kev.Added, kev.Due, kev.Name, kev.Ransomware)
	args = append(args, boolInt(c.Enriched), 0, 0, time.Now().UTC().Format(time.RFC3339))
	return args, nil
}

// yearOf extracts the year component of a CVE id.
func yearOf(id string) (int, bool) {
	if !strings.HasPrefix(id, "CVE-") || len(id) < 10 {
		return 0, false
	}
	y := id[4:8]
	n := 0
	for _, r := range y {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}

// PutCWE writes one CWE catalog entry and its parents.
func (t *Tx) PutCWE(ctx context.Context, c *model.CWE) error {
	if c == nil || c.ID == "" {
		return errors.New("store: put cwe: entry without id")
	}
	if _, err := t.stmts.putCwe.ExecContext(ctx, c.ID, c.Name, c.Abstraction, c.Status, c.Description); err != nil {
		return fmt.Errorf("store: put cwe %s: %w", c.ID, err)
	}
	if _, err := t.stmts.delParent.ExecContext(ctx, c.ID); err != nil {
		return fmt.Errorf("store: put cwe %s: parents: %w", c.ID, err)
	}
	for _, p := range c.Parents {
		if _, err := t.stmts.insParent.ExecContext(ctx, c.ID, p); err != nil {
			return fmt.Errorf("store: put cwe %s: parent %s: %w", c.ID, p, err)
		}
	}
	return nil
}

// PutCWE writes one CWE entry in its own transaction.
func (d *DB) PutCWE(ctx context.Context, c *model.CWE) error {
	return d.InTx(ctx, func(t *Tx) error { return t.PutCWE(ctx, c) })
}

// PutCWEAll writes a batch of CWE entries in one transaction.
func (d *DB) PutCWEAll(ctx context.Context, entries []*model.CWE) error {
	return d.InTx(ctx, func(t *Tx) error {
		for _, c := range entries {
			if err := t.PutCWE(ctx, c); err != nil {
				return err
			}
		}
		return nil
	})
}

// BuildDerived rebuilds the full-text index from scratch and refreshes the
// query planner statistics. It runs once at the end of a full sync.
func (d *DB) BuildDerived(ctx context.Context) error {
	steps := []string{
		`DELETE FROM cve_fts`,
		ftsBulkSQL,
		`ANALYZE`,
		`PRAGMA optimize`,
	}
	for _, s := range steps {
		if _, err := d.db.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("store: build derived: %w", err)
		}
	}
	return nil
}

// RefreshDerived rebuilds the FTS row of each id; used by the incremental
// update path after record upserts.
func (d *DB) RefreshDerived(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	return d.InTx(ctx, func(t *Tx) error {
		for _, id := range ids {
			if err := t.refreshFTS(ctx, id); err != nil {
				return err
			}
		}
		return nil
	})
}
