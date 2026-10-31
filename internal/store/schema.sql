PRAGMA user_version = 1;

CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;

CREATE TABLE cve (
  rowid INTEGER PRIMARY KEY,
  id TEXT NOT NULL UNIQUE,
  year INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'UNKNOWN',
  nvd_status TEXT NOT NULL DEFAULT '',
  published TEXT NOT NULL DEFAULT '', modified TEXT NOT NULL DEFAULT '',
  reserved TEXT NOT NULL DEFAULT '', assigner TEXT NOT NULL DEFAULT '',
  cna_title TEXT NOT NULL DEFAULT '',
  summary TEXT NOT NULL DEFAULT '', summary_src TEXT NOT NULL DEFAULT '',
  v2_score REAL,  v2_sev  TEXT NOT NULL DEFAULT '', v2_vec  TEXT NOT NULL DEFAULT '', v2_src  TEXT NOT NULL DEFAULT '',
  v30_score REAL, v30_sev TEXT NOT NULL DEFAULT '', v30_vec TEXT NOT NULL DEFAULT '', v30_src TEXT NOT NULL DEFAULT '',
  v31_score REAL, v31_sev TEXT NOT NULL DEFAULT '', v31_vec TEXT NOT NULL DEFAULT '', v31_src TEXT NOT NULL DEFAULT '',
  v40_score REAL, v40_sev TEXT NOT NULL DEFAULT '', v40_vec TEXT NOT NULL DEFAULT '', v40_src TEXT NOT NULL DEFAULT '',
  best_score REAL, best_sev TEXT NOT NULL DEFAULT '', best_ver TEXT NOT NULL DEFAULT '',
  kev INTEGER NOT NULL DEFAULT 0, kev_added TEXT NOT NULL DEFAULT '',
  kev_due TEXT NOT NULL DEFAULT '', kev_name TEXT NOT NULL DEFAULT '',
  kev_ransomware TEXT NOT NULL DEFAULT '',
  enriched INTEGER NOT NULL DEFAULT 0,
  cpe_count INTEGER NOT NULL DEFAULT 0, ref_count INTEGER NOT NULL DEFAULT 0,
  merged_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX cve_year ON cve(year);
CREATE INDEX cve_best_score ON cve(best_score);
CREATE INDEX cve_best_sev ON cve(best_sev, best_score);
CREATE INDEX cve_published ON cve(published);
CREATE INDEX cve_enriched ON cve(enriched);
CREATE INDEX cve_status ON cve(nvd_status);
CREATE INDEX cve_kev ON cve(kev) WHERE kev = 1;

CREATE VIRTUAL TABLE cve_fts USING fts5(
  summary, refs, products, tokenize = 'unicode61 remove_diacritics 2');

CREATE TABLE cpe_match (
  rowid INTEGER PRIMARY KEY,
  cve_id TEXT NOT NULL, criteria TEXT NOT NULL,
  part TEXT NOT NULL, vendor TEXT NOT NULL, product TEXT NOT NULL, version TEXT NOT NULL,
  update_ TEXT NOT NULL DEFAULT '', edition TEXT NOT NULL DEFAULT '', language TEXT NOT NULL DEFAULT '',
  sw_edition TEXT NOT NULL DEFAULT '', target_sw TEXT NOT NULL DEFAULT '',
  target_hw TEXT NOT NULL DEFAULT '', other TEXT NOT NULL DEFAULT '',
  vulnerable INTEGER NOT NULL DEFAULT 1, match_id TEXT NOT NULL DEFAULT '',
  start_incl TEXT NOT NULL DEFAULT '', start_excl TEXT NOT NULL DEFAULT '',
  end_incl TEXT NOT NULL DEFAULT '', end_excl TEXT NOT NULL DEFAULT '',
  src TEXT NOT NULL DEFAULT 'nvd'
);
CREATE INDEX cpe_match_cve ON cpe_match(cve_id);
CREATE INDEX cpe_match_part_vp ON cpe_match(part, vendor, product);
CREATE INDEX cpe_match_criteria ON cpe_match(criteria);

CREATE TABLE cve_product (
  cve_id TEXT NOT NULL, vendor TEXT NOT NULL, product TEXT NOT NULL,
  package_name TEXT NOT NULL DEFAULT '', versions TEXT NOT NULL DEFAULT '', src TEXT NOT NULL,
  PRIMARY KEY (cve_id, vendor, product, src)) WITHOUT ROWID;
CREATE INDEX cve_product_vp ON cve_product(vendor, product);

CREATE TABLE cve_cwe (
  cve_id TEXT NOT NULL, cwe_id TEXT NOT NULL, src TEXT NOT NULL,
  PRIMARY KEY (cve_id, cwe_id, src)) WITHOUT ROWID;
CREATE INDEX cve_cwe_cwe ON cve_cwe(cwe_id);

CREATE TABLE cve_ref (
  cve_id TEXT NOT NULL, url TEXT NOT NULL, tags TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL DEFAULT '', src TEXT NOT NULL, PRIMARY KEY (cve_id, url)) WITHOUT ROWID;

CREATE TABLE cwe (id TEXT PRIMARY KEY, name TEXT NOT NULL,
  abstraction TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '') WITHOUT ROWID;
CREATE TABLE cwe_parent (child TEXT NOT NULL, parent TEXT NOT NULL,
  nature TEXT NOT NULL DEFAULT '', PRIMARY KEY (child, parent)) WITHOUT ROWID;

CREATE TABLE source_state (source TEXT PRIMARY KEY, value TEXT NOT NULL,
  updated TEXT NOT NULL) WITHOUT ROWID;
