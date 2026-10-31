// Package store owns the SQLite database behind cv3: schema creation, the
// merge-on-write path that keeps cvelistV5 and NVD records coherent, the FTS5
// index, and every read query.
//
// Two connection profiles exist. Create uses a no-journal, no-sync profile
// because it builds a brand new file that is renamed into place; Open(full) is
// the incremental-update profile and is crash safe; Open(read) is the query
// profile and cannot write at all. That split is what makes an interrupted sync
// harmless: the live file is never the one being written.
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	_ "modernc.org/sqlite"
)

// SchemaVersion is the version recorded in meta.schema_version.
const SchemaVersion = 1

//go:embed schema.sql
var schemaSQL string

// ErrNotFound is returned by the single-record lookups.
var ErrNotFound = errors.New("store: not found")

// DB is a handle on a cv3 database file. Read queries are safe for concurrent
// use; write methods must be called from a single goroutine at a time.
type DB struct {
	db   *sql.DB
	path string
	ro   bool
}

// Create builds a new database at path with the bulk-load profile: no journal,
// no fsync, memory temp store. It fails when path already exists so a sync can
// never write into a live database by accident.
func Create(path string) (*DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("store: create: %w", err)
	}
	if _, err := os.Stat(abs); err == nil {
		return nil, fmt.Errorf("store: create: %s already exists", abs)
	}
	if dir := filepath.Dir(abs); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("store: create: %w", err)
		}
	}
	dsn := fileDSN(abs) + "?_txlock=immediate" +
		"&_pragma=journal_mode(OFF)" +
		"&_pragma=synchronous(OFF)" +
		"&_pragma=temp_store(MEMORY)" +
		"&_pragma=cache_size(-262144)" +
		"&_pragma=page_size(8192)" +
		"&_pragma=mmap_size(268435456)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: create: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: create: %w", err)
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: create: applying schema: %w", err)
	}
	d := &DB{db: db, path: abs}
	if err := d.SetMeta(context.Background(), "schema_version", fmt.Sprint(SchemaVersion)); err != nil {
		db.Close()
		return nil, err
	}
	return d, nil
}

// Open opens an existing database. ro selects the read-only profile, which is
// what every query surface uses; the read-write profile is the incremental
// update path (journal and full sync enabled).
func Open(path string, ro bool) (*DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	if _, err := os.Stat(abs); err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	var dsn string
	if ro {
		dsn = fileDSN(abs) + "?mode=ro" +
			"&_pragma=query_only(1)" +
			"&_pragma=busy_timeout(5000)" +
			"&_pragma=mmap_size(268435456)" +
			"&_pragma=temp_store(MEMORY)"
	} else {
		dsn = fileDSN(abs) + "?_txlock=immediate" +
			"&_pragma=journal_mode(DELETE)" +
			"&_pragma=synchronous(FULL)" +
			"&_pragma=busy_timeout(5000)" +
			"&_pragma=temp_store(MEMORY)" +
			"&_pragma=mmap_size(268435456)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	if ro {
		db.SetMaxOpenConns(max(1, runtime.NumCPU()))
	} else {
		db.SetMaxOpenConns(1)
	}
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: open %s: %w", abs, err)
	}
	d := &DB{db: db, path: abs, ro: ro}
	if err := d.checkVersion(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return d, nil
}

// fileDSN renders an absolute path as a file: URI. Paths with spaces or other
// characters that the sqlite DSN parser would otherwise mis-read stay intact.
func fileDSN(abs string) string {
	return (&url.URL{Scheme: "file", Path: abs}).String()
}

// checkVersion rejects databases written by a newer binary.
func (d *DB) checkVersion(ctx context.Context) error {
	got, err := d.Meta(ctx, "schema_version")
	if err != nil {
		return err
	}
	if got == "" {
		return fmt.Errorf("store: %s: not a cv3 database (no schema_version)", d.path)
	}
	if got != fmt.Sprint(SchemaVersion) {
		return fmt.Errorf("store: %s: schema_version %s, this binary speaks %d",
			d.path, got, SchemaVersion)
	}
	return nil
}

// Close releases the handle.
func (d *DB) Close() error { return d.db.Close() }

// Path is the absolute database path.
func (d *DB) Path() string { return d.path }

// SQL exposes the underlying handle for counter queries in the ingest layer.
// Query surfaces use the typed methods instead.
func (d *DB) SQL() *sql.DB { return d.db }

// Ping reports whether the database answers.
func (d *DB) Ping(ctx context.Context) error { return d.db.PingContext(ctx) }

// Meta reads a meta value; a missing key yields "".
func (d *DB) Meta(ctx context.Context, key string) (string, error) {
	var v string
	err := d.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store: meta %s: %w", key, err)
	}
	return v, nil
}

// SetMeta writes a meta value.
func (d *DB) SetMeta(ctx context.Context, key, value string) error {
	_, err := d.db.ExecContext(ctx,
		`INSERT INTO meta(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	if err != nil {
		return fmt.Errorf("store: set meta %s: %w", key, err)
	}
	return nil
}

// SetSourceState records the watermark of one upstream source.
func (d *DB) SetSourceState(ctx context.Context, source, value string) error {
	_, err := d.db.ExecContext(ctx,
		`INSERT INTO source_state(source, value, updated) VALUES(?, ?, ?)
		 ON CONFLICT(source) DO UPDATE SET value = excluded.value, updated = excluded.updated`,
		source, value, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("store: source state %s: %w", source, err)
	}
	return nil
}

// SourceState reads every source watermark.
func (d *DB) SourceState(ctx context.Context) (map[string]string, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT source, value FROM source_state ORDER BY source`)
	if err != nil {
		return nil, fmt.Errorf("store: source state: %w", err)
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("store: source state: %w", err)
		}
		out[k] = v
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: source state: %w", err)
	}
	return out, nil
}

// FileSize reports the size of the database file, or 0 when it cannot be
// stat'ed.
func (d *DB) FileSize() int64 {
	fi, err := os.Stat(d.path)
	if err != nil {
		return 0
	}
	return fi.Size()
}
