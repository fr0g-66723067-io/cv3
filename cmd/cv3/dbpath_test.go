package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/cv3/internal/store/storetest"
)

func TestResolveDBPrecedence(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	xdg := filepath.Join(root, "xdg")
	work := filepath.Join(root, "work")
	for _, dir := range []string{home, xdg, filepath.Join(work, "data")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", xdg)
	t.Setenv("CV3_DB", "")
	t.Chdir(work)

	localDB := filepath.Join(work, "data", "cv3.db")
	xdgDB := filepath.Join(xdg, "cv3", "cv3.db")

	// No project database yet: the XDG data directory wins over the home
	// fallback.
	got, err := resolveDB("")
	if err != nil {
		t.Fatalf("resolveDB: %v", err)
	}
	if got != xdgDB {
		t.Fatalf("resolveDB() = %q, want %q", got, xdgDB)
	}

	// A synced checkout wins over XDG.
	if err := os.WriteFile(localDB, []byte("db"), 0o644); err != nil {
		t.Fatalf("write local db: %v", err)
	}
	got, err = resolveDB("")
	if err != nil {
		t.Fatalf("resolveDB: %v", err)
	}
	if got != localDB {
		t.Fatalf("resolveDB() = %q, want %q", got, localDB)
	}

	// CV3_DB wins over the project database.
	t.Setenv("CV3_DB", filepath.Join(root, "env", "cv3.db"))
	want := filepath.Join(root, "env", "cv3.db")
	got, err = resolveDB("")
	if err != nil {
		t.Fatalf("resolveDB: %v", err)
	}
	if got != want {
		t.Fatalf("resolveDB() = %q, want %q", got, want)
	}

	// The flag wins over everything.
	flagPath := filepath.Join(root, "flag", "cv3.db")
	got, err = resolveDB(flagPath)
	if err != nil {
		t.Fatalf("resolveDB: %v", err)
	}
	if got != flagPath {
		t.Fatalf("resolveDB(flag) = %q, want %q", got, flagPath)
	}

	// Without XDG the home data directory is the fallback.
	t.Setenv("CV3_DB", "")
	t.Setenv("XDG_DATA_HOME", "")
	if err := os.Remove(localDB); err != nil {
		t.Fatalf("remove local db: %v", err)
	}
	got, err = resolveDB("")
	if err != nil {
		t.Fatalf("resolveDB: %v", err)
	}
	if wantHome := filepath.Join(home, ".local", "share", "cv3", "cv3.db"); got != wantHome {
		t.Fatalf("resolveDB() = %q, want %q", got, wantHome)
	}
}

// TestStatsWithoutFlagsFindsProjectDatabase is the behaviour the Makefile and
// README promise: after `cv3 sync` in a checkout, `cv3 stats` needs no -db.
func TestStatsWithoutFlagsFindsProjectDatabase(t *testing.T) {
	work := t.TempDir()
	db := storetest.BuildAt(t, filepath.Join(work, "data", "cv3.db"))
	t.Chdir(work)
	t.Setenv("CV3_DB", "")
	t.Setenv("XDG_DATA_HOME", filepath.Join(work, "xdg"))

	code, stdout, stderr := runCLI("stats")
	if code != exitOK {
		t.Fatalf("stats exit = %d (stderr %s)", code, stderr)
	}
	if !containsLine(stdout, db) {
		t.Fatalf("stats did not report %q:\n%s", db, stdout)
	}
}

func containsLine(out, sub string) bool { return strings.Contains(out, sub) }
