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
	for _, dir := range []string{home, xdg, work} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", xdg)
	t.Setenv("CV3_DB", "")
	t.Chdir(work)

	xdgDB := filepath.Join(xdg, "cv3", "cv3.db")
	got, err := resolveDB("")
	if err != nil {
		t.Fatalf("resolveDB: %v", err)
	}
	if got != xdgDB {
		t.Fatalf("resolveDB() = %q, want %q", got, xdgDB)
	}

	// A database in the working directory is not a default: the path the code
	// expects is the one `make install` provisions.
	if err := os.MkdirAll(filepath.Join(work, "data"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(work, "data", "cv3.db"), []byte("db"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err = resolveDB("")
	if err != nil {
		t.Fatalf("resolveDB: %v", err)
	}
	if got != xdgDB {
		t.Fatalf("resolveDB() = %q, want %q (cwd database must not win)", got, xdgDB)
	}

	// $CV3_DB wins over the default.
	envDB := filepath.Join(root, "env", "cv3.db")
	t.Setenv("CV3_DB", envDB)
	if got, err = resolveDB(""); err != nil || got != envDB {
		t.Fatalf("resolveDB() = %q, %v; want %q", got, err, envDB)
	}

	// The flag wins over everything.
	flagDB := filepath.Join(root, "flag", "cv3.db")
	if got, err = resolveDB(flagDB); err != nil || got != flagDB {
		t.Fatalf("resolveDB(flag) = %q, %v; want %q", got, err, flagDB)
	}

	// Without XDG_DATA_HOME the home data directory is the default.
	t.Setenv("CV3_DB", "")
	t.Setenv("XDG_DATA_HOME", "")
	if got, err = resolveDB(""); err != nil {
		t.Fatalf("resolveDB: %v", err)
	}
	if want := filepath.Join(home, ".local", "share", "cv3", "cv3.db"); got != want {
		t.Fatalf("resolveDB() = %q, want %q", got, want)
	}
}

// TestStatsWithoutFlagsUsesInstalledDefault is the contract `make install`
// promises: the database lives at the resolved default, so a bare `cv3 stats`
// finds it from any working directory.
func TestStatsWithoutFlagsUsesInstalledDefault(t *testing.T) {
	root := t.TempDir()
	xdg := filepath.Join(root, "xdg")
	work := filepath.Join(root, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Setenv("XDG_DATA_HOME", xdg)
	t.Setenv("CV3_DB", "")
	db := storetest.BuildAt(t, filepath.Join(xdg, "cv3", "cv3.db"))
	t.Chdir(work)

	code, stdout, stderr := runCLI("stats")
	if code != exitOK {
		t.Fatalf("stats exit = %d (stderr %s)", code, stderr)
	}
	if !strings.Contains(stdout, db) {
		t.Fatalf("stats did not report %q:\n%s", db, stdout)
	}
}
