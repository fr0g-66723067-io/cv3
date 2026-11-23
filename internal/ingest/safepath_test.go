package ingest

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenInRefusesEscape(t *testing.T) {
	root := t.TempDir()
	if _, err := openIn(root, "../x", os.O_RDONLY, 0); err == nil {
		t.Fatal("openIn accepted a path escaping its root")
	}

	path := filepath.Join(root, "ok")
	f, err := createFile(path)
	if err != nil {
		t.Fatalf("createFile: %v", err)
	}
	if _, err := f.WriteString("hello"); err != nil {
		f.Close()
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	f, err = openFile(path)
	if err != nil {
		t.Fatalf("openFile: %v", err)
	}
	defer f.Close()
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("contents = %q", got)
	}
}

func TestCreateFileRefusesSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "target")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(root, "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if _, err := createFile(filepath.Join(root, "link")); err == nil {
		t.Fatal("createFile followed a symlink out of its directory")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(got) != "original" {
		t.Fatalf("target was modified: %q", got)
	}
}
