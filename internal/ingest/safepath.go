package ingest

import (
	"os"
	"path/filepath"
)

// openIn opens name beneath dir through os.Root. The root refuses ".."
// components and symlinks that would leave dir, so a cache entry can never
// redirect a read or write outside the directory it belongs to.
func openIn(dir, name string, flag int, perm os.FileMode) (*os.File, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.OpenFile(name, flag, perm)
}

// openFile opens path anchored at its own directory.
func openFile(path string) (*os.File, error) {
	return openIn(filepath.Dir(path), filepath.Base(path), os.O_RDONLY, 0)
}

// createFile creates or truncates path anchored at its own directory.
func createFile(path string) (*os.File, error) {
	return openIn(filepath.Dir(path), filepath.Base(path), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o666)
}
