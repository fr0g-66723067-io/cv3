//go:build !unix

package ingest

// checkFree is a no-op where syscall.Statfs does not exist (Windows). The guard
// is a courtesy: a short disk still fails on the first write with the OS error,
// only later. minimumFree stays the documented requirement in README and doc.go.
func checkFree(dir string, want int64) error { return nil }
