//go:build unix

package ingest

import (
	"fmt"
	"syscall"
)

// checkFree fails when dir has less than want bytes available. An unreadable
// filesystem is not treated as a failure: the download itself will report.
func checkFree(dir string, want int64) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return nil
	}
	avail := int64(st.Bavail) * int64(st.Bsize)
	if avail < want {
		return fmt.Errorf("ingest: need %s free in %s, have %s",
			humanBytes(want), dir, humanBytes(avail))
	}
	return nil
}
