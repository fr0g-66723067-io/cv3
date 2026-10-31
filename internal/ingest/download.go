package ingest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Fetcher downloads upstream archives into a cache directory. Interrupted
// downloads resume with a Range request instead of restarting: the cvelistV5
// all-CVEs archive is 647 MB.
type Fetcher struct {
	Dir     string
	Retries int
	UA      string
	Client  *http.Client

	// Force ignores cached files and downloads every asset again. Reuse (the
	// default) turns an interrupted sync into a resumable one: the archives
	// already in the cache are not fetched a second time.
	Force bool

	// backoff is the delay before retry n; tests shrink it.
	backoff []time.Duration
}

func (f *Fetcher) client() *http.Client {
	if f.Client != nil {
		return f.Client
	}
	return &http.Client{Timeout: 30 * time.Minute}
}

func (f *Fetcher) ua() string {
	if f.UA != "" {
		return f.UA
	}
	return "cv3/1.0"
}

func (f *Fetcher) delays() []time.Duration {
	if len(f.backoff) > 0 {
		return f.backoff
	}
	return []time.Duration{2 * time.Second, 8 * time.Second, 30 * time.Second}
}

// Get downloads url to dest. Downloading into dest+".part" and renaming on
// success means a truncated file is never mistaken for a complete one.
func (f *Fetcher) Get(ctx context.Context, url, dest string, log io.Writer) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		return fmt.Errorf("ingest: fetch: %w", err)
	}
	if !f.Force {
		if fi, err := os.Stat(dest); err == nil && fi.Size() > 0 {
			if log != nil {
				fmt.Fprintf(log, "cv3: cached %s (%d bytes)\n", filepath.Base(dest), fi.Size())
			}
			return nil
		}
	}
	if log != nil {
		fmt.Fprintf(log, "cv3: downloading %s\n", url)
	}
	retries := max(1, f.Retries)
	delays := f.delays()
	var lastErr error
	for attempt := 1; attempt <= retries; attempt++ {
		if attempt > 1 && log != nil {
			fmt.Fprintf(log, "cv3: retry %d/%d %s: %v\n", attempt, retries, url, lastErr)
		}
		if err := f.getOnce(ctx, url, dest); err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return fmt.Errorf("ingest: fetch %s: %w", url, ctx.Err())
			}
			if attempt < retries {
				d := delays[min(attempt-1, len(delays)-1)]
				select {
				case <-ctx.Done():
					return fmt.Errorf("ingest: fetch %s: %w", url, ctx.Err())
				case <-time.After(d):
				}
			}
			continue
		}
		return nil
	}
	return fmt.Errorf("ingest: fetch %s: %w", url, lastErr)
}

func (f *Fetcher) getOnce(ctx context.Context, url, dest string) error {
	part := dest + ".part"
	fh, err := os.OpenFile(part, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("ingest: fetch: %w", err)
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil {
		return fmt.Errorf("ingest: fetch: %w", err)
	}
	offset := fi.Size()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("ingest: fetch: %w", err)
	}
	req.Header.Set("User-Agent", f.ua())
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return fmt.Errorf("ingest: fetch: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusPartialContent:
		// resumed: keep the bytes already on disk
	case resp.StatusCode == http.StatusOK:
		// Server ignored the Range header (or this is the first attempt):
		// restart from zero.
		if offset > 0 {
			if err := fh.Truncate(0); err != nil {
				return fmt.Errorf("ingest: fetch: %w", err)
			}
			if _, err := fh.Seek(0, io.SeekStart); err != nil {
				return fmt.Errorf("ingest: fetch: %w", err)
			}
		}
	default:
		return fmt.Errorf("ingest: fetch %s: HTTP %s", url, resp.Status)
	}
	if _, err := io.Copy(fh, resp.Body); err != nil {
		return fmt.Errorf("ingest: fetch: %w", err)
	}
	if err := fh.Sync(); err != nil {
		return fmt.Errorf("ingest: fetch: %w", err)
	}
	if err := fh.Close(); err != nil {
		return fmt.Errorf("ingest: fetch: %w", err)
	}
	if err := os.Rename(part, dest); err != nil {
		return fmt.Errorf("ingest: fetch: %w", err)
	}
	return nil
}
