package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/fr0g-66723067-io/cv3/internal/model"
	"github.com/fr0g-66723067-io/cv3/internal/report"
	"github.com/fr0g-66723067-io/cv3/internal/store"
)

func runGet(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("get")
	db := fs.String("db", "", "database path")
	jsonOut := fs.Bool("json", false, "emit JSON")

	flags, ids := splitArgs(fs, args)
	if status, ok := parseFlags(fs, flags, stdout, stderr); !ok {
		return status
	}
	if len(ids) == 0 {
		fmt.Fprintln(stderr, "cv3: get needs at least one CVE id")
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	for _, id := range ids {
		if !strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			return fail(stderr, exitUsage, "malformed CVE id %q", id)
		}
	}
	d, code := openReadOnly(stderr, *db)
	if code != exitOK {
		return code
	}
	defer d.Close()
	ctx := context.Background()

	missing := 0
	var docs []report.CVEDoc
	for _, id := range ids {
		c, err := d.Get(ctx, strings.ToUpper(id))
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				fmt.Fprintf(stderr, "cv3: %s: not found\n", id)
				missing++
				continue
			}
			return fail(stderr, exitData, "%v", err)
		}
		names, err := cweNameMap(d, idsOf(c))
		if err != nil {
			return fail(stderr, exitData, "%v", err)
		}
		docs = append(docs, report.FromModel(c, names))
	}

	if *jsonOut {
		for _, doc := range docs {
			if err := report.WriteJSON(stdout, report.GetEnvelope{SchemaVersion: report.SchemaVersion, CVE: doc}); err != nil {
				return fail(stderr, exitData, "%v", err)
			}
		}
	} else {
		for i, doc := range docs {
			if i > 0 {
				fmt.Fprintln(stdout)
			}
			if err := writeGetText(stdout, doc); err != nil {
				return fail(stderr, exitData, "%v", err)
			}
		}
	}
	if missing > 0 || len(docs) == 0 {
		return exitNoResults
	}
	return exitOK
}

func idsOf(c *model.CVE) []string {
	out := make([]string, 0, len(c.CWEs))
	for _, w := range c.CWEs {
		out = append(out, w.ID)
	}
	return out
}
