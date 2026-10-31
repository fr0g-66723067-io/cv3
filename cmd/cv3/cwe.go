package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/fr0g-66723067-io/cv3/internal/report"
	"github.com/fr0g-66723067-io/cv3/internal/store"
)

func runCWE(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("cwe")
	db := fs.String("db", "", "database path")
	jsonOut := fs.Bool("json", false, "emit JSON")
	search := fs.String("search", "", "search catalog names and descriptions")
	limit := fs.Int("limit", 25, "page size")

	flags, positional := splitArgs(fs, args)
	if status, ok := parseFlags(fs, flags, stdout, stderr); !ok {
		return status
	}
	if len(positional) > 1 {
		return fail(stderr, exitUsage, "cwe takes at most one id")
	}
	if *search == "" && len(positional) == 0 {
		fmt.Fprintln(stderr, "cv3: cwe needs an id or -search")
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	if *search != "" && len(positional) > 0 {
		return fail(stderr, exitUsage, "cwe takes an id or -search, not both")
	}
	d, code := openReadOnly(stderr, *db)
	if code != exitOK {
		return code
	}
	defer d.Close()
	ctx := context.Background()

	if *search != "" {
		infos, err := d.CWESearch(ctx, *search, *limit)
		if err != nil {
			return fail(stderr, exitData, "%v", err)
		}
		env := report.CWEListEnvelope{SchemaVersion: report.SchemaVersion, Total: len(infos), Results: make([]report.CWEDoc, 0, len(infos))}
		for i := range infos {
			env.Results = append(env.Results, report.CWEFromStore(&infos[i]))
		}
		if *jsonOut {
			if err := report.WriteJSON(stdout, env); err != nil {
				return fail(stderr, exitData, "%v", err)
			}
		} else if err := writeCWEListText(stdout, env); err != nil {
			return fail(stderr, exitData, "%v", err)
		}
		if len(infos) == 0 {
			return exitNoResults
		}
		return exitOK
	}

	id := strings.TrimSpace(positional[0])
	if !strings.HasPrefix(strings.ToUpper(id), "CWE-") {
		return fail(stderr, exitUsage, "malformed CWE id %q", id)
	}
	info, err := d.CWE(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fail(stderr, exitNoResults, "%s: not found in the catalog", id)
		}
		return fail(stderr, exitData, "%v", err)
	}
	doc := report.CWEFromStore(info)
	if *jsonOut {
		if err := report.WriteJSON(stdout, report.CWEEnvelope{SchemaVersion: report.SchemaVersion, CWE: doc}); err != nil {
			return fail(stderr, exitData, "%v", err)
		}
		return exitOK
	}
	if err := writeCWEText(stdout, doc); err != nil {
		return fail(stderr, exitData, "%v", err)
	}
	return exitOK
}
