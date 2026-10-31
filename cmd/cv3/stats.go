package main

import (
	"context"
	"io"

	"github.com/fr0g-66723067-io/cv3/internal/report"
)

func runStats(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("stats")
	db := fs.String("db", "", "database path")
	jsonOut := fs.Bool("json", false, "emit JSON")

	flags, _ := splitArgs(fs, args)
	if status, ok := parseFlags(fs, flags, stdout, stderr); !ok {
		return status
	}
	d, code := openReadOnly(stderr, *db)
	if code != exitOK {
		return code
	}
	defer d.Close()

	st, err := d.Stats(context.Background())
	if err != nil {
		return fail(stderr, exitData, "%v", err)
	}
	doc := report.StatsFromStore(st)
	if *jsonOut {
		if err := report.WriteJSON(stdout, report.StatsEnvelope{SchemaVersion: report.SchemaVersion, Stats: doc}); err != nil {
			return fail(stderr, exitData, "%v", err)
		}
		return exitOK
	}
	if err := writeStatsText(stdout, doc); err != nil {
		return fail(stderr, exitData, "%v", err)
	}
	return exitOK
}
