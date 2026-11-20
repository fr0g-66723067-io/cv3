package main

import (
	"context"
	"io"

	"github.com/fr0g-66723067-io/cv3/internal/report"
	"github.com/fr0g-66723067-io/cv3/internal/store"
)

func runStats(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("stats")
	db := fs.String("db", "", "database path")
	jsonOut := fs.Bool("json", false, "emit JSON")
	severities := listFlag{}
	fs.Var(&severities, "severity", "low,medium,high,critical,none (repeatable)")

	flags, _ := splitArgs(fs, args)
	if status, ok := parseFlags(fs, flags, stdout, stderr); !ok {
		return status
	}
	want := make([]string, 0, len(severities))
	for _, raw := range severities {
		v, err := store.ParseSeverity(raw)
		if err != nil {
			return fail(stderr, exitUsage, "%v", err)
		}
		want = append(want, v)
	}
	d, code := openReadOnly(stderr, *db)
	if code != exitOK {
		return code
	}
	defer d.Close()

	st, err := d.Stats(context.Background(), store.StatsFilter{Severities: want})
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
