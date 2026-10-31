package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/fr0g-66723067-io/cv3/internal/report"
	"github.com/fr0g-66723067-io/cv3/internal/store"
)

func runCPE(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("cpe")
	db := fs.String("db", "", "database path")
	jsonOut := fs.Bool("json", false, "emit JSON")
	vendor := fs.String("vendor", "", "vendor")
	product := fs.String("product", "", "product")
	version := fs.String("version", "", "version")
	part := fs.String("part", "", "a|o|h")
	criteria := fs.String("cpe", "", "full CPE name")
	limit := fs.Int("limit", 100, "page size")

	flags, _ := splitArgs(fs, args)
	if status, ok := parseFlags(fs, flags, stdout, stderr); !ok {
		return status
	}
	if *vendor == "" && *product == "" && *criteria == "" {
		fmt.Fprintln(stderr, "cv3: cpe needs -vendor, -product or -cpe")
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch strings.ToLower(*part) {
	case "", "a", "o", "h", "*":
	default:
		return fail(stderr, exitUsage, "part must be a, o or h")
	}
	filter := store.CPEFilter{
		Vendor:   strings.ToLower(strings.TrimSpace(*vendor)),
		Product:  strings.ToLower(strings.TrimSpace(*product)),
		Version:  strings.TrimSpace(*version),
		Part:     strings.ToLower(strings.TrimSpace(*part)),
		Criteria: strings.TrimSpace(*criteria),
		Limit:    *limit,
	}
	d, code := openReadOnly(stderr, *db)
	if code != exitOK {
		return code
	}
	defer d.Close()

	hits, err := d.ByCPE(context.Background(), filter)
	if err != nil {
		return fail(stderr, exitData, "%v", err)
	}
	env := report.CPEFromStore(report.CPEFilterDoc{
		Vendor: filter.Vendor, Product: filter.Product, Version: filter.Version,
		Part: filter.Part, CPE: filter.Criteria,
	}, hits)
	if *jsonOut {
		if err := report.WriteJSON(stdout, env); err != nil {
			return fail(stderr, exitData, "%v", err)
		}
	} else if err := writeCPEText(stdout, env); err != nil {
		return fail(stderr, exitData, "%v", err)
	}
	if len(hits) == 0 {
		return exitNoResults
	}
	return exitOK
}
