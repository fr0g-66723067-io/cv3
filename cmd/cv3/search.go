package main

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/fr0g-66723067-io/cv3/internal/report"
	"github.com/fr0g-66723067-io/cv3/internal/store"
)

func runSearch(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("search")
	db := fs.String("db", "", "database path")
	jsonOut := fs.Bool("json", false, "emit JSON")
	severity := listFlag{}
	fs.Var(&severity, "severity", "low,medium,high,critical")
	minScore := fs.Float64("min-score", 0, "minimum score")
	maxScore := fs.Float64("max-score", 0, "maximum score")
	cvssVersion := fs.String("cvss", "", "v2|v3.0|v3.1|v4.0")
	cwes := listFlag{}
	fs.Var(&cwes, "cwe", "CWE id")
	vendors := listFlag{}
	fs.Var(&vendors, "vendor", "vendor")
	products := listFlag{}
	fs.Var(&products, "product", "product")
	year := fs.String("year", "", "YYYY or YYYY-YYYY")
	states := listFlag{}
	fs.Var(&states, "state", "PUBLISHED,REJECTED,RESERVED")
	statuses := listFlag{}
	fs.Var(&statuses, "status", "NVD vulnStatus")
	kev := fs.Bool("kev", false, "only CISA KEV entries")
	noNVD := fs.Bool("no-nvd", false, "only records NVD never enriched")
	after := fs.String("after", "", "published on/after YYYY-MM-DD")
	before := fs.String("before", "", "published on/before YYYY-MM-DD")
	sortBy := fs.String("sort", "", "relevance|score|date|id")
	limit := fs.Int("limit", 20, "page size")
	offset := fs.Int("offset", 0, "page offset")
	or := fs.Bool("or", false, "OR the terms instead of AND")

	flags, terms := splitArgs(fs, args)
	if status, ok := parseFlags(fs, flags, stdout, stderr); !ok {
		return status
	}

	filterFlags := []string{
		"severity", "min-score", "max-score", "cvss", "cwe", "vendor",
		"product", "year", "state", "status", "kev", "no-nvd", "after", "before",
	}
	if len(terms) == 0 && !anySet(fs, filterFlags...) {
		fmt.Fprintln(stderr, "cv3: search needs terms or a filter")
		fmt.Fprint(stderr, usage)
		return exitUsage
	}

	q := store.SearchQuery{
		Query:          strings.Join(terms, " "),
		Or:             *or,
		KEVOnly:        *kev,
		UnenrichedOnly: *noNVD,
		Sort:           strings.ToLower(strings.TrimSpace(*sortBy)),
		Limit:          *limit,
		Offset:         *offset,
	}
	for _, raw := range severity {
		v, err := store.ParseSeverity(raw)
		if err != nil {
			return fail(stderr, exitUsage, "%v", err)
		}
		q.Severities = append(q.Severities, v)
	}
	from, to, err := store.ParseYearRange(*year)
	if err != nil {
		return fail(stderr, exitUsage, "%v", err)
	}
	q.YearsFrom, q.YearsTo = from, to
	ver, err := store.ParseCVSSVersion(*cvssVersion)
	if err != nil {
		return fail(stderr, exitUsage, "%v", err)
	}
	q.CVSSVersion = ver
	if anySet(fs, "min-score") {
		q.HasScore, q.MinScore = true, *minScore
	}
	if *maxScore > 0 {
		q.MaxScore = *maxScore
	}
	for _, c := range cwes {
		q.CWEs = append(q.CWEs, strings.ToUpper(c))
	}
	q.Vendors = append(q.Vendors, vendors...)
	q.Products = append(q.Products, products...)
	for _, s := range states {
		q.States = append(q.States, strings.ToUpper(s))
	}
	q.Statuses = append(q.Statuses, statuses...)
	pubAfter, err := dateBound(*after, false)
	if err != nil {
		return fail(stderr, exitUsage, "%v", err)
	}
	pubBefore, err := dateBound(*before, true)
	if err != nil {
		return fail(stderr, exitUsage, "%v", err)
	}
	q.PublishedAfter, q.PublishedBefore = pubAfter, pubBefore
	switch q.Sort {
	case "", "relevance", "score", "date", "id":
	default:
		return fail(stderr, exitUsage, "unknown sort %q (relevance, score, date, id)", *sortBy)
	}

	d, code := openReadOnly(stderr, *db)
	if code != exitOK {
		return code
	}
	defer d.Close()

	res, err := d.Search(context.Background(), q)
	if err != nil {
		return fail(stderr, exitData, "%v", err)
	}

	doc := report.SearchQueryDoc{
		Terms: q.Query, Or: q.Or, Severity: q.Severities, State: q.States, Status: q.Statuses,
		CWE: q.CWEs, Vendor: q.Vendors, Product: q.Products,
		YearFrom: q.YearsFrom, YearTo: q.YearsTo, CVSS: q.CVSSVersion,
		KEV: q.KEVOnly, NoNVD: q.UnenrichedOnly, After: q.PublishedAfter,
		Before: q.PublishedBefore, Sort: q.Sort,
	}
	if q.HasScore {
		min := q.MinScore
		doc.MinScore = &min
	}
	if q.MaxScore > 0 {
		max := q.MaxScore
		doc.MaxScore = &max
	}
	env := report.SearchFromStore(doc, res, q.Limit, q.Offset)
	if *jsonOut {
		if err := report.WriteJSON(stdout, env); err != nil {
			return fail(stderr, exitData, "%v", err)
		}
	} else if err := writeSearchText(stdout, env); err != nil {
		return fail(stderr, exitData, "%v", err)
	}
	if res.Total == 0 {
		return exitNoResults
	}
	return exitOK
}

// dateBound normalises a YYYY-MM-DD bound into an RFC 3339 instant, taking the
// end of the day for upper bounds.
func dateBound(s string, upper bool) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if _, err := strconv.Atoi(strings.ReplaceAll(s, "-", "")); err != nil || len(s) != 10 {
		return "", fmt.Errorf("bad date %q (want YYYY-MM-DD)", s)
	}
	if upper {
		return s + "T23:59:59Z", nil
	}
	return s + "T00:00:00Z", nil
}
