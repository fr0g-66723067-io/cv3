package store

import (
	"strings"
	"testing"
)

// TestBuildSearchSQLKeepsValuesInArgs pins the search invariant: query text is
// assembled only from constants and generated placeholder lists, so a caller
// value can never change the SQL grammar. It also pins that the count and page
// queries carry exactly the arguments their placeholders expect.
func TestBuildSearchSQLKeepsValuesInArgs(t *testing.T) {
	const hostile = `' OR 1=1 --`
	q := SearchQuery{
		Query:      hostile + " x?y",
		Vendors:    []string{hostile},
		Products:   []string{"x?y"},
		CWEs:       []string{hostile},
		Severities: []string{"high"},
		States:     []string{"PUBLISHED"},
		Limit:      20,
	}
	q.normalize()
	fts, err := ftsQuery(q.Query, q.Or)
	if err != nil {
		t.Fatalf("ftsQuery: %v", err)
	}

	plan := buildSearchSQL(&q, fts)
	for name, sql := range map[string]string{"page": plan.page, "count": plan.count} {
		for _, bad := range []string{"OR 1=1", "--", "x?y"} {
			if strings.Contains(sql, bad) {
				t.Errorf("%s SQL contains caller value %q:\n%s", name, bad, sql)
			}
		}
	}
	if got, want := strings.Count(plan.count, "?"), len(plan.args); got != want {
		t.Errorf("count placeholders = %d, args = %d", got, want)
	}
	if got, want := strings.Count(plan.page, "?"), len(plan.args)+2; got != want {
		t.Errorf("page placeholders = %d, args+limit/offset = %d", got, want)
	}
	if !strings.HasPrefix(plan.count, "SELECT count(*) FROM ") {
		t.Errorf("count query = %q", plan.count)
	}
}
