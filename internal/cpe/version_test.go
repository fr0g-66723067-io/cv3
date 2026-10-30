package cpe

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.10", "1.9", 1},
		{"1.9", "1.10", -1},
		{"5.6.1", "5.6.1", 0},
		{"1.0", "1.0.0", 0},
		{"2.4.1a", "2.4.1", 1},
		{"", "1.0", -1},
		{"1.0", "", 1},
		{"", "", 0},
	}
	for _, tc := range cases {
		if got := Compare(tc.a, tc.b); sign(got) != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want sign %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func sign(v int) int {
	switch {
	case v < 0:
		return -1
	case v > 0:
		return 1
	}
	return 0
}

func TestRangeAffects(t *testing.T) {
	cases := []struct {
		name    string
		r       Range
		version string
		want    bool
	}{
		{"bounded inclusive", Range{Start: "5.6.0", End: "5.6.2"}, "5.6.1", true},
		{"bounded end exclusive inside", Range{Start: "5.6.0", End: "5.6.2", EndExclusive: true}, "5.6.1", true},
		{"bounded end exclusive boundary", Range{Start: "5.6.0", End: "5.6.2", EndExclusive: true}, "5.6.2", false},
		{"bounded end inclusive boundary", Range{Start: "5.6.0", End: "5.6.2"}, "5.6.2", true},
		{"bounded start exclusive boundary", Range{Start: "5.6.0", StartExclusive: true}, "5.6.0", false},
		{"below start", Range{Start: "5.6.0"}, "5.5.9", false},
		{"above end", Range{End: "5.6.2"}, "5.6.3", false},
		{"open range", Range{}, "9.9.9", true},
		{"open range empty version", Range{}, "", true},
		{"exact", Range{Exact: "5.6.1"}, "5.6.1", true},
		{"exact mismatch", Range{Exact: "5.6.1"}, "5.6.2", false},
		{"exact leading zeros", Range{Exact: "5.6"}, "5.6.0", true},
		{"exact prefix wildcard", Range{Exact: "5.6.*"}, "5.6.4", true},
		{"exact prefix wildcard mismatch", Range{Exact: "5.6.*"}, "5.7.4", false},
		{"exact wins over bounds", Range{Exact: "5.6.1", Start: "9.0"}, "5.6.1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.Affects(tc.version); got != tc.want {
				t.Fatalf("Range%+v.Affects(%q) = %v, want %v", tc.r, tc.version, got, tc.want)
			}
		})
	}
}

func TestRangeString(t *testing.T) {
	cases := []struct {
		r    Range
		want string
	}{
		{Range{Exact: "5.6.1"}, "=5.6.1"},
		{Range{Exact: "5.6.*"}, "~5.6.*"},
		{Range{Start: "5.6.0", End: "5.6.2", EndExclusive: true}, ">=5.6.0, <5.6.2"},
		{Range{End: "1.2", StartExclusive: true}, "<=1.2"},
		{Range{}, "any"},
	}
	for _, tc := range cases {
		if got := tc.r.String(); got != tc.want {
			t.Errorf("Range%+v.String() = %q, want %q", tc.r, got, tc.want)
		}
	}
}
