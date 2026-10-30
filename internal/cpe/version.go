package cpe

import (
	"strconv"
	"strings"
)

// Compare compares two version strings using a natural ordering that splits on
// non-numeric boundaries and compares dot-separated components numerically where
// possible and lexically otherwise. It returns -1 if a<b, 0 if equal, +1 if a>b.
// Empty/unknown values compare less than any concrete value.
func Compare(a, b string) int {
	ac := versionComponents(a)
	bc := versionComponents(b)
	n := len(ac)
	if len(bc) > n {
		n = len(bc)
	}
	for i := 0; i < n; i++ {
		av, bv := "", ""
		if i < len(ac) {
			av = ac[i]
		}
		if i < len(bc) {
			bv = bc[i]
		}
		if c := cmpComponent(av, bv); c != 0 {
			return c
		}
	}
	return 0
}

// versionComponents splits a version string into comparable components,
// separating on dots and also splitting digit/non-digit boundaries so that
// e.g. "2.4.1a" and "2.4.1" compare sensibly. Trailing zero components are
// dropped so that "1.0.0" and "1.0" are treated as equal.
func versionComponents(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ".") {
		if part == "" {
			out = append(out, "")
			continue
		}
		out = append(out, splitDigits(part)...)
	}
	for len(out) > 0 {
		last := out[len(out)-1]
		if last == "0" || last == "" {
			out = out[:len(out)-1]
		} else {
			break
		}
	}
	return out
}

// splitDigits splits a component into alternating numeric and textual chunks
// (e.g. "1a" -> ["1","a"]).
func splitDigits(s string) []string {
	if len(s) == 0 {
		return nil
	}
	var out []string
	start := 0
	prevDigit := isDigit(s[0])
	for i := 1; i <= len(s); i++ {
		digit := i < len(s) && isDigit(s[i])
		if i == len(s) || digit != prevDigit {
			out = append(out, s[start:i])
			start = i
			if i < len(s) {
				prevDigit = digit
			}
		}
	}
	return out
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func cmpComponent(a, b string) int {
	// Empty components compare equal to absent ones.
	if a == "" && b == "" {
		return 0
	}
	if a == "" {
		return -1
	}
	if b == "" {
		return 1
	}
	na, errA := strconv.Atoi(a)
	nb, errB := strconv.Atoi(b)
	if errA == nil && errB == nil {
		switch {
		case na < nb:
			return -1
		case na > nb:
			return 1
		default:
			return 0
		}
	}
	return strings.Compare(a, b)
}

// Range is an applicability constraint: an exact version, inclusive/exclusive
// bounds, or both. Empty bounds are unbounded on that side.
type Range struct {
	Exact          string
	Start          string
	StartExclusive bool
	End            string
	EndExclusive   bool
}

// Affects reports whether version satisfies the range. Exact wins when set; an
// empty Start and End match everything; an empty version with no Exact also
// matches everything, which callers use for "unversioned" rows.
func (r Range) Affects(version string) bool {
	if r.Exact != "" {
		return matchExact(r.Exact, version)
	}
	if r.Start == "" && r.End == "" {
		return true
	}
	if version == "" {
		return true
	}
	if r.Start != "" {
		switch c := Compare(version, r.Start); {
		case c < 0:
			return false
		case c == 0 && r.StartExclusive:
			return false
		}
	}
	if r.End != "" {
		switch c := Compare(version, r.End); {
		case c > 0:
			return false
		case c == 0 && r.EndExclusive:
			return false
		}
	}
	return true
}

// matchExact compares an exact CPE version against version. A "*" anywhere in
// the pattern is a prefix wildcard ("5.6.*" matches "5.6.1"); otherwise the
// comparison uses the natural component ordering so that "5.6" and "5.6.0"
// are equal.
func matchExact(pattern, version string) bool {
	p := strings.ToLower(pattern)
	v := strings.ToLower(version)
	if i := strings.IndexByte(p, '*'); i >= 0 {
		return strings.HasPrefix(v, p[:i])
	}
	return Compare(p, v) == 0
}

// String renders the range for human output.
func (r Range) String() string {
	if r.Exact != "" {
		if strings.ContainsRune(r.Exact, '*') {
			return "~" + r.Exact
		}
		return "=" + r.Exact
	}
	var parts []string
	if r.Start != "" {
		op := ">="
		if r.StartExclusive {
			op = ">"
		}
		parts = append(parts, op+r.Start)
	}
	if r.End != "" {
		op := "<="
		if r.EndExclusive {
			op = "<"
		}
		parts = append(parts, op+r.End)
	}
	if len(parts) == 0 {
		return "any"
	}
	return strings.Join(parts, ", ")
}
