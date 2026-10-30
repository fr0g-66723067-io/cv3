package cpe

import (
	"errors"
	"fmt"
	"strings"
)

// Any and NA are the two special CPE attribute values: ANY matches every value
// of that attribute, NA states the attribute is not applicable.
const (
	Any = "*"
	NA  = "-"
)

// ErrInvalid reports a string that is neither a CPE 2.3 formatted string nor a
// CPE 2.2/2.3 URI binding.
var ErrInvalid = errors.New("cpe: invalid formatted string")

// Name is a parsed CPE name with every attribute normalised to lower case.
type Name struct {
	Part      string // a (application), o (operating system), h (hardware), * (any)
	Vendor    string
	Product   string
	Version   string
	Update    string
	Edition   string
	Language  string
	SwEdition string
	TargetSw  string
	TargetHw  string
	Other     string
}

// IsAny reports whether v is the ANY wildcard.
func IsAny(v string) bool { return v == Any }

// IsNA reports whether v is the NA marker.
func IsNA(v string) bool { return v == NA }

// Parse decodes a CPE 2.3 formatted string ("cpe:2.3:part:vendor:product:...")
// or a CPE URI binding ("cpe:/part:vendor:product:..."). Both bindings appear
// interleaved in cvelistV5 ADP containers, so both are required to index it.
// All fields are lower cased, as CPE comparison is case insensitive.
func Parse(s string) (Name, error) {
	t := strings.TrimSpace(s)
	switch {
	case len(t) >= len("cpe:2.3:") && strings.EqualFold(t[:len("cpe:2.3:")], "cpe:2.3:"):
		return parseFormatted(t[len("cpe:2.3:"):])
	case len(t) >= len("cpe:/") && strings.EqualFold(t[:len("cpe:/")], "cpe:/"):
		return parseURI(t[len("cpe:/"):])
	}
	return Name{}, ErrInvalid
}

// ParseOK is Parse without the error, for call sites that skip malformed
// upstream strings instead of failing the record.
func ParseOK(s string) (Name, bool) {
	n, err := Parse(s)
	if err != nil {
		return Name{}, false
	}
	return n, true
}

// parseFormatted decodes the eleven attributes of the formatted-string binding.
// The binding escapes ":" and "\" (and other special characters) with a
// backslash, so the field split must honour escapes.
func parseFormatted(s string) (Name, error) {
	raw := splitEscaped(s, ':')
	if len(raw) != 11 {
		return Name{}, fmt.Errorf("%w: %d attributes, want 11", ErrInvalid, len(raw))
	}
	var f [11]string
	for i, v := range raw {
		f[i] = strings.ToLower(unescape(v))
		if f[i] == "" {
			f[i] = Any
		}
	}
	return Name{
		Part:      f[0],
		Vendor:    f[1],
		Product:   f[2],
		Version:   f[3],
		Update:    f[4],
		Edition:   f[5],
		Language:  f[6],
		SwEdition: f[7],
		TargetSw:  f[8],
		TargetHw:  f[9],
		Other:     f[10],
	}, nil
}

// parseURI decodes the URI binding: up to seven fields after "cpe:/" with
// percent encoding, "~" for NA and absent trailing fields meaning ANY.
func parseURI(s string) (Name, error) {
	parts := strings.Split(s, ":")
	if len(parts) > 7 {
		return Name{}, fmt.Errorf("%w: %d URI fields, want at most 7", ErrInvalid, len(parts))
	}
	var f [11]string
	for i := range f {
		f[i] = Any
	}
	for i, p := range parts {
		v := strings.ToLower(percentDecode(p))
		switch v {
		case "":
			v = Any
		case "~":
			v = NA
		}
		f[i] = v
	}
	if f[0] != Any && f[0] != NA && f[0] != "a" && f[0] != "o" && f[0] != "h" {
		return Name{}, fmt.Errorf("%w: bad part %q", ErrInvalid, f[0])
	}
	return Name{
		Part:      f[0],
		Vendor:    f[1],
		Product:   f[2],
		Version:   f[3],
		Update:    f[4],
		Edition:   f[5],
		Language:  f[6],
		SwEdition: f[7],
		TargetSw:  f[8],
		TargetHw:  f[9],
		Other:     f[10],
	}, nil
}

// splitEscaped splits s on sep, ignoring separators preceded by a backslash.
// The backslashes stay in the returned fields for unescape to consume.
func splitEscaped(s string, sep byte) []string {
	var out []string
	start := 0
	escaped := false
	for i := range len(s) {
		c := s[i]
		switch {
		case escaped:
			escaped = false
		case c == '\\':
			escaped = true
		case c == sep:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// unescape decodes the formatted-string escapes: "\\", "\:" and friends, plus
// the "\xHH" byte form.
func unescape(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		if s[i+1] == 'x' && i+3 < len(s) {
			hi, okHi := hexVal(s[i+2])
			lo, okLo := hexVal(s[i+3])
			if okHi && okLo {
				b.WriteByte(hi<<4 | lo)
				i += 3
				continue
			}
		}
		i++
		b.WriteByte(s[i])
	}
	return b.String()
}

// escape encodes the characters that would otherwise terminate or corrupt a
// formatted-string field.
func escape(s string) string {
	if !strings.ContainsAny(s, "\\:") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	for i := range len(s) {
		if c := s[i]; c == '\\' || c == ':' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func percentDecode(s string) string {
	if !strings.ContainsRune(s, '%') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, okHi := hexVal(s[i+1])
			lo, okLo := hexVal(s[i+2])
			if okHi && okLo {
				b.WriteByte(hi<<4 | lo)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Fields returns the eleven attributes in formatted-string order.
func (n Name) Fields() [11]string {
	return [11]string{
		n.Part, n.Vendor, n.Product, n.Version, n.Update, n.Edition,
		n.Language, n.SwEdition, n.TargetSw, n.TargetHw, n.Other,
	}
}

// Criteria renders the name as a CPE 2.3 formatted string.
func (n Name) Criteria() string {
	f := n.Fields()
	var b strings.Builder
	b.WriteString("cpe:2.3:")
	for i, v := range f {
		if i > 0 {
			b.WriteByte(':')
		}
		if v == "" {
			v = Any
		}
		b.WriteString(escape(v))
	}
	return b.String()
}

// VendorProduct renders the "vendor:product" pair used for product lookups.
func (n Name) VendorProduct() string { return n.Vendor + ":" + n.Product }

// IsUnversioned reports whether the name carries no version constraint, i.e.
// its version attribute is ANY or NA.
func (n Name) IsUnversioned() bool { return IsAny(n.Version) || IsNA(n.Version) }
