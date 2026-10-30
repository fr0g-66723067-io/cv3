package cpe

import (
	"errors"
	"testing"
)

func TestParseFormatted(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want Name
	}{
		{
			name: "application with version",
			in:   "cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*",
			want: Name{Part: "a", Vendor: "tukaani", Product: "xz", Version: "5.6.1",
				Update: Any, Edition: Any, Language: Any, SwEdition: Any, TargetSw: Any, TargetHw: Any, Other: Any},
		},
		{
			name: "operating system with NA version",
			in:   "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*",
			want: Name{Part: "o", Vendor: "linux", Product: "linux_kernel", Version: NA,
				Update: Any, Edition: Any, Language: Any, SwEdition: Any, TargetSw: Any, TargetHw: Any, Other: Any},
		},
		{
			name: "escaped colon in vendor round-trips",
			in:   `cpe:2.3:a:foo\:bar:baz:1.0:*:*:*:*:*:*:*`,
			want: Name{Part: "a", Vendor: "foo:bar", Product: "baz", Version: "1.0",
				Update: Any, Edition: Any, Language: Any, SwEdition: Any, TargetSw: Any, TargetHw: Any, Other: Any},
		},
		{
			name: "uppercase is normalised",
			in:   "CPE:2.3:A:OpenSSL:OpenSSL:3.0.1:*:*:*:*:*:*:*",
			want: Name{Part: "a", Vendor: "openssl", Product: "openssl", Version: "3.0.1",
				Update: Any, Edition: Any, Language: Any, SwEdition: Any, TargetSw: Any, TargetHw: Any, Other: Any},
		},
		{
			name: "all fields populated",
			in:   "cpe:2.3:a:vendor:product:1.2.3:p1:ed:en:sw:tsw:thw:other",
			want: Name{Part: "a", Vendor: "vendor", Product: "product", Version: "1.2.3",
				Update: "p1", Edition: "ed", Language: "en", SwEdition: "sw", TargetSw: "tsw", TargetHw: "thw", Other: "other"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.in)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("Parse(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseURI(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want Name
	}{
		{
			name: "redhat enterprise linux",
			in:   "cpe:/o:redhat:enterprise_linux:10.1",
			want: Name{Part: "o", Vendor: "redhat", Product: "enterprise_linux", Version: "10.1",
				Update: Any, Edition: Any, Language: Any, SwEdition: Any, TargetSw: Any, TargetHw: Any, Other: Any},
		},
		{
			name: "bare part vendor product",
			in:   "cpe:/a:openssl:openssl",
			want: Name{Part: "a", Vendor: "openssl", Product: "openssl", Version: Any,
				Update: Any, Edition: Any, Language: Any, SwEdition: Any, TargetSw: Any, TargetHw: Any, Other: Any},
		},
		{
			name: "tilde is NA",
			in:   "cpe:/a:vendor:product:~:update",
			want: Name{Part: "a", Vendor: "vendor", Product: "product", Version: NA, Update: "update",
				Edition: Any, Language: Any, SwEdition: Any, TargetSw: Any, TargetHw: Any, Other: Any},
		},
		{
			name: "percent decoding",
			in:   "cpe:/a:foo%3Abar:baz%20qux:1.0",
			want: Name{Part: "a", Vendor: "foo:bar", Product: "baz qux", Version: "1.0",
				Update: Any, Edition: Any, Language: Any, SwEdition: Any, TargetSw: Any, TargetHw: Any, Other: Any},
		},
		{
			name: "full seven fields",
			in:   "cpe:/a:v:p:1.0:u:e:fr",
			want: Name{Part: "a", Vendor: "v", Product: "p", Version: "1.0", Update: "u", Edition: "e", Language: "fr",
				SwEdition: Any, TargetSw: Any, TargetHw: Any, Other: Any},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.in)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("Parse(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseInvalid(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"no prefix", "a:vendor:product:1.0"},
		{"too few attributes", "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*"},
		{"too many attributes", "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*:*"},
		{"too many URI fields", "cpe:/a:v:p:1:u:e:l:extra"},
		{"bad URI part", "cpe:/z:vendor:product:1.0"},
		{"unrelated", "https://example.test/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.in); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Parse(%q) error = %v, want ErrInvalid", tc.in, err)
			}
			if _, ok := ParseOK(tc.in); ok {
				t.Fatalf("ParseOK(%q) = true, want false", tc.in)
			}
		})
	}
}

func TestNameCriteriaRoundTrip(t *testing.T) {
	in := []string{
		"cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*",
		"cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*",
		`cpe:2.3:a:foo\:bar:baz:1.0:*:*:*:*:*:*:*`,
	}
	for _, s := range in {
		first, err := Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		second, err := Parse(first.Criteria())
		if err != nil {
			t.Fatalf("Parse(%q): %v", first.Criteria(), err)
		}
		if first != second {
			t.Fatalf("round trip of %q = %+v, want %+v", s, second, first)
		}
		if got := first.Criteria(); got != s {
			t.Fatalf("Criteria() = %q, want %q", got, s)
		}
	}
}

func TestVendorProductAndUnversioned(t *testing.T) {
	n, err := Parse("cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatal(err)
	}
	if got := n.VendorProduct(); got != "tukaani:xz" {
		t.Fatalf("VendorProduct() = %q", got)
	}
	if !n.IsUnversioned() {
		t.Fatal("wildcard version reported as versioned")
	}
	n.Version = NA
	if !n.IsUnversioned() {
		t.Fatal("NA version reported as versioned")
	}
	n.Version = "5.6.1"
	if n.IsUnversioned() {
		t.Fatal("concrete version reported as unversioned")
	}
}
