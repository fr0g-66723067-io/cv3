package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/cv3/internal/report"
	"github.com/fr0g-66723067-io/cv3/internal/store/storetest"
)

// runCLI invokes the command dispatcher the way main does.
func runCLI(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestExitCodes(t *testing.T) {
	db := storetest.Build(t)
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"help", []string{"help"}, exitOK},
		{"version", []string{"version"}, exitOK},
		{"unknown command", []string{"frobnicate"}, exitUsage},
		{"search without terms or filters", []string{"search"}, exitUsage},
		{"search bad severity", []string{"search", "-db", db, "-severity", "catastrophic"}, exitUsage},
		{"search bad year", []string{"search", "-db", db, "-year", "20xx"}, exitUsage},
		{"search bad sort", []string{"search", "-db", db, "-sort", "sideways"}, exitUsage},
		{"get malformed id", []string{"get", "-db", db, "3094"}, exitUsage},
		{"get unknown id", []string{"get", "-db", db, "CVE-1999-0001"}, exitNoResults},
		{"cpe without selector", []string{"cpe", "-db", db}, exitUsage},
		{"cpe missing data", []string{"cpe", "-db", db, "-vendor", "nope"}, exitNoResults},
		{"cwe malformed id", []string{"cwe", "-db", db, "79"}, exitUsage},
		{"cwe unknown id", []string{"cwe", "-db", db, "CWE-999999"}, exitNoResults},
		{"stats on missing database", []string{"stats", "-db", "/nonexistent/cv3.db"}, exitData},
		{"get hit", []string{"get", "-db", db, storetest.EnrichedID}, exitOK},
		{"search hit", []string{"search", "-db", db, "backdoor"}, exitOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runCLI(tc.args...)
			if code != tc.want {
				t.Fatalf("exit = %d, want %d (stderr: %s)", code, tc.want, strings.TrimSpace(stderr))
			}
		})
	}
}

func TestSearchJSON(t *testing.T) {
	db := storetest.Build(t)
	code, stdout, stderr := runCLI("search", "-db", db, "-json", "-severity", "critical", "backdoor")
	if code != exitOK {
		t.Fatalf("exit = %d (stderr %s)", code, stderr)
	}
	var env report.SearchEnvelope
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	if env.SchemaVersion != report.SchemaVersion {
		t.Fatalf("schemaVersion = %q", env.SchemaVersion)
	}
	if env.Total != 1 || len(env.Results) != 1 || env.Results[0].ID != storetest.EnrichedID {
		t.Fatalf("envelope = %+v", env)
	}
	if env.Results[0].Score == nil || *env.Results[0].Score != 10.0 {
		t.Fatalf("score = %v", env.Results[0].Score)
	}
	if env.Query.Terms != "backdoor" || len(env.Query.Severity) != 1 {
		t.Fatalf("query echo = %+v", env.Query)
	}
}

func TestSearchText(t *testing.T) {
	db := storetest.Build(t)
	code, stdout, _ := runCLI("search", "-db", db, "-no-nvd", "-limit", "5")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(stdout, "CVE") || !strings.Contains(stdout, "SUMMARY") {
		t.Fatalf("missing header:\n%s", stdout)
	}
	if !strings.Contains(stdout, "2 results") {
		t.Fatalf("missing footer:\n%s", stdout)
	}
	// An unfiltered invocation is a usage error: 417k rows are never a useful
	// answer.
	if code, _, _ := runCLI("search", "-db", db); code != exitUsage {
		t.Fatalf("unfiltered search exit = %d, want %d", code, exitUsage)
	}
}

func TestGetJSON(t *testing.T) {
	db := storetest.Build(t)
	code, stdout, _ := runCLI("get", "-db", db, "-json", storetest.EnrichedID)
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	var env report.GetEnvelope
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	c := env.CVE
	if c.ID != storetest.EnrichedID || !c.Enriched || c.NVDStatus != "Modified" {
		t.Fatalf("record = %+v", c)
	}
	if c.Best == nil || c.Best.Score != 10.0 || c.Best.Severity != "critical" {
		t.Fatalf("best = %+v", c.Best)
	}
	if len(c.CWE) != 1 || c.CWE[0].ID != "CWE-506" || c.CWE[0].Name == "" {
		t.Fatalf("cwe = %+v", c.CWE)
	}
	if len(c.CPE) != 1 || c.CPE[0].Range != ">=5.6.0, <5.6.2" {
		t.Fatalf("cpe = %+v", c.CPE)
	}
	if c.KEV == nil || c.KEV.Name != "XZ Utils Backdoor" {
		t.Fatalf("kev = %+v", c.KEV)
	}
	if !c.Sources.CVEListV5 || !c.Sources.NVD {
		t.Fatalf("sources = %+v", c.Sources)
	}
}

func TestGetTextShowsUnenriched(t *testing.T) {
	db := storetest.Build(t)
	code, stdout, _ := runCLI("get", "-db", db, storetest.CNAOnlyID)
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(stdout, "NVD status:  (none)") {
		t.Fatalf("NVD status line missing:\n%s", stdout)
	}
	if !strings.Contains(stdout, "OpenSSL") {
		t.Fatalf("summary missing:\n%s", stdout)
	}
}

func TestGetMultipleWithOneMissing(t *testing.T) {
	db := storetest.Build(t)
	code, stdout, stderr := runCLI("get", "-db", db, storetest.EnrichedID, "CVE-1999-0002")
	if code != exitNoResults {
		t.Fatalf("exit = %d, want %d", code, exitNoResults)
	}
	if !strings.Contains(stdout, storetest.EnrichedID) {
		t.Fatalf("found record not printed:\n%s", stdout)
	}
	if !strings.Contains(stderr, "not found") {
		t.Fatalf("missing not-found note: %s", stderr)
	}
}

func TestCPEJSON(t *testing.T) {
	db := storetest.Build(t)
	code, stdout, _ := runCLI("cpe", "-db", db, "-json", "-vendor", "tukaani", "-product", "xz", "-version", "5.6.1")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	var env report.CPEEnvelope
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	if env.Total != 1 || env.Results[0].CVE != storetest.EnrichedID || env.Results[0].Match != "range" {
		t.Fatalf("envelope = %+v", env)
	}
	if env.Query.Version != "5.6.1" || env.Query.Vendor != "tukaani" {
		t.Fatalf("query echo = %+v", env.Query)
	}
}

func TestCWECommands(t *testing.T) {
	db := storetest.Build(t)
	code, stdout, _ := runCLI("cwe", "-db", db, "-json", storetest.CrossSiteID)
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	var env report.CWEEnvelope
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	if env.CWE.ID != storetest.CrossSiteID || env.CWE.CVECount != 1 {
		t.Fatalf("cwe = %+v", env.CWE)
	}

	code, stdout, _ = runCLI("cwe", "-db", db, "-json", "-search", "malicious")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	var list report.CWEListEnvelope
	if err := json.Unmarshal([]byte(stdout), &list); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	if list.Total != 1 || list.Results[0].ID != "CWE-506" {
		t.Fatalf("list = %+v", list)
	}
}

func TestStatsJSON(t *testing.T) {
	db := storetest.Build(t)
	code, stdout, _ := runCLI("stats", "-db", db, "-json")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	var env report.StatsEnvelope
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	if env.Stats.CVEs != 3 || env.Stats.Enriched != 1 || env.Stats.Unenriched != 2 {
		t.Fatalf("stats = %+v", env.Stats)
	}
	if env.Stats.SourceState["cvelistV5"] != "cve_2026-10-30_1900Z" {
		t.Fatalf("source state = %+v", env.Stats.SourceState)
	}
	if env.Stats.ByYear["2024"] != 1 {
		t.Fatalf("byYear = %+v", env.Stats.ByYear)
	}
}

func TestFlagsAfterPositionals(t *testing.T) {
	db := storetest.Build(t)
	code, stdout, stderr := runCLI("search", "backdoor", "-db", db, "-json")
	if code != exitOK {
		t.Fatalf("exit = %d (stderr %s)", code, stderr)
	}
	if !strings.Contains(stdout, storetest.EnrichedID) {
		t.Fatalf("output = %s", stdout)
	}
}
