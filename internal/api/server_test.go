package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/cv3/internal/report"
	"github.com/fr0g-66723067-io/cv3/internal/store/storetest"
)

func newServer(t *testing.T) (*httptest.Server, *httptest.ResponseRecorder) {
	t.Helper()
	path := storetest.Build(t)
	db := storetest.Open(t, path)
	srv := httptest.NewServer(New(db, io.Discard))
	t.Cleanup(srv.Close)
	return srv, nil
}

func get(t *testing.T, srv *httptest.Server, path string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return resp, body
}

func decode[T any](t *testing.T, body []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("decode %T: %v\n%s", v, err, body)
	}
	return v
}

func TestHealth(t *testing.T) {
	srv, _ := newServer(t)
	resp, body := get(t, srv, "/healthz")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := string(bytes.TrimSpace(body)); !strings.Contains(got, `"ok"`) {
		t.Fatalf("body = %s", got)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content type = %q", ct)
	}
}

func TestSearchRoute(t *testing.T) {
	srv, _ := newServer(t)
	resp, body := get(t, srv, "/v1/search?q=backdoor&limit=3")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	env := decode[report.SearchEnvelope](t, body)
	if env.SchemaVersion != report.SchemaVersion || env.Total != 1 {
		t.Fatalf("envelope = %+v", env)
	}
	if env.Results[0].ID != storetest.EnrichedID {
		t.Fatalf("results = %+v", env.Results)
	}

	// Filters combine.
	resp, body = get(t, srv, "/v1/search?severity=critical&year=2024&cwe=CWE-506")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	if env := decode[report.SearchEnvelope](t, body); env.Total != 1 {
		t.Fatalf("filtered total = %d", env.Total)
	}

	// Unenriched filter.
	resp, body = get(t, srv, "/v1/search?noNvd=1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	if env := decode[report.SearchEnvelope](t, body); env.Total != 2 {
		t.Fatalf("noNvd total = %d", env.Total)
	}

	// Limit clamping.
	_, body = get(t, srv, "/v1/search?noNvd=1&limit=1000")
	if env := decode[report.SearchEnvelope](t, body); env.Limit != 500 {
		t.Fatalf("limit = %d, want 500", env.Limit)
	}

	// Bad input.
	for _, path := range []string{
		"/v1/search?severity=catastrophic",
		"/v1/search?year=20xx",
		"/v1/search?cvss=9",
		"/v1/search?minScore=abc",
	} {
		resp, body := get(t, srv, path)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s status = %d: %s", path, resp.StatusCode, body)
		}
	}
}

func TestCVERouteMatchesCLI(t *testing.T) {
	path := storetest.Build(t)
	db := storetest.Open(t, path)
	srv := httptest.NewServer(New(db, io.Discard))
	defer srv.Close()

	resp, body := get(t, srv, "/v1/cve/"+storetest.EnrichedID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	env := decode[report.GetEnvelope](t, body)
	if env.CVE.ID != storetest.EnrichedID {
		t.Fatalf("id = %q", env.CVE.ID)
	}
	if env.CVE.Best == nil || env.CVE.Best.Score != 10.0 {
		t.Fatalf("best = %+v", env.CVE.Best)
	}

	// Byte-identical to what the CLI -json path renders for the same record.
	c, err := db.Get(context.Background(), storetest.EnrichedID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	names, err := db.CWENames(context.Background(), []string{"CWE-506"})
	if err != nil {
		t.Fatalf("CWENames: %v", err)
	}
	var want bytes.Buffer
	if err := report.WriteJSON(&want, report.GetEnvelope{SchemaVersion: report.SchemaVersion, CVE: report.FromModel(c, names)}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(want.Bytes()), bytes.TrimSpace(body)) {
		t.Fatalf("API body differs from CLI JSON:\nAPI: %s\nCLI: %s", body, want.Bytes())
	}

	// Lowercase ids are accepted.
	resp, _ = get(t, srv, "/v1/cve/cve-2024-3094")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("lowercase status = %d", resp.StatusCode)
	}

	for _, tc := range []struct {
		path string
		want int
	}{
		{"/v1/cve/CVE-1999-0001", http.StatusNotFound},
		{"/v1/cve/not-a-cve", http.StatusBadRequest},
	} {
		resp, body := get(t, srv, tc.path)
		if resp.StatusCode != tc.want {
			t.Fatalf("%s status = %d, want %d (%s)", tc.path, resp.StatusCode, tc.want, body)
		}
	}
}

func TestCPERoute(t *testing.T) {
	srv, _ := newServer(t)
	resp, body := get(t, srv, "/v1/cpe?vendor=tukaani&product=xz&version=5.6.1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	env := decode[report.CPEEnvelope](t, body)
	if env.Total != 1 || env.Results[0].CVE != storetest.EnrichedID || env.Results[0].Match != "range" {
		t.Fatalf("envelope = %+v", env)
	}

	resp, body = get(t, srv, "/v1/cpe")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("no-params status = %d: %s", resp.StatusCode, body)
	}

	resp, _ = get(t, srv, "/v1/cpe?vendor=absent")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("absent product status = %d", resp.StatusCode)
	}
}

func TestCWERoutes(t *testing.T) {
	srv, _ := newServer(t)
	resp, body := get(t, srv, "/v1/cwe/"+storetest.CrossSiteID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	env := decode[report.CWEEnvelope](t, body)
	if env.CWE.ID != storetest.CrossSiteID || env.CWE.CVECount != 1 {
		t.Fatalf("cwe = %+v", env.CWE)
	}

	resp, _ = get(t, srv, "/v1/cwe/CWE-999999")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing status = %d", resp.StatusCode)
	}
	resp, _ = get(t, srv, "/v1/cwe/79")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed status = %d", resp.StatusCode)
	}

	resp, body = get(t, srv, "/v1/cwe?q=malicious")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("search status = %d: %s", resp.StatusCode, body)
	}
	list := decode[report.CWEListEnvelope](t, body)
	if list.Total != 1 || list.Results[0].ID != "CWE-506" {
		t.Fatalf("list = %+v", list)
	}

	resp, _ = get(t, srv, "/v1/cwe")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing q status = %d", resp.StatusCode)
	}
}

func TestStatsRoute(t *testing.T) {
	srv, _ := newServer(t)
	resp, body := get(t, srv, "/v1/stats")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	env := decode[report.StatsEnvelope](t, body)
	if env.Stats.CVEs != 3 || env.Stats.Enriched != 1 {
		t.Fatalf("stats = %+v", env.Stats)
	}
}
