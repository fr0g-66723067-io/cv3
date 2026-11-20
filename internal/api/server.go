// Package api serves the cv3 database over local HTTP as JSON. The payloads are
// the report package envelopes, byte-identical to what the CLI prints with
// -json.
package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/fr0g-66723067-io/cv3/internal/model"
	"github.com/fr0g-66723067-io/cv3/internal/report"
	"github.com/fr0g-66723067-io/cv3/internal/store"
)

var (
	cveIDRE = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	cweIDRE = regexp.MustCompile(`^CWE-[0-9]+$`)
)

// New builds the HTTP handler over an open read-only database. Diagnostics go to
// log; nil discards them.
func New(db *store.DB, log io.Writer) http.Handler {
	s := &server{db: db, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /v1/search", s.search)
	mux.HandleFunc("GET /v1/cve/{id}", s.getCVE)
	mux.HandleFunc("GET /v1/cpe", s.cpe)
	mux.HandleFunc("GET /v1/cwe/{id}", s.getCWE)
	mux.HandleFunc("GET /v1/cwe", s.cweSearch)
	mux.HandleFunc("GET /v1/stats", s.stats)
	return mux
}

type server struct {
	db  *store.DB
	log io.Writer
}

func (s *server) logf(format string, args ...any) {
	if s.log == nil {
		return
	}
	fmt.Fprintf(s.log, "cv3: api: "+format+"\n", args...)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	report.WriteJSON(w, v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	if err := s.db.Ping(r.Context()); err != nil {
		s.logf("healthz: %v", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "degraded", "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// queryValues reads every value of one parameter, splitting commas.
func queryValues(q map[string][]string, key string) []string {
	var out []string
	for _, raw := range q[key] {
		for _, part := range strings.Split(raw, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func queryInt(q map[string][]string, key string, def int) (int, error) {
	raw := strings.TrimSpace(first(q, key))
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", key)
	}
	return n, nil
}

func queryFloat(q map[string][]string, key string) (float64, bool, error) {
	raw := strings.TrimSpace(first(q, key))
	if raw == "" {
		return 0, false, nil
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, false, fmt.Errorf("%s must be a number", key)
	}
	return f, true, nil
}

func queryBool(q map[string][]string, key string) bool {
	switch strings.ToLower(strings.TrimSpace(first(q, key))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func first(q map[string][]string, key string) string {
	if v, ok := q[key]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}

func (s *server) search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ctx := r.Context()

	query := store.SearchQuery{
		Query:          strings.TrimSpace(first(q, "q")),
		Or:             queryBool(q, "or"),
		KEVOnly:        queryBool(q, "kev"),
		UnenrichedOnly: queryBool(q, "noNvd"),
		Sort:           strings.ToLower(strings.TrimSpace(first(q, "sort"))),
	}
	for _, raw := range queryValues(q, "severity") {
		v, err := store.ParseSeverity(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		query.Severities = append(query.Severities, v)
	}
	for _, raw := range queryValues(q, "state") {
		query.States = append(query.States, strings.ToUpper(raw))
	}
	for _, raw := range queryValues(q, "status") {
		query.Statuses = append(query.Statuses, raw)
	}
	for _, raw := range queryValues(q, "cwe") {
		query.CWEs = append(query.CWEs, strings.ToUpper(raw))
	}
	query.Vendors = queryValues(q, "vendor")
	query.Products = queryValues(q, "product")

	yearFrom, yearTo, err := store.ParseYearRange(first(q, "year"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	query.YearsFrom, query.YearsTo = yearFrom, yearTo

	ver, err := store.ParseCVSSVersion(first(q, "cvss"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	query.CVSSVersion = ver

	minScore, hasMin, err := queryFloat(q, "minScore")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	query.MinScore, query.HasScore = minScore, hasMin
	maxScore, _, err := queryFloat(q, "maxScore")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	query.MaxScore = maxScore
	query.PublishedAfter = first(q, "after")
	query.PublishedBefore = first(q, "before")

	limit, err := queryInt(q, "limit", 20)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	offset, err := queryInt(q, "offset", 0)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	limit = store.ClampLimit(limit, 20)
	query.Limit, query.Offset = limit, offset

	res, err := s.db.Search(ctx, query)
	if err != nil {
		s.logf("search: %v", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	doc := report.SearchQueryDoc{
		Terms: query.Query, Or: query.Or, Severity: query.Severities,
		State: query.States, Status: query.Statuses, CWE: query.CWEs,
		Vendor: query.Vendors, Product: query.Products,
		YearFrom: query.YearsFrom, YearTo: query.YearsTo,
		CVSS: ver, KEV: query.KEVOnly, NoNVD: query.UnenrichedOnly,
		After: query.PublishedAfter, Before: query.PublishedBefore, Sort: query.Sort,
	}
	if hasMin {
		doc.MinScore = &minScore
	}
	if query.MaxScore > 0 {
		ms := query.MaxScore
		doc.MaxScore = &ms
	}
	writeJSON(w, http.StatusOK, report.SearchFromStore(doc, res, limit, offset))
}

func (s *server) getCVE(w http.ResponseWriter, r *http.Request) {
	id := strings.ToUpper(strings.TrimSpace(r.PathValue("id")))
	if !cveIDRE.MatchString(id) {
		writeError(w, http.StatusBadRequest, "malformed CVE id")
		return
	}
	ctx := r.Context()
	c, err := s.db.Get(ctx, id)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		s.logf("cve/%s: %v", id, err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	names, err := s.cweNames(ctx, c)
	if err != nil {
		s.logf("cve/%s: %v", id, err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report.GetEnvelope{SchemaVersion: report.SchemaVersion, CVE: report.FromModel(c, names)})
}

// cweNames resolves the catalog names for a record's CWE ids.
func (s *server) cweNames(ctx context.Context, c *model.CVE) (map[string]string, error) {
	ids := make([]string, 0, len(c.CWEs))
	for _, w := range c.CWEs {
		ids = append(ids, w.ID)
	}
	return s.db.CWENames(ctx, ids)
}

func (s *server) cpe(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := store.CPEFilter{
		Vendor:   strings.ToLower(strings.TrimSpace(first(q, "vendor"))),
		Product:  strings.ToLower(strings.TrimSpace(first(q, "product"))),
		Version:  strings.TrimSpace(first(q, "version")),
		Part:     strings.ToLower(strings.TrimSpace(first(q, "part"))),
		Criteria: strings.TrimSpace(first(q, "cpe")),
	}
	if filter.Vendor == "" && filter.Product == "" && filter.Criteria == "" {
		writeError(w, http.StatusBadRequest, "one of vendor, product or cpe is required")
		return
	}
	limit, err := queryInt(q, "limit", 100)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	filter.Limit = store.ClampLimit(limit, 100)

	hits, err := s.db.ByCPE(r.Context(), filter)
	if err != nil {
		s.logf("cpe: %v", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report.CPEFromStore(report.CPEFilterDoc{
		Vendor: filter.Vendor, Product: filter.Product, Version: filter.Version,
		Part: filter.Part, CPE: filter.Criteria,
	}, hits))
}

func (s *server) getCWE(w http.ResponseWriter, r *http.Request) {
	id := strings.ToUpper(strings.TrimSpace(r.PathValue("id")))
	if !cweIDRE.MatchString(id) {
		writeError(w, http.StatusBadRequest, "malformed CWE id")
		return
	}
	info, err := s.db.CWE(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		s.logf("cwe/%s: %v", id, err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report.CWEEnvelope{SchemaVersion: report.SchemaVersion, CWE: report.CWEFromStore(info)})
}

func (s *server) cweSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	terms := strings.TrimSpace(first(q, "q"))
	if terms == "" {
		writeError(w, http.StatusBadRequest, "q is required")
		return
	}
	limit, err := queryInt(q, "limit", 25)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	limit = store.ClampLimit(limit, 25)
	infos, err := s.db.CWESearch(r.Context(), terms, limit)
	if err != nil {
		s.logf("cwe?q=%s: %v", terms, err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	env := report.CWEListEnvelope{SchemaVersion: report.SchemaVersion, Total: len(infos), Results: make([]report.CWEDoc, 0, len(infos))}
	for i := range infos {
		env.Results = append(env.Results, report.CWEFromStore(&infos[i]))
	}
	writeJSON(w, http.StatusOK, env)
}

func (s *server) stats(w http.ResponseWriter, r *http.Request) {
	st, err := s.db.Stats(r.Context())
	if err != nil {
		s.logf("stats: %v", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report.StatsEnvelope{SchemaVersion: report.SchemaVersion, Stats: report.StatsFromStore(st)})
}

func isNotFound(err error) bool { return errors.Is(err, store.ErrNotFound) }
