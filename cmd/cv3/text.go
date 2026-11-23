package main

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/fr0g-66723067-io/cv3/internal/report"
)

// writeSearchText renders a search envelope as an aligned table.
func writeSearchText(w io.Writer, env report.SearchEnvelope) error {
	w = newTerminalWriter(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CVE\tSCORE\tSEV\tCVSS\tPUBLISHED\tCWE\tSUMMARY")
	for _, h := range env.Results {
		score := "-"
		if h.Score != nil {
			score = fmt.Sprintf("%.1f", *h.Score)
		}
		sev := h.Severity
		if sev == "" {
			sev = "-"
		}
		cvss := h.CVSS
		if cvss == "" {
			cvss = "-"
		}
		published := h.Published
		if published == "" {
			published = "-"
		}
		cwe := "-"
		if len(h.CWE) > 0 {
			cwe = joinLimited(h.CWE, 3)
		}
		summary := h.Snippet
		if summary == "" {
			summary = h.Summary
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			h.ID, score, sev, cvss, published, cwe, oneLine(summary))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	shown := len(env.Results)
	if shown == 0 {
		fmt.Fprintf(w, "\n0 results\n")
		return nil
	}
	fmt.Fprintf(w, "\n%d results (showing %d-%d)\n", env.Total, env.Offset+1, env.Offset+shown)
	return nil
}

// writeGetText renders one record as labelled lines.
func writeGetText(w io.Writer, doc report.CVEDoc) error {
	w = newTerminalWriter(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	line := func(label, value string) {
		if value == "" {
			value = "-"
		}
		fmt.Fprintf(tw, "%s:\t%s\n", label, value)
	}
	line("ID", doc.ID)
	line("State", doc.State)
	if doc.NVDStatus == "" {
		line("NVD status", "(none)")
	} else {
		line("NVD status", doc.NVDStatus)
	}
	line("Published", doc.Published)
	line("Modified", doc.Modified)
	line("Assigner", doc.Assigner)
	if doc.Title != "" {
		line("Title", doc.Title)
	}
	if doc.Best != nil {
		line("Best CVSS", fmt.Sprintf("%.1f %s (%s)", doc.Best.Score, upperOrDash(doc.Best.Severity), doc.Best.Version))
	} else {
		line("Best CVSS", "-")
	}
	for _, m := range doc.CVSS {
		line("  "+cvssLabel(m), fmt.Sprintf("%.1f %s  %s", m.Score, upperOrDash(m.Severity), m.Vector))
	}
	if len(doc.CWE) > 0 {
		parts := make([]string, 0, len(doc.CWE))
		for _, c := range doc.CWE {
			if c.Name != "" {
				parts = append(parts, fmt.Sprintf("%s (%s)", c.ID, c.Name))
			} else {
				parts = append(parts, c.ID)
			}
		}
		line("CWE", joinLimited(parts, len(parts)))
	}
	if len(doc.CPE) > 0 {
		fmt.Fprintln(tw, "CPE:")
		for _, m := range doc.CPE {
			rng := m.Range
			if rng == "" {
				rng = "any"
			}
			flag := ""
			if !m.Vulnerable {
				flag = " [not vulnerable]"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", m.Criteria, rng, m.Source+flag)
		}
	}
	if len(doc.Products) > 0 {
		fmt.Fprintln(tw, "Products:")
		for _, p := range doc.Products {
			version := p.Versions
			if len(version) > 80 {
				version = version[:80] + "…"
			}
			fmt.Fprintf(tw, "  %s/%s\t%s\n", p.Vendor, p.Product, version)
		}
	}
	if len(doc.References) > 0 {
		fmt.Fprintln(tw, "References:")
		for _, r := range doc.References {
			if len(r.Tags) > 0 {
				fmt.Fprintf(tw, "  %s\t%s\n", r.URL, joinLimited(r.Tags, 3))
			} else {
				fmt.Fprintf(tw, "  %s\n", r.URL)
			}
		}
	}
	if doc.KEV != nil {
		line("KEV", fmt.Sprintf("%s (added %s, due %s)", doc.KEV.Name, doc.KEV.Added, doc.KEV.Due))
	}
	src := "cvelistV5"
	if doc.Sources.NVD {
		src += "+nvd"
	}
	line("Sources", src)
	if err := tw.Flush(); err != nil {
		return err
	}
	if doc.Summary != "" {
		fmt.Fprintf(w, "\n%s\n", doc.Summary)
	}
	return nil
}

// writeCPEText renders applicability hits.
func writeCPEText(w io.Writer, env report.CPEEnvelope) error {
	w = newTerminalWriter(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CVE\tSCORE\tSEV\tMATCH\tRANGE\tCRITERIA")
	for _, h := range env.Results {
		score := "-"
		if h.Score != nil {
			score = fmt.Sprintf("%.1f", *h.Score)
		}
		criteria := h.Criteria
		if criteria == "" {
			criteria = h.Vendor + "/" + h.Product
		}
		rng := h.Range
		if rng == "" {
			rng = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", h.CVE, score, upperOrDash(h.Severity), h.Match, rng, criteria)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(env.Results) == 0 {
		fmt.Fprintf(w, "\n0 matches\n")
	} else {
		fmt.Fprintf(w, "\n%d matches\n", env.Total)
	}
	return nil
}

// writeCWEText renders a catalog entry.
func writeCWEText(w io.Writer, doc report.CWEDoc) error {
	w = newTerminalWriter(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "ID:\t%s\n", doc.ID)
	fmt.Fprintf(tw, "Name:\t%s\n", doc.Name)
	if doc.Abstraction != "" {
		fmt.Fprintf(tw, "Abstraction:\t%s\n", doc.Abstraction)
	}
	if doc.Status != "" {
		fmt.Fprintf(tw, "Status:\t%s\n", doc.Status)
	}
	fmt.Fprintf(tw, "CVE count:\t%d\n", doc.CVECount)
	if len(doc.Parents) > 0 {
		fmt.Fprintf(tw, "Parents:\t%s\n", joinLimited(doc.Parents, len(doc.Parents)))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if doc.Description != "" {
		fmt.Fprintf(w, "\n%s\n", doc.Description)
	}
	return nil
}

// writeCWEListText renders catalog search results.
func writeCWEListText(w io.Writer, env report.CWEListEnvelope) error {
	w = newTerminalWriter(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CWE\tABSTR\tCVES\tNAME")
	for _, c := range env.Results {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", c.ID, c.Abstraction, c.CVECount, c.Name)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "\n%d entries\n", env.Total)
	return nil
}

// writeStatsText renders the corpus summary.
func writeStatsText(w io.Writer, s report.StatsDoc) error {
	w = newTerminalWriter(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "database:\t%s\n", s.DBPath)
	fmt.Fprintf(tw, "size:\t%s\n", humanBytes(s.DBSize))
	fmt.Fprintf(tw, "built:\t%s\n", orDash(s.BuiltAt))
	if len(s.Severities) > 0 {
		fmt.Fprintf(tw, "severity filter:\t%s\n", strings.Join(s.Severities, ", "))
	}
	fmt.Fprintf(tw, "cves:\t%d\n", s.CVEs)
	fmt.Fprintf(tw, "  nvd enriched:\t%d\n", s.Enriched)
	fmt.Fprintf(tw, "  cvelistV5 only:\t%d\n", s.Unenriched)
	fmt.Fprintf(tw, "  rejected:\t%d\n", s.Rejected)
	fmt.Fprintf(tw, "  reserved:\t%d\n", s.Reserved)
	fmt.Fprintf(tw, "kev entries:\t%d\n", s.KEV)
	fmt.Fprintf(tw, "cpe matches:\t%d\n", s.CPEMatches)
	fmt.Fprintf(tw, "cna products:\t%d\n", s.CVEProducts)
	fmt.Fprintf(tw, "cwe catalog:\t%d\n", s.CWECatalog)
	fmt.Fprintf(tw, "references:\t%d\n", s.Refs)
	fmt.Fprintf(tw, "fts rows:\t%d\n", s.FTSRows)
	for _, name := range sortedKeys(s.SourceState) {
		fmt.Fprintf(tw, "source %s:\t%s\n", name, s.SourceState[name])
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(s.BySeverity) > 0 {
		fmt.Fprintln(w, "\nseverity:")
		for _, sev := range sortedKeys(s.BySeverity) {
			fmt.Fprintf(w, "  %-10s %d\n", sev, s.BySeverity[sev])
		}
	}
	if len(s.ByYear) > 0 {
		fmt.Fprintln(w, "\nyear:")
		for _, y := range sortedKeys(s.ByYear) {
			fmt.Fprintf(w, "  %-10s %d\n", y, s.ByYear[y])
		}
	}
	return nil
}

func cvssLabel(m report.CVSSDoc) string {
	label := "CVSS"
	switch {
	case len(m.Vector) >= 8 && m.Vector[:8] == "CVSS:4.0":
		label = "v4.0"
	case len(m.Vector) >= 8 && m.Vector[:8] == "CVSS:3.1":
		label = "v3.1"
	case len(m.Vector) >= 8 && m.Vector[:8] == "CVSS:3.0":
		label = "v3.0"
	case m.Vector != "" && m.Vector[:1] == "A":
		label = "v2.0"
	}
	if m.Source != "" {
		label += " " + m.Source
	}
	return label
}

func upperOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return toUpper(s)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func toUpper(s string) string {
	out := []byte(s)
	for i := range out {
		if out[i] >= 'a' && out[i] <= 'z' {
			out[i] -= 'a' - 'A'
		}
	}
	return string(out)
}

// oneLine collapses whitespace so a table row stays on one line.
func oneLine(s string) string {
	out := make([]byte, 0, len(s))
	space := false
	for i := range len(s) {
		c := s[i]
		switch c {
		case '\n', '\r', '\t':
			if !space {
				out = append(out, ' ')
				space = true
			}
		default:
			out = append(out, c)
			space = c == ' '
		}
	}
	return string(out)
}

func joinLimited(items []string, maxItems int) string {
	if len(items) <= maxItems {
		return joinAll(items, ", ")
	}
	return joinAll(items[:maxItems], ", ") + " +" + itoa(len(items)-maxItems)
}

func joinAll(items []string, sep string) string {
	out := make([]byte, 0, 32)
	for i, s := range items {
		if i > 0 {
			out = append(out, sep...)
		}
		out = append(out, s...)
	}
	return string(out)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := v < 0
	if neg {
		v = -v
	}
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// humanBytes renders a byte count for the stats output.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return itoa(int(n)) + " B"
	}
	div, exp := int64(unit), 0
	for n/div >= unit && exp < 4 {
		div *= unit
		exp++
	}
	whole := n / div
	frac := (n % div) * 10 / div
	return itoa(int(whole)) + "." + itoa(int(frac)) + " " + string("KMGTP"[exp]) + "iB"
}
