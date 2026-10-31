package ingest

import (
	"archive/zip"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"os"
	"path"
	"strings"

	"github.com/fr0g-66723067-io/cv3/internal/model"
)

// CWE catalog shapes. The catalog declares the http://cwe.mitre.org/cwe-8
// default namespace; encoding/xml matches local names when a struct tag carries
// no namespace, so plain tags work.
type cweCatalog struct {
	XMLName    xml.Name `xml:"Weakness_Catalog"`
	Name       string   `xml:"Name,attr"`
	Version    string   `xml:"Version,attr"`
	Weaknesses struct {
		Weakness []cweWeakness `xml:"Weakness"`
	} `xml:"Weaknesses"`
}

// descText holds a Description element's raw inner XML: some entries wrap
// paragraphs in xhtml elements, and Go rejects a name combined with the
// innerxml flag on the same field.
type descText struct {
	Inner string `xml:",innerxml"`
}

type cweWeakness struct {
	ID          string   `xml:"ID,attr"`
	Name        string   `xml:"Name,attr"`
	Abstraction string   `xml:"Abstraction,attr"`
	Status      string   `xml:"Status,attr"`
	Description descText `xml:"Description"`
	Related     struct {
		Related []struct {
			Nature string `xml:"Nature,attr"`
			CWEID  string `xml:"CWE_ID,attr"`
		} `xml:"Related_Weakness"`
	} `xml:"Related_Weaknesses"`
}

// ParseCWEZip reads the catalog archive (a single cwec_v*.xml member) and
// returns its weaknesses with parents.
func ParseCWEZip(archive string) ([]model.CWE, string, error) {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return nil, "", fmt.Errorf("ingest: cwe catalog: %w", err)
	}
	defer zr.Close()
	var member *zip.File
	for _, f := range zr.File {
		if strings.HasSuffix(strings.ToLower(path.Base(f.Name)), ".xml") {
			member = f
			break
		}
	}
	if member == nil {
		return nil, "", fmt.Errorf("ingest: cwe catalog: no xml member in %s", archive)
	}
	rc, err := member.Open()
	if err != nil {
		return nil, "", fmt.Errorf("ingest: cwe catalog: %w", err)
	}
	defer rc.Close()
	return ParseCWEXML(rc)
}

// ParseCWEXML decodes a CWE catalog document.
func ParseCWEXML(r io.Reader) ([]model.CWE, string, error) {
	var cat cweCatalog
	if err := xml.NewDecoder(io.LimitReader(r, 256<<20)).Decode(&cat); err != nil {
		return nil, "", fmt.Errorf("ingest: cwe catalog: %w", err)
	}
	out := make([]model.CWE, 0, len(cat.Weaknesses.Weakness))
	for _, w := range cat.Weaknesses.Weakness {
		id := strings.TrimSpace(w.ID)
		if id == "" {
			continue
		}
		entry := model.CWE{
			ID:          "CWE-" + id,
			Name:        strings.TrimSpace(w.Name),
			Abstraction: w.Abstraction,
			Status:      w.Status,
			Description: cleanXMLText(w.Description.Inner),
		}
		seenParent := map[string]bool{}
		for _, rel := range w.Related.Related {
			if !strings.EqualFold(rel.Nature, "ChildOf") {
				continue
			}
			parent := strings.TrimSpace(rel.CWEID)
			if parent == "" || seenParent[parent] {
				continue
			}
			seenParent[parent] = true
			entry.Parents = append(entry.Parents, "CWE-"+parent)
		}
		out = append(out, entry)
	}
	if len(out) == 0 {
		return nil, "", fmt.Errorf("ingest: cwe catalog: no weaknesses parsed")
	}
	return out, cat.Version, nil
}

// cleanXMLText strips the inline XHTML the catalog uses for some descriptions
// and collapses whitespace.
func cleanXMLText(s string) string {
	if strings.ContainsAny(s, "<>") {
		var b strings.Builder
		b.Grow(len(s))
		inTag := false
		for _, r := range s {
			switch {
			case r == '<':
				inTag = true
			case r == '>':
				inTag = false
				b.WriteByte(' ')
			case !inTag:
				b.WriteRune(r)
			}
		}
		s = b.String()
	}
	return strings.Join(strings.Fields(html.UnescapeString(s)), " ")
}

// ParseCWEFile reads a catalog XML from disk.
func ParseCWEFile(file string) ([]model.CWE, string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, "", fmt.Errorf("ingest: cwe catalog: %w", err)
	}
	defer f.Close()
	return ParseCWEXML(f)
}
