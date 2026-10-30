// Package cv3 is an offline search engine over the complete CVE corpus with
// CVSS scores, CPE applicability and CWE classification.
//
// # Sources
//
// Two upstream sources are merged by CVE ID, because neither is sufficient
// alone:
//
//   - cvelistV5 (https://github.com/CVEProject/cvelistV5) is the authoritative
//     corpus. Its daily all-CVEs release carries every CVE the CVE Program
//     knows about, including records NVD never enriched, plus CNA-supplied
//     CVSS metrics, CWE problem types, affected products and (via CISA's
//     Vulnerability Richness ADP container) CPE strings.
//   - NVD CVE 2.0 feeds (https://nvd.nist.gov/vuln/data-feeds) are the only
//     source of NVD-style CPE applicability with version ranges, NVD CVSS
//     metrics, KEV flags and vulnStatus. They lag publication: records absent
//     here still exist in the database because of cvelistV5.
//
// A third source, the MITRE CWE catalog, supplies CWE names, descriptions and
// parents so CWE filters return readable results rather than bare identifiers.
//
// # Precedence
//
// cvelistV5 creates the base row; NVD overlays it. Per CVSS version an
// NVD-primary metric beats an NVD-secondary metric, which beats a CNA metric,
// which beats an ADP metric. NVD wins for summary, published/modified times and
// vulnStatus; cvelistV5 wins for record state. CPE match rows from both sources
// are kept and distinguished by their src column. The representative score
// (best_score) comes from the highest CVSS version present, v4.0 > v3.1 > v3.0 >
// v2.0.
//
// # Storage
//
// A single SQLite database (pure Go, no cgo) holds relational tables for
// structured queries and an FTS5 index for full-text search. A full sync is
// built into a new file and renamed into place, so an interrupted sync never
// damages a working database. Expect 2-3 GiB on disk and 10-30 minutes for a
// full sync.
package cv3
