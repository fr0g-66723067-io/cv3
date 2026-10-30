// Package cvss normalises CVSS qualitative severities.
//
// Scores themselves are never computed here: both upstream sources (NVD feeds
// and cvelistV5) publish a baseScore with every metric, and recomputing it would
// only introduce a second, disagreeing arithmetic. What neither source is
// consistent about is the qualitative band, and what callers need is one
// vocabulary across CVSS v2's three bands and v3.x/v4.0's four.
package cvss

import "strings"

// Severity returns the qualitative rating for score under the given CVSS
// version family ("v2" for the three-band v2 scale, anything else for the
// four-band v3.x/v4.0 scale). A nil score yields the empty string.
func Severity(version string, score *float64) string {
	if score == nil {
		return ""
	}
	return SeverityOf(version, *score)
}

// SeverityOf returns the qualitative rating for score under the given CVSS
// version family. Scores below zero yield the empty string; v2 has no "none"
// band, so a v2 score of 0.0 is "low".
func SeverityOf(version string, score float64) string {
	if score < 0 {
		return ""
	}
	if isV2(version) {
		switch {
		case score < 4.0:
			return "low"
		case score < 7.0:
			return "medium"
		default:
			return "high"
		}
	}
	switch {
	case score == 0:
		return "none"
	case score < 4.0:
		return "low"
	case score < 7.0:
		return "medium"
	case score < 9.0:
		return "high"
	default:
		return "critical"
	}
}

// isV2 reports whether version names the CVSS v2 family, accepting both the
// store's column suffix ("v2") and a metric version string ("2.0").
func isV2(version string) bool {
	v := strings.ToLower(strings.TrimSpace(version))
	return strings.HasPrefix(v, "v2") || strings.HasPrefix(v, "2.")
}
