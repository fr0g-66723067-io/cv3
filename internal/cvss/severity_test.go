package cvss

import "testing"

func TestSeverityOf(t *testing.T) {
	boundaries := []float64{0.0, 0.1, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10.0}
	v3 := []string{"none", "low", "low", "medium", "medium", "high", "high", "critical", "critical"}
	v2 := []string{"low", "low", "low", "medium", "medium", "high", "high", "high", "high"}
	for i, score := range boundaries {
		if got := SeverityOf("v31", score); got != v3[i] {
			t.Errorf("SeverityOf(v31, %v) = %q, want %q", score, got, v3[i])
		}
		if got := SeverityOf("v2", score); got != v2[i] {
			t.Errorf("SeverityOf(v2, %v) = %q, want %q", score, got, v2[i])
		}
	}
	if got := SeverityOf("v40", 9.5); got != "critical" {
		t.Errorf("SeverityOf(v40, 9.5) = %q", got)
	}
	if got := SeverityOf("2.0", 5.0); got != "medium" {
		t.Errorf("SeverityOf(2.0, 5.0) = %q", got)
	}
	if got := SeverityOf("v30", -1); got != "" {
		t.Errorf("SeverityOf(v30, -1) = %q, want empty", got)
	}
}

func TestSeverityNil(t *testing.T) {
	if got := Severity("v31", nil); got != "" {
		t.Fatalf("Severity(v31, nil) = %q, want empty", got)
	}
	score := 7.5
	if got := Severity("v31", &score); got != "high" {
		t.Fatalf("Severity(v31, 7.5) = %q, want high", got)
	}
}
