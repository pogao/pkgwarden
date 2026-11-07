package advisory

import "testing"

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		in   string
		want Severity
	}{
		{"LOW", SeverityLow},
		{"medium", SeverityMedium},
		{"MODERATE", SeverityMedium},
		{"moderate", SeverityMedium},
		{" High\n", SeverityHigh},
		{"CRITICAL", SeverityCritical},
		{"", SeverityUnknown},
		{"UNKNOWN", SeverityUnknown},
		{"none", SeverityUnknown},
		{"9.8", SeverityUnknown},
	}
	for _, tt := range tests {
		if got := ParseSeverity(tt.in); got != tt.want {
			t.Errorf("ParseSeverity(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestSeverityOrderAndNames(t *testing.T) {
	ordered := []Severity{SeverityUnknown, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	names := []string{"", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	for i, s := range ordered {
		if i > 0 && s <= ordered[i-1] {
			t.Errorf("%v is not above %v", s, ordered[i-1])
		}
		if s.String() != names[i] {
			t.Errorf("String() = %q, want %q", s.String(), names[i])
		}
		if i > 0 && ParseSeverity(s.String()) != s {
			t.Errorf("ParseSeverity(%q) does not round-trip", s.String())
		}
	}
}
