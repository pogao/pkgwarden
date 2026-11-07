// Package advisory looks up known-bad package releases in public advisory
// databases: OSV, the GitHub Advisory Database, and the OpenSSF malicious
// packages dataset.
package advisory

import (
	"context"
	"slices"
	"strings"

	"github.com/pogao/pkgwarden/internal/ecosystem"
)

// Kind separates deliberately malicious packages from vulnerable ones.
type Kind int

const (
	Vulnerability Kind = iota
	Malicious
)

func (k Kind) String() string {
	if k == Malicious {
		return "malicious"
	}
	return "vulnerability"
}

// Severity is the qualitative CVSS rating of a vulnerability. Ratings are
// ordered, so a higher value is more severe.
type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = [...]string{"", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

// String returns the upper-case CVSS name, or "" for SeverityUnknown.
func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return ""
	}
	return severityNames[s]
}

// ParseSeverity reads a database rating, ignoring case and surrounding
// space. GitHub's "moderate" is MEDIUM. Anything else is SeverityUnknown.
func ParseSeverity(s string) Severity {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "MODERATE" {
		return SeverityMedium
	}
	if i := slices.Index(severityNames[:], s); i > 0 {
		return Severity(i)
	}
	return SeverityUnknown
}

// Advisory is one database entry describing affected releases of a package.
type Advisory struct {
	ID        string
	Aliases   []string
	Source    string // "osv", "ghsa" or "openssf"
	Kind      Kind
	Summary   string
	Severity  Severity
	URL       string
	Ecosystem ecosystem.Ecosystem
	// Versions lists explicitly affected releases.
	Versions []string
	// Ranges lists affected version intervals. An advisory with no Versions
	// and no Ranges affects every release.
	Ranges []Range
}

// Range is a half-open version interval [Introduced, Fixed), or the closed
// interval [Introduced, LastAffected] when LastAffected is set. An empty
// Introduced (or "0") means the interval starts at the first release. An
// empty Fixed and LastAffected means it never ends.
type Range struct {
	Introduced   string
	Fixed        string
	LastAffected string
}

// Source returns every advisory for a package across all of its releases.
// Implementations return a nil slice, not an error, for unknown packages.
type Source interface {
	Lookup(ctx context.Context, eco ecosystem.Ecosystem, name string) ([]Advisory, error)
}
