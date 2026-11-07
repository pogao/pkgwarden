// Package advisory looks up known-bad package releases in public advisory
// databases: OSV, the GitHub Advisory Database, and the OpenSSF malicious
// packages dataset.
package advisory

import (
	"context"

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

// Advisory is one database entry describing affected releases of a package.
type Advisory struct {
	ID        string
	Aliases   []string
	Source    string // "osv", "ghsa" or "openssf"
	Kind      Kind
	Summary   string
	Severity  string // upper-case CVSS rating such as "HIGH"; empty when unknown
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
