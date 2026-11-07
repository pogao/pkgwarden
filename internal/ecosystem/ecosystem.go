// Package ecosystem identifies the package ecosystems pkgwarden proxies and
// maps each one onto the names used by external advisory databases.
package ecosystem

import (
	"fmt"
	"regexp"
	"strings"
)

// Ecosystem is a package ecosystem such as npm or PyPI.
type Ecosystem string

const (
	Npm      Ecosystem = "npm"
	PyPI     Ecosystem = "pypi"
	RubyGems Ecosystem = "rubygems"
	Go       Ecosystem = "go"
	Cargo    Ecosystem = "cargo"
)

type traits struct {
	osv       string
	ghsa      string
	normalize func(string) string
}

var pep503 = regexp.MustCompile(`[-_.]+`)

var table = map[Ecosystem]traits{
	Npm:      {osv: "npm", ghsa: "npm", normalize: strings.ToLower},
	PyPI:     {osv: "PyPI", ghsa: "pip", normalize: func(s string) string { return pep503.ReplaceAllString(strings.ToLower(s), "-") }},
	RubyGems: {osv: "RubyGems", ghsa: "rubygems", normalize: func(s string) string { return s }},
	Go:       {osv: "Go", ghsa: "go", normalize: func(s string) string { return s }},
	Cargo:    {osv: "crates.io", ghsa: "rust", normalize: func(s string) string { return strings.ReplaceAll(strings.ToLower(s), "_", "-") }},
}

// All lists every supported ecosystem.
func All() []Ecosystem { return []Ecosystem{Npm, PyPI, RubyGems, Go, Cargo} }

// Parse converts a user-supplied identifier into an Ecosystem.
func Parse(s string) (Ecosystem, error) {
	e := Ecosystem(strings.ToLower(s))
	if _, ok := table[e]; !ok {
		return "", fmt.Errorf("unknown ecosystem %q", s)
	}
	return e, nil
}

// FromOSV maps an OSV ecosystem name back to an Ecosystem.
func FromOSV(s string) (Ecosystem, bool) {
	for e, t := range table {
		if t.osv == s {
			return e, true
		}
	}
	return "", false
}

// OSV returns the ecosystem name used by OSV and the OpenSSF malicious packages dataset.
func (e Ecosystem) OSV() string { return table[e].osv }

// GHSA returns the ecosystem name used by the GitHub Advisory Database.
func (e Ecosystem) GHSA() string { return table[e].ghsa }

// Normalize returns the canonical form of a package name, so that names the
// registry treats as identical compare equal.
func (e Ecosystem) Normalize(name string) string { return table[e].normalize(name) }
