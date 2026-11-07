// Package version orders release versions using each ecosystem's own rules.
package version

import (
	"strings"

	"golang.org/x/mod/semver"

	"github.com/pogao/pkgwarden/internal/ecosystem"
)

// Compare returns -1, 0 or +1 as a sorts before, equal to, or after b under
// the version ordering of eco.
//
// Input the ecosystem cannot parse never panics. A parseable version sorts
// before an unparseable one, and two unparseable versions compare as plain
// strings, so the order stays total and deterministic.
func Compare(eco ecosystem.Ecosystem, a, b string) int {
	if a == b {
		return 0
	}
	switch eco {
	case ecosystem.Npm, ecosystem.Cargo, ecosystem.Go:
		return compareParsed(a, b, parseSemver, semver.Compare)
	case ecosystem.PyPI:
		return compareParsed(a, b, parsePEP440, comparePEP440)
	case ecosystem.RubyGems:
		return compareParsed(a, b, parseGem, compareGem)
	}
	return strings.Compare(a, b)
}

func compareParsed[K any](a, b string, parse func(string) (K, bool), cmp func(K, K) int) int {
	ka, okA := parse(a)
	kb, okB := parse(b)
	switch {
	case okA && okB:
		return cmp(ka, kb)
	case okA:
		return -1
	case okB:
		return 1
	}
	return strings.Compare(a, b)
}

// parseSemver accepts SemVer 2.0 with or without a leading "v" (npm also
// tolerates "="). Go module versions, pseudo-versions included, are SemVer
// with a mandatory "v", but advisory databases often record them without it.
func parseSemver(s string) (string, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "=")
	s = "v" + strings.TrimPrefix(s, "v")
	return s, semver.IsValid(s)
}
