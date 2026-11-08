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
	return Parse(eco, a).Compare(Parse(eco, b))
}

// Version is a version string parsed once under one ecosystem's rules, so it
// can be compared many times.
type Version struct {
	eco ecosystem.Ecosystem
	raw string
	ok  bool
	key string
	pep pep440
	gem []gemSeg
}

// Parse reads s under the version rules of eco. Input eco cannot parse
// still yields a Version, ordered as Compare describes.
func Parse(eco ecosystem.Ecosystem, s string) Version {
	v := Version{eco: eco, raw: s}
	switch eco {
	case ecosystem.Npm, ecosystem.Cargo, ecosystem.Go:
		var sv string
		if sv, v.ok = parseSemver(s); v.ok {
			v.key = semver.Canonical(sv)
		}
	case ecosystem.PyPI:
		if v.pep, v.ok = parsePEP440(s); v.ok {
			v.key = pep440Key(v.pep)
		}
	case ecosystem.RubyGems:
		if v.gem, v.ok = parseGem(s); v.ok {
			v.key = gemKey(v.gem)
		}
	}
	if !v.ok {
		// No parsed key starts with "!", and an unparseable version equals
		// only its own spelling.
		v.key = "!" + s
	}
	return v
}

// Compare returns -1, 0 or +1 as v sorts before, equal to, or after w. Both
// must be parsed under the same ecosystem.
func (v Version) Compare(w Version) int {
	switch {
	case v.ok && w.ok:
		switch v.eco {
		case ecosystem.PyPI:
			return comparePEP440(v.pep, w.pep)
		case ecosystem.RubyGems:
			return compareGem(v.gem, w.gem)
		}
		return semver.Compare(v.key, w.key)
	case v.ok:
		return -1
	case w.ok:
		return 1
	}
	return strings.Compare(v.raw, w.raw)
}

// Key returns a string that two versions share exactly when Compare reports
// them equal, so it can stand in for the version in a map.
func (v Version) Key() string { return v.key }

// parseSemver accepts SemVer 2.0 with or without a leading "v" (npm also
// tolerates "="). Go module versions, pseudo-versions included, are SemVer
// with a mandatory "v", but advisory databases often record them without it.
func parseSemver(s string) (string, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "=")
	s = "v" + strings.TrimPrefix(s, "v")
	return s, semver.IsValid(s)
}
