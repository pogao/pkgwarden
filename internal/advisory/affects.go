package advisory

import (
	"slices"

	"github.com/pogao/pkgwarden/internal/version"
)

// Affects reports whether version is one of the releases the advisory covers.
// To test many versions, build a Matcher once.
func (a Advisory) Affects(v string) bool {
	return a.Matcher().Affects(version.Parse(a.Ecosystem, v))
}

// Matcher tests versions against one advisory whose versions and range
// bounds are parsed once.
type Matcher struct {
	versions map[string]bool // keys of the listed versions
	ranges   []bounds
}

type bounds struct {
	introduced, fixed, lastAffected *version.Version
}

// Matcher prepares the advisory for Affects calls with versions parsed
// under a.Ecosystem.
func (a Advisory) Matcher() Matcher {
	m := Matcher{versions: make(map[string]bool, len(a.Versions))}
	for _, s := range a.Versions {
		m.versions[version.Parse(a.Ecosystem, s).Key()] = true
	}
	parse := func(s string) *version.Version {
		if s == "" {
			return nil
		}
		v := version.Parse(a.Ecosystem, s)
		return &v
	}
	for _, r := range a.Ranges {
		b := bounds{fixed: parse(r.Fixed), lastAffected: parse(r.LastAffected)}
		if r.Introduced != "0" {
			b.introduced = parse(r.Introduced)
		}
		m.ranges = append(m.ranges, b)
	}
	return m
}

// Affects reports whether v is one of the releases the advisory covers.
func (m Matcher) Affects(v version.Version) bool {
	if len(m.versions) == 0 && len(m.ranges) == 0 {
		return true
	}
	if m.versions[v.Key()] {
		return true
	}
	return slices.ContainsFunc(m.ranges, func(b bounds) bool { return b.contains(v) })
}

func (b bounds) contains(v version.Version) bool {
	if b.introduced != nil && v.Compare(*b.introduced) < 0 {
		return false
	}
	switch {
	case b.fixed != nil:
		return v.Compare(*b.fixed) < 0
	case b.lastAffected != nil:
		return v.Compare(*b.lastAffected) <= 0
	}
	return true
}
