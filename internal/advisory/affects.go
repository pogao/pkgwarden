package advisory

import (
	"slices"

	"github.com/pogao/pkgwarden/internal/version"
)

// Affects reports whether version is one of the releases the advisory covers.
func (a Advisory) Affects(v string) bool {
	if len(a.Versions) == 0 && len(a.Ranges) == 0 {
		return true
	}
	if slices.ContainsFunc(a.Versions, func(x string) bool { return version.Compare(a.Ecosystem, v, x) == 0 }) {
		return true
	}
	return slices.ContainsFunc(a.Ranges, func(r Range) bool { return r.contains(a, v) })
}

func (r Range) contains(a Advisory, v string) bool {
	if r.Introduced != "" && r.Introduced != "0" && version.Compare(a.Ecosystem, v, r.Introduced) < 0 {
		return false
	}
	switch {
	case r.Fixed != "":
		return version.Compare(a.Ecosystem, v, r.Fixed) < 0
	case r.LastAffected != "":
		return version.Compare(a.Ecosystem, v, r.LastAffected) <= 0
	}
	return true
}
