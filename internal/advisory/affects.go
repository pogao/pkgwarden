package advisory

import "slices"

// Affects reports whether version is one of the releases the advisory covers.
func (a Advisory) Affects(version string) bool {
	if len(a.Versions) == 0 && len(a.Ranges) == 0 {
		return true
	}
	return slices.Contains(a.Versions, version)
}
