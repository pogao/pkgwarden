package version

import (
	"cmp"
	"regexp"
	"strconv"
	"strings"
)

var (
	gemPattern    = regexp.MustCompile(`^[0-9]+(?:\.[0-9a-zA-Z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	gemSegPattern = regexp.MustCompile(`[0-9]+|[a-zA-Z]+`)
)

// gemSeg is one piece of a Gem::Version: a number, or a letter run that
// marks the version as a prerelease.
type gemSeg struct {
	isText bool
	n      uint64
	text   string
}

// parseGem returns Gem::Version's canonical segments. Trailing zeros are
// dropped separately from the numeric prefix and from the part starting at
// the first letter run, so "1.0.a" becomes [1 a] and "1.0" becomes [1].
func parseGem(s string) ([]gemSeg, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		s = "0"
	}
	if !gemPattern.MatchString(s) {
		return nil, false
	}
	s = strings.ReplaceAll(s, "-", ".pre.")
	var segs []gemSeg
	textAt := -1
	for _, raw := range gemSegPattern.FindAllString(s, -1) {
		if raw[0] >= '0' && raw[0] <= '9' {
			n, err := strconv.ParseUint(raw, 10, 64)
			if err != nil {
				return nil, false
			}
			segs = append(segs, gemSeg{n: n})
			continue
		}
		if textAt < 0 {
			textAt = len(segs)
		}
		segs = append(segs, gemSeg{isText: true, text: raw})
	}
	if textAt < 0 {
		return trimZeros(segs), true
	}
	return append(trimZeros(segs[:textAt:textAt]), trimZeros(segs[textAt:])...), true
}

// gemKey joins the canonical segments. parseGem leaves no trailing zero for
// compareGem to pad, so equal keys mean equal versions.
func gemKey(segs []gemSeg) string {
	var b []byte
	for i, s := range segs {
		if i > 0 {
			b = append(b, '.')
		}
		if s.isText {
			b = append(b, s.text...)
		} else {
			b = strconv.AppendUint(b, s.n, 10)
		}
	}
	return string(b)
}

func trimZeros(segs []gemSeg) []gemSeg {
	for len(segs) > 0 && !segs[len(segs)-1].isText && segs[len(segs)-1].n == 0 {
		segs = segs[:len(segs)-1]
	}
	return segs
}

// compareGem follows Gem::Version#<=>: missing segments count as 0, and a
// letter segment sorts before any number.
func compareGem(a, b []gemSeg) int {
	for i := range max(len(a), len(b)) {
		var x, y gemSeg
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		switch {
		case x.isText && !y.isText:
			return -1
		case !x.isText && y.isText:
			return 1
		case x.isText:
			if c := strings.Compare(x.text, y.text); c != 0 {
				return c
			}
		default:
			if c := cmp.Compare(x.n, y.n); c != 0 {
				return c
			}
		}
	}
	return 0
}
