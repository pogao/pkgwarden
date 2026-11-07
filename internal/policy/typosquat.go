package policy

import (
	"bufio"
	"bytes"
	"embed"
	"strings"
	"sync"

	"github.com/pogao/pkgwarden/internal/ecosystem"
)

// The lists hold packages people type into an install command. Deep
// transitive dependencies are left out: lockfiles name them exactly, so they
// are not typo targets, and their often generic names would only add noise.
//
//go:embed popular/*.txt
var popularLists embed.FS

// popularName is one listed package. Names are compared element by element,
// where elements are the "/"-separated parts of an npm scoped name or a Go
// module path; every other ecosystem has single-element names.
type popularName struct {
	name  string
	parts []element
}

// element is one lower-cased name element with the forms it is compared in,
// computed once so a lookup does no per-comparison string work.
type element struct {
	text      string
	runes     []rune
	stripped  string
	lookalike string
}

func newElement(s string) element {
	stripped := separators.Replace(s)
	return element{text: s, runes: []rune(s), stripped: stripped, lookalike: confusables.Replace(stripped)}
}

type popularIndex struct {
	listed map[string]bool
	names  []popularName
}

var popularIndexes = sync.OnceValue(func() map[ecosystem.Ecosystem]*popularIndex {
	out := make(map[ecosystem.Ecosystem]*popularIndex)
	for _, eco := range ecosystem.All() {
		data, err := popularLists.ReadFile("popular/" + string(eco) + ".txt")
		if err != nil {
			continue
		}
		idx := &popularIndex{listed: make(map[string]bool)}
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			line, _, _ := strings.Cut(sc.Text(), "#")
			listed := strings.TrimSpace(line)
			key := eco.Normalize(listed)
			if key == "" || idx.listed[key] {
				continue
			}
			idx.listed[key] = true
			idx.names = append(idx.names, popularName{name: listed, parts: splitName(key)})
		}
		out[eco] = idx
	}
	return out
})

// resemblance names the popular package a name imitates and how.
type resemblance struct {
	popular string
	how     string
}

// resembles reports whether name imitates a popular package of eco without
// being one. A name differing from a popular one only in letter case is not
// reported: registries that care fold case in Normalize, and Go module hosts
// such as GitHub resolve case variants to the same repository.
func resembles(eco ecosystem.Ecosystem, name string) (resemblance, bool) {
	idx := popularIndexes()[eco]
	if idx == nil {
		return resemblance{}, false
	}
	name = eco.Normalize(name)
	if idx.listed[name] {
		return resemblance{}, false
	}
	parts := splitName(name)
	for _, p := range idx.names {
		if how, ok := resembleParts(parts, p.parts); ok {
			return resemblance{popular: p.name, how: how}, true
		}
	}
	return resemblance{}, false
}

func splitName(name string) []element {
	var out []element
	for s := range strings.SplitSeq(strings.ToLower(name), "/") {
		out = append(out, newElement(s))
	}
	return out
}

// resembleParts compares names that differ in exactly one element, so a Go
// module path such as github.com/sirupsen/logrus is judged by the length of
// the owner or repository that changed rather than the whole path, which
// would otherwise make github.com/x/net look one typo away from .../x/text.
func resembleParts(cand, pop []element) (string, bool) {
	if len(cand) != len(pop) {
		return "", false
	}
	diff := -1
	for i := range cand {
		if cand[i].text != pop[i].text {
			if diff >= 0 {
				return "", false
			}
			diff = i
		}
	}
	if diff < 0 {
		return "", false
	}
	return resembleElement(cand[diff], pop[diff])
}

const minEditLen = 4

func resembleElement(cand, pop element) (string, bool) {
	if cand.stripped == pop.stripped {
		return "differs only in separators", true
	}
	if cand.lookalike == pop.lookalike {
		return "differs only by look-alike characters", true
	}
	cr, pr := cand.runes, pop.runes
	if len(cr) < minEditLen || len(pr) < minEditLen {
		return "", false
	}
	limit := 1
	if len(pr) > 8 {
		limit = 2
	}
	switch osaDistance(cr, pr, limit) {
	case 1:
		return "one edit away", true
	case 2:
		if limit >= 2 {
			return "two edits away", true
		}
	}
	return "", false
}

var (
	separators  = strings.NewReplacer("-", "", "_", "", ".", "")
	confusables = strings.NewReplacer("rn", "m", "vv", "w", "0", "o", "1", "l", "5", "s")
)

// osaDistance is the optimal string alignment distance between a and b:
// insertions, deletions, substitutions and adjacent transpositions each cost
// one. Any distance above limit is reported as limit+1.
func osaDistance(a, b []rune, limit int) int {
	if abs(len(a)-len(b)) > limit {
		return limit + 1
	}
	prev2 := make([]int, len(b)+1)
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				cur[j] = min(cur[j], prev2[j-2]+1)
			}
		}
		prev2, prev, cur = prev, cur, prev2
	}
	return min(prev[len(b)], limit+1)
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
