package version

import (
	"cmp"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// pep440Pattern is the permissive pattern from PEP 440's appendix, which
// accepts every spelling the spec normalizes ("1.0RC1", "1.0-post1", "v1.0").
var pep440Pattern = regexp.MustCompile(`^v?` +
	`(?:(?P<epoch>[0-9]+)!)?` +
	`(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?:[-_.]?(?P<pre_l>alpha|beta|preview|pre|rc|a|b|c)[-_.]?(?P<pre_n>[0-9]+)?)?` +
	`(?:-(?P<post_n1>[0-9]+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?)?` +
	`(?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?` +
	`(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$`)

// pep440 is the sort key of a PEP 440 version. Each optional part is a
// (rank, number) pair whose rank places "absent" before or after every
// present value, mirroring the infinities in the reference implementation.
type pep440 struct {
	epoch   uint64
	release []uint64 // trailing zeros stripped, so 1.0 == 1.0.0
	pre     part     // rank: 0 dev-only release, 1 a, 2 b, 3 rc, 4 none
	post    part     // rank: 0 none, 1 present
	dev     part     // rank: 0 present, 1 none
}

type part struct {
	rank int
	n    uint64
}

var preRank = map[string]int{
	"a": 1, "alpha": 1,
	"b": 2, "beta": 2,
	"c": 3, "rc": 3, "pre": 3, "preview": 3,
}

func parsePEP440(s string) (pep440, bool) {
	m := pep440Pattern.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return pep440{}, false
	}
	g := func(name string) string { return m[pep440Pattern.SubexpIndex(name)] }
	var v pep440
	ok := true
	num := func(s string) uint64 {
		if s == "" {
			return 0
		}
		n, err := strconv.ParseUint(s, 10, 64)
		ok = ok && err == nil
		return n
	}

	v.epoch = num(g("epoch"))
	for seg := range strings.SplitSeq(g("release"), ".") {
		v.release = append(v.release, num(seg))
	}
	for len(v.release) > 0 && v.release[len(v.release)-1] == 0 {
		v.release = v.release[:len(v.release)-1]
	}

	hasPost := g("post_n1") != "" || g("post_l") != ""
	hasDev := g("dev_l") != ""
	switch {
	case g("pre_l") != "":
		v.pre = part{preRank[g("pre_l")], num(g("pre_n"))}
	case !hasPost && hasDev:
		v.pre = part{rank: 0}
	default:
		v.pre = part{rank: 4}
	}
	if hasPost {
		v.post = part{1, num(g("post_n1") + g("post_n2"))}
	}
	if hasDev {
		v.dev = part{0, num(g("dev_n"))}
	} else {
		v.dev = part{rank: 1}
	}
	return v, ok
}

func comparePEP440(a, b pep440) int {
	return cmp.Or(
		cmp.Compare(a.epoch, b.epoch),
		slices.Compare(a.release, b.release),
		a.pre.compare(b.pre),
		a.post.compare(b.post),
		a.dev.compare(b.dev),
	)
}

func (p part) compare(q part) int {
	return cmp.Or(cmp.Compare(p.rank, q.rank), cmp.Compare(p.n, q.n))
}

// pep440Key spells out every field comparePEP440 reads, so two versions
// share a key exactly when they compare equal.
func pep440Key(v pep440) string {
	b := strconv.AppendUint(nil, v.epoch, 10)
	b = append(b, '!')
	for i, n := range v.release {
		if i > 0 {
			b = append(b, '.')
		}
		b = strconv.AppendUint(b, n, 10)
	}
	for _, p := range [...]part{v.pre, v.post, v.dev} {
		b = append(b, '|')
		b = strconv.AppendInt(b, int64(p.rank), 10)
		b = append(b, ':')
		b = strconv.AppendUint(b, p.n, 10)
	}
	return string(b)
}
