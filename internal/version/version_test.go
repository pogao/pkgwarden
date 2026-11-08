package version

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/pogao/pkgwarden/internal/ecosystem"
)

func TestCompareOrdering(t *testing.T) {
	semverOrder := []string{
		"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
		"1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.2.0", "1.10.0", "2.0.0", "10.0.0",
	}
	ascending := map[ecosystem.Ecosystem][]string{
		ecosystem.Npm:   semverOrder,
		ecosystem.Cargo: append([]string{"0.9.0", "0.10.0"}, semverOrder...),
		ecosystem.Go: {
			"v0.0.0-20190101000000-abcdefabcdef", "v0.1.0", "v1.0.0-rc.1", "v1.0.0",
			"v1.0.1-0.20200101000000-abcdefabcdef", "v1.0.1", "v1.10.0", "v2.0.0+incompatible",
		},
		ecosystem.PyPI: {
			"1.0.dev0", "1.0a1.dev1", "1.0a1", "1.0a2", "1.0b1", "1.0rc1", "1.0",
			"1.0.post1.dev0", "1.0.post1", "1.0.1", "1.1", "1.10", "2.0", "1!0.1",
		},
		ecosystem.RubyGems: {
			"0.9", "1.0.a", "1.0.a9", "1.0.a10", "1.0.b", "1.0.b1", "1.0.rc1", "1.0", "1.0.1", "1.1", "1.10", "2",
		},
	}
	for eco, order := range ascending {
		t.Run(string(eco), func(t *testing.T) {
			for i, a := range order {
				if got := Compare(eco, a, a); got != 0 {
					t.Errorf("Compare(%q, %q) = %d, want 0", a, a, got)
				}
				for _, b := range order[i+1:] {
					if got := Compare(eco, a, b); got != -1 {
						t.Errorf("Compare(%q, %q) = %d, want -1", a, b, got)
					}
					if got := Compare(eco, b, a); got != 1 {
						t.Errorf("Compare(%q, %q) = %d, want 1", b, a, got)
					}
				}
			}
		})
	}
}

func TestCompareEquivalentSpellings(t *testing.T) {
	tests := []struct {
		eco  ecosystem.Ecosystem
		a, b string
	}{
		{ecosystem.Npm, "1.0.0+build.1", "1.0.0"},
		{ecosystem.Npm, "v1.2.3", "1.2.3"},
		{ecosystem.Npm, "=1.2.3", "1.2.3"},
		{ecosystem.Cargo, "1.0.0+20130313144700", "1.0.0+exp.sha.5114f85"},
		{ecosystem.Go, "1.2.3", "v1.2.3"},
		{ecosystem.Go, "v2.0.0+incompatible", "v2.0.0"},
		{ecosystem.PyPI, "1.0", "1.0.0"},
		{ecosystem.PyPI, "1.0RC1", "1.0rc1"},
		{ecosystem.PyPI, "1.0c1", "1.0rc1"},
		{ecosystem.PyPI, "1.0alpha2", "1.0a2"},
		{ecosystem.PyPI, "1.0-post1", "1.0.post1"},
		{ecosystem.PyPI, "1.0-1", "1.0.post1"},
		{ecosystem.PyPI, "1.0.post", "1.0.post0"},
		{ecosystem.PyPI, "1.0-dev", "1.0.dev0"},
		{ecosystem.PyPI, "1.0+ubuntu.1", "1.0"},
		{ecosystem.PyPI, "v1.0", "1.0"},
		{ecosystem.PyPI, "0!1.0", "1.0"},
		{ecosystem.RubyGems, "1.0.0", "1"},
		{ecosystem.RubyGems, "1.a", "1.0.a"},
		{ecosystem.RubyGems, "1.0-beta", "1.0.pre.beta"},
	}
	for _, tt := range tests {
		if got := Compare(tt.eco, tt.a, tt.b); got != 0 {
			t.Errorf("%s: Compare(%q, %q) = %d, want 0", tt.eco, tt.a, tt.b, got)
		}
		if got := Compare(tt.eco, tt.b, tt.a); got != 0 {
			t.Errorf("%s: Compare(%q, %q) = %d, want 0", tt.eco, tt.b, tt.a, got)
		}
	}
}

func TestCompareUnparseable(t *testing.T) {
	tests := []struct {
		eco        ecosystem.Ecosystem
		valid, bad string
	}{
		{ecosystem.Npm, "1.0.0", "not-a-version"},
		{ecosystem.Npm, "1.0.0", "1.0.0.0"},
		{ecosystem.Cargo, "1.0.0", "01.0.0"},
		{ecosystem.Go, "v1.0.0", "master"},
		{ecosystem.PyPI, "1.0", "1.0-foo"},
		{ecosystem.PyPI, "1.0", "1.99999999999999999999999"},
		{ecosystem.RubyGems, "1.0", "1..0"},
		{ecosystem.RubyGems, "1.0", "junk!"},
	}
	for _, tt := range tests {
		if got := Compare(tt.eco, tt.valid, tt.bad); got != -1 {
			t.Errorf("%s: Compare(%q, %q) = %d, want -1", tt.eco, tt.valid, tt.bad, got)
		}
		if got := Compare(tt.eco, tt.bad, tt.valid); got != 1 {
			t.Errorf("%s: Compare(%q, %q) = %d, want 1", tt.eco, tt.bad, tt.valid, got)
		}
	}
	for _, eco := range append(ecosystem.All(), "unknown") {
		if got := Compare(eco, "zzz", "aaa"); got != 1 {
			t.Errorf("%s: two unparseable versions: Compare(zzz, aaa) = %d, want 1", eco, got)
		}
	}
}

func TestKeyMatchesCompare(t *testing.T) {
	semverCorpus := append(product(
		[]string{"", "v", "=", " "},
		[]string{"1", "1.2", "1.2.0", "1.10.0", "01.2.0", "0.0.0"},
		[]string{"", "-rc.1", "-alpha", "-alpha.1", "-0", "-01", "-x.7.z.92"},
		[]string{"", "+b.5", "+incompatible", "+"},
	), "v0.0.0-20190101000000-abcdefabcdef", "v1.0.1-0.20200101000000-abcdefabcdef", "1.0.0.0", "master")
	corpora := map[ecosystem.Ecosystem][]string{
		ecosystem.Npm:   semverCorpus,
		ecosystem.Cargo: semverCorpus,
		ecosystem.Go:    semverCorpus,
		ecosystem.PyPI: append(product(
			[]string{"", "v", "0!", "1!"},
			[]string{"1", "1.0", "1.0.0", "1.2"},
			[]string{"", "a1", "alpha1", "rc1", "c1", "-preview"},
			[]string{"", ".post1", "-1", "post"},
			[]string{"", ".dev0", "dev"},
			[]string{"", "+l.1"},
		), "1.0-foo", "1.99999999999999999999999", "1.0RC1", "1.0.post"),
		ecosystem.RubyGems: append(product(
			[]string{"0", "1", "01", "1.0", "1.0.0"},
			[]string{"", ".a", ".a9", ".0.a", ".b1", ".rc1", ".pre", "-beta", "-beta.1", "a", ".1", ".10"},
			[]string{"", ".0", ".1"},
		), "", "1..0", "junk!", "1.0.A"),
	}
	tokens := []string{"0", "1", "01", "10", ".", "-", "_", "+", "!", "=", " ", "v", "a", "b", "c", "rc", "alpha", "pre", "post", "dev", "r", "x"}
	rng := rand.New(rand.NewPCG(1, 1))
	var junk []string
	for range 300 {
		var b strings.Builder
		for range 1 + rng.IntN(6) {
			b.WriteString(tokens[rng.IntN(len(tokens))])
		}
		junk = append(junk, b.String())
	}

	for eco, corpus := range corpora {
		corpus = slices.Concat(corpus, junk)
		vs := make([]Version, len(corpus))
		for i, s := range corpus {
			vs[i] = Parse(eco, s)
		}
		equalSpellings := 0
		for i := range vs {
			for j := i + 1; j < len(vs); j++ {
				equal := vs[i].Compare(vs[j]) == 0
				if sameKey := vs[i].Key() == vs[j].Key(); sameKey != equal {
					t.Fatalf("%s: %q vs %q: same key is %t, but Compare == 0 is %t", eco, corpus[i], corpus[j], sameKey, equal)
				}
				if equal && corpus[i] != corpus[j] {
					equalSpellings++
				}
			}
		}
		if equalSpellings == 0 {
			t.Errorf("%s: no two spellings compare equal, so only one direction was tested", eco)
		}
	}
}

// product returns every concatenation of one string from each part, in order.
func product(parts ...[]string) []string {
	out := []string{""}
	for _, part := range parts {
		var next []string
		for _, prefix := range out {
			for _, s := range part {
				next = append(next, prefix+s)
			}
		}
		out = next
	}
	return out
}
