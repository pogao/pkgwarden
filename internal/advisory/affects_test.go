package advisory

import (
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/pogao/pkgwarden/internal/ecosystem"
	"github.com/pogao/pkgwarden/internal/version"
)

func TestAffects(t *testing.T) {
	tests := []struct {
		name     string
		adv      Advisory
		affected []string
		safe     []string
	}{
		{
			name:     "no versions or ranges covers every release",
			adv:      Advisory{Ecosystem: ecosystem.Npm},
			affected: []string{"0.0.1", "99.0.0"},
		},
		{
			name:     "explicit versions compare by ecosystem rules",
			adv:      Advisory{Ecosystem: ecosystem.PyPI, Versions: []string{"1.0"}},
			affected: []string{"1.0", "1.0.0"},
			safe:     []string{"1.0.1", "0.9"},
		},
		{
			name:     "half-open range",
			adv:      Advisory{Ecosystem: ecosystem.Npm, Ranges: []Range{{Introduced: "1.2.0", Fixed: "1.4.0"}}},
			affected: []string{"1.2.0", "1.3.9", "1.4.0-rc.1"},
			safe:     []string{"1.1.9", "1.2.0-beta.1", "1.4.0", "2.0.0"},
		},
		{
			name:     "closed range with last affected",
			adv:      Advisory{Ecosystem: ecosystem.Cargo, Ranges: []Range{{Introduced: "0", LastAffected: "0.3.1"}}},
			affected: []string{"0.0.1", "0.3.1"},
			safe:     []string{"0.3.2", "1.0.0"},
		},
		{
			name:     "empty introduced starts at the first release",
			adv:      Advisory{Ecosystem: ecosystem.RubyGems, Ranges: []Range{{Fixed: "2.0"}}},
			affected: []string{"0.1", "1.9.9", "2.0.a"},
			safe:     []string{"2.0", "2.0.0", "2.1"},
		},
		{
			name:     "unparseable introduced starts at the first release",
			adv:      Advisory{Ecosystem: ecosystem.Npm, Ranges: []Range{{Introduced: "not-a-version", Fixed: "9.9.9"}}},
			affected: []string{"0.0.1", "1.0.0", "1.0.3", "9.9.8"},
			safe:     []string{"9.9.9", "10.0.0"},
		},
		{
			name:     "open-ended range",
			adv:      Advisory{Ecosystem: ecosystem.Go, Ranges: []Range{{Introduced: "1.5.0"}}},
			affected: []string{"v1.5.0", "v9.0.0"},
			safe:     []string{"v1.4.9", "v1.5.0-0.20200101000000-abcdefabcdef"},
		},
		{
			name: "versions and ranges are a union",
			adv: Advisory{Ecosystem: ecosystem.Npm, Versions: []string{"0.5.0"},
				Ranges: []Range{{Introduced: "1.0.0", Fixed: "1.1.0"}, {Introduced: "2.0.0", Fixed: "2.0.5"}}},
			affected: []string{"0.5.0", "1.0.3", "2.0.4"},
			safe:     []string{"0.5.1", "1.1.0", "2.0.5"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, v := range tt.affected {
				if !tt.adv.Affects(v) {
					t.Errorf("Affects(%q) = false, want true", v)
				}
			}
			for _, v := range tt.safe {
				if tt.adv.Affects(v) {
					t.Errorf("Affects(%q) = true, want false", v)
				}
			}
		})
	}
}

func TestMatcherAgreesWithPairwiseComparison(t *testing.T) {
	semver := []string{"0", "0.1.0", "1.0", "1.0.0", "v1.0.0", "=1.0.0", "1.0.0+build.1", "1.0.0-rc.1", "1.2.3", "1.10.0", "2.0.0-alpha", "2.0.0", "01.0.0", "not-a-version"}
	pools := map[ecosystem.Ecosystem][]string{
		ecosystem.Npm:      semver,
		ecosystem.Cargo:    semver,
		ecosystem.Go:       append(slices.Clip(semver), "v0.0.0-20190101000000-abcdefabcdef", "v1.0.1-0.20200101000000-abcdefabcdef", "v2.0.0+incompatible", "master"),
		ecosystem.PyPI:     {"0", "0.0", "0.dev0", "1.0", "1.0.0", "1.0a1", "1.0alpha1", "1.0rc1", "1.0c1", "1.0.post1", "1.0-1", "1.0.dev0", "1.0+local", "v1.1", "2.0", "1!0.1", "1.0-foo", "junk"},
		ecosystem.RubyGems: {"", "0", "0.a", "1.a", "1.0.a", "1", "1.0", "1.0.0", "1.0-beta", "1.0.pre.beta", "1.0.1", "2", "1..0", "junk!"},
		"unknown":          {"0", "1.0", "1.0.0", "a", "b"},
	}
	rng := rand.New(rand.NewPCG(1, 1))
	for eco, pool := range pools {
		pick := func() string { return pool[rng.IntN(len(pool))] }
		bound := func() string {
			switch rng.IntN(6) {
			case 0, 1:
				return ""
			case 2:
				return "0"
			}
			return pick()
		}
		affected, checked := 0, 0
		for range 300 {
			adv := Advisory{Ecosystem: eco}
			for range rng.IntN(4) {
				adv.Versions = append(adv.Versions, pick())
			}
			for range rng.IntN(3) {
				adv.Ranges = append(adv.Ranges, Range{Introduced: bound(), Fixed: bound(), LastAffected: bound()})
			}
			m := adv.Matcher()
			for _, v := range pool {
				got, want := m.Affects(version.Parse(eco, v)), pairwiseAffects(adv, v)
				if got != want {
					t.Fatalf("%s: %+v: Affects(%q) = %t, want %t", eco, adv, v, got, want)
				}
				checked++
				if got {
					affected++
				}
			}
		}
		if affected == 0 || affected == checked {
			t.Errorf("%s: %d of %d checks affected, so the comparison saw only one answer", eco, affected, checked)
		}
	}
}

// pairwiseAffects answers Affects by comparing v with each listed version
// and range bound in turn.
func pairwiseAffects(a Advisory, v string) bool {
	if len(a.Versions) == 0 && len(a.Ranges) == 0 {
		return true
	}
	if slices.ContainsFunc(a.Versions, func(x string) bool { return version.Compare(a.Ecosystem, v, x) == 0 }) {
		return true
	}
	return slices.ContainsFunc(a.Ranges, func(r Range) bool {
		if r.Introduced != "" && r.Introduced != "0" && version.Parse(a.Ecosystem, r.Introduced).OK() && version.Compare(a.Ecosystem, v, r.Introduced) < 0 {
			return false
		}
		switch {
		case r.Fixed != "":
			return version.Compare(a.Ecosystem, v, r.Fixed) < 0
		case r.LastAffected != "":
			return version.Compare(a.Ecosystem, v, r.LastAffected) <= 0
		}
		return true
	})
}
