package version

import (
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
