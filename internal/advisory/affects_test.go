package advisory

import (
	"testing"

	"github.com/pogao/pkgwarden/internal/ecosystem"
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
