package advisory

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/pogao/pkgwarden/internal/ecosystem"
)

type sourceFunc func(ctx context.Context, eco ecosystem.Ecosystem, name string) ([]Advisory, error)

func (f sourceFunc) Lookup(ctx context.Context, eco ecosystem.Ecosystem, name string) ([]Advisory, error) {
	return f(ctx, eco, name)
}

func fixed(advs []Advisory, err error) Source {
	return sourceFunc(func(context.Context, ecosystem.Ecosystem, string) ([]Advisory, error) { return advs, err })
}

func TestMergeDeduplicates(t *testing.T) {
	osvResults := func() []Advisory {
		return []Advisory{
			{ID: "GHSA-aaaa", Aliases: []string{"CVE-2024-1"}, Source: "osv", Ecosystem: ecosystem.PyPI,
				Summary: "from osv", Ranges: []Range{{Introduced: "0", Fixed: "1.0"}}},
			{ID: "PYSEC-2024-7", Aliases: []string{"CVE-2024-1"}, Source: "osv", Ecosystem: ecosystem.PyPI,
				Ranges: []Range{{Introduced: "0", Fixed: "1.0"}}},
			{ID: "GHSA-unrelated", Source: "osv", Ecosystem: ecosystem.PyPI, Versions: []string{"0.1"}},
		}
	}
	osv := osvResults()
	ghsa := []Advisory{
		{ID: "GHSA-aaaa", Aliases: []string{"CVE-2024-1"}, Source: "ghsa", Ecosystem: ecosystem.PyPI,
			Severity: SeverityHigh, Versions: []string{"2.0"}},
	}
	openssf := []Advisory{
		{ID: "MAL-2024-3", Aliases: []string{"PYSEC-2024-7"}, Source: "openssf", Kind: Malicious, Ecosystem: ecosystem.PyPI,
			Ranges: []Range{{Introduced: "3.0", LastAffected: "3.1"}}},
	}

	advs, err := Merge(fixed(osv, nil), fixed(ghsa, nil), fixed(openssf, nil)).Lookup(context.Background(), ecosystem.PyPI, "p")
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 2 {
		t.Fatalf("got %d advisories, want 2: %+v", len(advs), advs)
	}
	a := byID(t, advs, "MAL-2024-3")
	if a.Kind != Malicious || a.Source != "osv+ghsa+openssf" || a.Severity != SeverityHigh || a.Summary != "from osv" {
		t.Errorf("unexpected merged advisory %+v", a)
	}
	slices.Sort(a.Aliases)
	if want := []string{"CVE-2024-1", "GHSA-aaaa", "PYSEC-2024-7"}; !slices.Equal(a.Aliases, want) {
		t.Errorf("aliases = %v, want %v", a.Aliases, want)
	}
	checkAffects(t, a, []string{"0.5", "2.0", "3.0", "3.1"}, []string{"1.0", "1.5", "3.2"})
	checkAffects(t, byID(t, advs, "GHSA-unrelated"), []string{"0.1"}, []string{"0.5"})

	if !reflect.DeepEqual(osv, osvResults()) {
		t.Errorf("Merge mutated a source's results")
	}
}

func TestMergeAffectsAllWins(t *testing.T) {
	advs, err := Merge(
		fixed([]Advisory{{ID: "MAL-2022-1", Source: "openssf", Kind: Malicious, Ecosystem: ecosystem.Npm}}, nil),
		fixed([]Advisory{{ID: "GHSA-x", Aliases: []string{"MAL-2022-1"}, Source: "ghsa", Ecosystem: ecosystem.Npm,
			Ranges: []Range{{LastAffected: "1.0.1"}}}}, nil),
	).Lookup(context.Background(), ecosystem.Npm, "crossenv")
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 {
		t.Fatalf("got %d advisories, want 1", len(advs))
	}
	checkAffects(t, advs[0], []string{"0.1.0", "1.0.1", "2.0.0"}, nil)
}

func TestMergePartialFailure(t *testing.T) {
	boom := errors.New("ghsa rate limited")
	advs, err := Merge(
		fixed([]Advisory{{ID: "OSV-1", Source: "osv"}}, nil),
		fixed(nil, boom),
	).Lookup(context.Background(), ecosystem.Npm, "p")
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want it to wrap %v", err, boom)
	}
	if len(advs) != 1 || advs[0].ID != "OSV-1" {
		t.Errorf("advisories = %+v, want the healthy source's results", advs)
	}
}

func TestMergeTakesHighestSeverity(t *testing.T) {
	tests := []struct {
		name          string
		first, second Severity
		want          Severity
	}{
		{"later source rates higher", SeverityMedium, SeverityHigh, SeverityHigh},
		{"first source rates higher", SeverityCritical, SeverityLow, SeverityCritical},
		{"first source unrated", SeverityUnknown, SeverityMedium, SeverityMedium},
		{"both unrated", SeverityUnknown, SeverityUnknown, SeverityUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			advs, err := Merge(
				fixed([]Advisory{{ID: "GHSA-aaaa", Aliases: []string{"CVE-2024-1"}, Source: "osv", Severity: tt.first}}, nil),
				fixed([]Advisory{{ID: "CVE-2024-1", Source: "ghsa", Severity: tt.second}}, nil),
			).Lookup(context.Background(), ecosystem.Npm, "p")
			if err != nil {
				t.Fatal(err)
			}
			if len(advs) != 1 || advs[0].Severity != tt.want {
				t.Errorf("merged = %+v, want one advisory rated %v", advs, tt.want)
			}
		})
	}
}
