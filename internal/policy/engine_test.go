package policy

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pogao/pkgwarden/internal/advisory"
	"github.com/pogao/pkgwarden/internal/ecosystem"
)

var testNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func daysAgo(n int) time.Time { return testNow.Add(-time.Duration(n) * 24 * time.Hour) }

type fakeSource struct {
	advs []advisory.Advisory
	err  error
}

func (f fakeSource) Lookup(context.Context, ecosystem.Ecosystem, string) ([]advisory.Advisory, error) {
	return f.advs, f.err
}

func newTestEngine(cfg Config, src advisory.Source) *Engine {
	if src == nil {
		src = fakeSource{}
	}
	e := New(cfg, src)
	e.now = func() time.Time { return testNow }
	return e
}

// shown returns the findings a client is told about: those as strict as the
// verdict, matching what the proxy prints.
func shown(v Verdict) []Finding {
	if v.Decision == Allow {
		return nil
	}
	var out []Finding
	for _, f := range v.Findings {
		if f.Decision >= v.Decision {
			out = append(out, f)
		}
	}
	return out
}

func shownRules(v Verdict) []Rule {
	var out []Rule
	for _, f := range shown(v) {
		out = append(out, f.Rule)
	}
	slices.Sort(out)
	return out
}

func sortedRules(rs ...Rule) []Rule {
	slices.Sort(rs)
	return rs
}

func shownText(v Verdict) string {
	var parts []string
	for _, f := range shown(v) {
		parts = append(parts, string(f.Rule)+": "+f.Reason)
	}
	return strings.Join(parts, "; ")
}

func assertDecision(t *testing.T, a *Assessment, version string, want Decision) Verdict {
	t.Helper()
	v := a.Release(version)
	if v.Decision != want {
		t.Errorf("%s: decision %s, want %s (findings %+v)", version, v.Decision, want, v.Findings)
	}
	return v
}

func assertMentions(t *testing.T, v Verdict, substrings ...string) {
	t.Helper()
	text := shownText(v)
	for _, s := range substrings {
		if !strings.Contains(text, s) {
			t.Errorf("reasons %q do not mention %q", text, s)
		}
	}
}

func TestCooldown(t *testing.T) {
	e := newTestEngine(Config{Cooldown: 7 * 24 * time.Hour}, nil)
	a := e.Assess(context.Background(), &Package{
		Ecosystem: ecosystem.Npm, Name: "left-pad",
		Releases: []Release{
			{Version: "1.0.0", Published: daysAgo(30)},
			{Version: "1.1.0", Published: daysAgo(2)},
			{Version: "1.2.0"},
		},
	})
	assertDecision(t, a, "1.0.0", Allow)
	assertMentions(t, assertDecision(t, a, "1.1.0", Block), "cooldown: published 2d ago")
	assertMentions(t, assertDecision(t, a, "1.2.0", Block), "cooldown: publish time unknown")
}

func TestAdvisories(t *testing.T) {
	releases := []Release{
		{Version: "1.0.0", Published: daysAgo(400)},
		{Version: "1.1.0", Published: daysAgo(300)},
	}
	malicious := advisory.Advisory{ID: "MAL-2026-1", Source: "openssf", Kind: advisory.Malicious, Versions: []string{"1.1.0"}}
	vuln := advisory.Advisory{ID: "GHSA-aaaa-bbbb-cccc", Source: "ghsa", Kind: advisory.Vulnerability, Severity: "HIGH", Versions: []string{"1.0.0"}}
	everything := advisory.Advisory{ID: "MAL-2026-2", Source: "osv", Kind: advisory.Malicious}

	tests := []struct {
		name      string
		advs      []advisory.Advisory
		blockVuln bool
		want      map[string]Decision
		mention   string
	}{
		{"malicious blocks even when vulnerabilities only warn", []advisory.Advisory{malicious}, false,
			map[string]Decision{"1.0.0": Allow, "1.1.0": Block}, "MAL-2026-1 (malicious, via openssf)"},
		{"vulnerability blocks when configured", []advisory.Advisory{vuln}, true,
			map[string]Decision{"1.0.0": Block, "1.1.0": Allow}, "GHSA-aaaa-bbbb-cccc (high vulnerability, via ghsa)"},
		{"vulnerability warns otherwise", []advisory.Advisory{vuln}, false,
			map[string]Decision{"1.0.0": Warn, "1.1.0": Allow}, "GHSA-aaaa-bbbb-cccc"},
		{"advisory without versions or ranges blocks every release", []advisory.Advisory{everything}, false,
			map[string]Decision{"1.0.0": Block, "1.1.0": Block}, "MAL-2026-2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newTestEngine(Config{BlockVulnerabilities: tt.blockVuln}, fakeSource{advs: tt.advs})
			a := e.Assess(context.Background(), &Package{Ecosystem: ecosystem.Npm, Name: "left-pad", Releases: releases})
			for version, want := range tt.want {
				v := assertDecision(t, a, version, want)
				if want != Allow {
					assertMentions(t, v, "advisory: "+tt.mention)
				}
			}
		})
	}
}

func TestAdvisoryWithoutVersionsBlocksThePackage(t *testing.T) {
	e := newTestEngine(Config{}, fakeSource{advs: []advisory.Advisory{{ID: "MAL-2026-3", Source: "openssf", Kind: advisory.Malicious}}})
	a := e.Assess(context.Background(), &Package{Ecosystem: ecosystem.PyPI, Name: "evil", Releases: []Release{{Version: "0.1", Published: daysAgo(90)}}})
	if a.Package.Decision != Block {
		t.Errorf("package decision %s, want block", a.Package.Decision)
	}
}

func TestAdvisoryLookupFailure(t *testing.T) {
	src := fakeSource{
		advs: []advisory.Advisory{{ID: "MAL-2026-4", Source: "osv", Kind: advisory.Malicious, Versions: []string{"2.0.0"}}},
		err:  errors.New("ghsa: 503 Service Unavailable"),
	}
	pkg := &Package{Ecosystem: ecosystem.Npm, Name: "left-pad", Releases: []Release{
		{Version: "1.0.0", Published: daysAgo(400)},
		{Version: "2.0.0", Published: daysAgo(300)},
	}}

	t.Run("fails closed by default", func(t *testing.T) {
		a := newTestEngine(Config{}, src).Assess(context.Background(), pkg)
		assertMentions(t, assertDecision(t, a, "1.0.0", Block), "advisory-lookup: advisory lookup failed: ghsa: 503")
	})
	t.Run("fail open warns and still applies partial results", func(t *testing.T) {
		a := newTestEngine(Config{FailOpen: true}, src).Assess(context.Background(), pkg)
		assertMentions(t, assertDecision(t, a, "1.0.0", Warn), "advisory lookup failed")
		assertMentions(t, assertDecision(t, a, "2.0.0", Block), "MAL-2026-4")
	})
}

func TestAllowlistBypassesEveryCheck(t *testing.T) {
	cfg := Config{
		Cooldown:   7 * 24 * time.Hour,
		Heuristics: defaultHeuristics(),
		Allow:      map[ecosystem.Ecosystem][]string{ecosystem.PyPI: {"internal_tool"}},
	}
	src := fakeSource{advs: []advisory.Advisory{{ID: "MAL-2026-5", Kind: advisory.Malicious}}}
	a := newTestEngine(cfg, src).Assess(context.Background(), &Package{
		Ecosystem: ecosystem.PyPI, Name: "Internal.Tool", WeeklyDownloads: 0,
		Releases: []Release{{Version: "1.0", Published: daysAgo(1)}},
	})
	assertDecision(t, a, "1.0", Allow)
}

func TestUnknownReleaseIsBlocked(t *testing.T) {
	a := newTestEngine(Config{}, nil).Assess(context.Background(), &Package{
		Ecosystem: ecosystem.Cargo, Name: "serde", Releases: []Release{{Version: "1.0.0", Published: daysAgo(900)}},
	})
	assertMentions(t, assertDecision(t, a, "9.9.9", Block), "unknown-release: version 9.9.9 is not published upstream")
}

// defaultHeuristics mirrors the CLI defaults.
func defaultHeuristics() HeuristicsConfig {
	return HeuristicsConfig{Enabled: true, NewPackageAge: 30 * 24 * time.Hour, LowWeeklyDownloads: 100, WarnScore: 30, BlockScore: 70}
}

func assessHeuristics(pkg *Package) *Assessment {
	return newTestEngine(Config{Heuristics: defaultHeuristics()}, nil).Assess(context.Background(), pkg)
}

func TestHeuristicsBlockTyposquatScenario(t *testing.T) {
	a := assessHeuristics(&Package{
		Ecosystem: ecosystem.Npm, Name: "lodahs", Created: daysAgo(3), WeeklyDownloads: 12,
		Releases: []Release{{Version: "4.17.21", Published: daysAgo(3), Publishers: []string{"evil"}}},
	})
	v := assertDecision(t, a, "4.17.21", Block)
	if got, want := shownRules(v), sortedRules(RuleTyposquat, RuleNewPackage, RuleLowDownloads, RuleHeuristicScore); !slices.Equal(got, want) {
		t.Errorf("shown rules %v, want %v", got, want)
	}
	assertMentions(t, v,
		`resembles popular package "lodash"`,
		"first published 3d ago",
		"12 downloads last week",
		"scores 110", "block threshold 70")
}

func TestHeuristicsAllowEstablishedPopularPackage(t *testing.T) {
	a := assessHeuristics(&Package{
		Ecosystem: ecosystem.Npm, Name: "lodash", Created: daysAgo(5000), WeeklyDownloads: 60_000_000,
		Releases: []Release{
			{Version: "4.17.20", Published: daysAgo(2000), Publishers: []string{"jdalton"}},
			{Version: "4.17.21", Published: daysAgo(1900), Publishers: []string{"jdalton"}},
		},
	})
	for _, version := range []string{"4.17.20", "4.17.21"} {
		if v := assertDecision(t, a, version, Allow); len(v.Findings) != 0 {
			t.Errorf("%s: unexpected findings %+v", version, v.Findings)
		}
	}
}

func TestHeuristicsMaintainerChangeAffectsOnlyThatRelease(t *testing.T) {
	a := assessHeuristics(&Package{
		Ecosystem: ecosystem.Npm, Name: "acme-widgets", Created: daysAgo(900), WeeklyDownloads: 5000,
		Releases: []Release{
			{Version: "1.2.0", Published: daysAgo(10), Publishers: []string{"mallory"}},
			{Version: "1.0.0", Published: daysAgo(800), Publishers: []string{"alice"}},
			{Version: "1.1.0", Published: daysAgo(400), Publishers: []string{"Alice"}},
		},
	})
	assertDecision(t, a, "1.0.0", Allow)
	assertDecision(t, a, "1.1.0", Allow)
	v := assertDecision(t, a, "1.2.0", Warn)
	assertMentions(t, v, `published by "mallory", who never published an earlier release`, "warn threshold 30")
}

func TestHeuristicsWarnBand(t *testing.T) {
	a := assessHeuristics(&Package{
		Ecosystem: ecosystem.Npm, Name: "acme-widgets", Created: daysAgo(10), WeeklyDownloads: 5000,
		Releases: []Release{{Version: "0.1.0", Published: daysAgo(10)}},
	})
	if a.Package.Decision != Warn {
		t.Errorf("package decision %s, want warn", a.Package.Decision)
	}
	v := assertDecision(t, a, "0.1.0", Warn)
	if got, want := shownRules(v), sortedRules(RuleNewPackage, RuleHeuristicScore); !slices.Equal(got, want) {
		t.Errorf("shown rules %v, want %v", got, want)
	}
	assertMentions(t, v, "first published 10d ago, under the 30d new-package age", "scores 30", "warn threshold 30")
}

func TestHeuristicsReleaseSignalsEscalateOverPackageWarning(t *testing.T) {
	a := assessHeuristics(&Package{
		Ecosystem: ecosystem.Npm, Name: "acme-widgets", Created: daysAgo(20), WeeklyDownloads: 5000,
		Releases: []Release{
			{Version: "1.0.0", Published: daysAgo(20), Publishers: []string{"alice"}},
			{Version: "1.0.1", Published: daysAgo(1), Publishers: []string{"alice", "mallory"}, InstallScripts: true},
		},
	})
	assertDecision(t, a, "1.0.0", Warn)
	v := assertDecision(t, a, "1.0.1", Block)
	if got, want := shownRules(v), sortedRules(RuleNewPackage, RuleMaintainerChange, RuleInstallScripts, RuleHeuristicScore); !slices.Equal(got, want) {
		t.Errorf("shown rules %v, want %v", got, want)
	}
	assertMentions(t, v,
		"first published 20d ago",
		`published by "mallory"`,
		"runs install scripts, which the previous release 1.0.0 did not",
		"scores 75", "block threshold 70")
}

func TestHeuristicsQuietCases(t *testing.T) {
	tests := []struct {
		name string
		pkg  Package
	}{
		{"install scripts alone stay under the warn threshold", Package{
			Created: daysAgo(900), WeeklyDownloads: 5000,
			Releases: []Release{
				{Version: "1.0.0", Published: daysAgo(800)},
				{Version: "1.1.0", Published: daysAgo(10), InstallScripts: true},
			},
		}},
		{"install scripts kept from the previous release", Package{
			Created: daysAgo(900), WeeklyDownloads: 5000,
			Releases: []Release{
				{Version: "1.0.0", Published: daysAgo(800), InstallScripts: true},
				{Version: "1.1.0", Published: daysAgo(10), InstallScripts: true, Publishers: []string{"bob"}},
			},
		}},
		{"unknown download counts are not low", Package{
			Created: daysAgo(900), WeeklyDownloads: UnknownDownloads,
			Releases: []Release{{Version: "1.0.0", Published: daysAgo(800)}},
		}},
		{"maintainer change needs publishers on earlier releases", Package{
			Created: daysAgo(900), WeeklyDownloads: 5000,
			Releases: []Release{
				{Version: "1.0.0", Published: daysAgo(800)},
				{Version: "1.1.0", Published: daysAgo(10), Publishers: []string{"mallory"}},
			},
		}},
		{"unknown creation and publish times are not new", Package{
			WeeklyDownloads: 5000,
			Releases:        []Release{{Version: "1.0.0"}},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := tt.pkg
			pkg.Ecosystem, pkg.Name = ecosystem.Npm, "acme-widgets"
			a := assessHeuristics(&pkg)
			for _, r := range pkg.Releases {
				if v := a.Release(r.Version); len(v.Findings) != 0 {
					t.Errorf("%s: unexpected findings %+v", r.Version, v.Findings)
				}
			}
		})
	}
}

func TestHeuristicsNewPackageFallsBackToFirstRelease(t *testing.T) {
	a := assessHeuristics(&Package{
		Ecosystem: ecosystem.PyPI, Name: "acme-widgets", WeeklyDownloads: UnknownDownloads,
		Releases: []Release{
			{Version: "0.2", Published: daysAgo(2)},
			{Version: "0.1", Published: daysAgo(5)},
		},
	})
	v := assertDecision(t, a, "0.2", Warn)
	if got, want := shownRules(v), sortedRules(RuleNewPackage, RuleHeuristicScore); !slices.Equal(got, want) {
		t.Errorf("shown rules %v, want %v (unknown downloads must not count as low)", got, want)
	}
	assertMentions(t, v, "first published 5d ago")
}

func TestHeuristicsFirstReleaseWithInstallScripts(t *testing.T) {
	a := assessHeuristics(&Package{
		Ecosystem: ecosystem.Npm, Name: "acme-widgets", Created: daysAgo(5), WeeklyDownloads: 5000,
		Releases: []Release{{Version: "0.1.0", Published: daysAgo(5), InstallScripts: true}},
	})
	assertMentions(t, assertDecision(t, a, "0.1.0", Warn), "first release runs install scripts", "release scores 45")
}
