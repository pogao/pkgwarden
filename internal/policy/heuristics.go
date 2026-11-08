package policy

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	weightTyposquat        = 60
	weightNewPackage       = 30
	weightLowDownloads     = 20
	weightMaintainerChange = 30
	weightInstallScripts   = 15
)

// signal is one heuristic that fired. Its finding's decision is only known
// once every signal for a release has been summed.
type signal struct {
	rule   Rule
	weight int
	reason string
}

func (s signal) finding(d Decision) Finding {
	return Finding{Rule: s.rule, Decision: d, Reason: s.reason}
}

// heuristics records each contributing signal at the decision the total
// reached, because the proxy only shows findings as strict as the verdict.
// Package signals that already cross a threshold go on the package; a
// release whose own signals push it further restates them at its stricter
// decision.
func (e *Engine) heuristics(pkg *Package, a *Assessment) {
	h := e.cfg.Heuristics
	pkgSignals := e.packageSignals(pkg)
	pkgDecision := h.decide(total(pkgSignals))
	if pkgDecision > Allow {
		for _, s := range pkgSignals {
			a.Package.add(s.finding(pkgDecision))
		}
		a.Package.add(h.scoreFinding("package", pkgSignals, pkgDecision))
	}
	for version, own := range releaseSignals(pkg.Releases) {
		all := slices.Concat(pkgSignals, own)
		d := h.decide(total(all))
		if d == Allow {
			continue
		}
		shown := own
		if d > pkgDecision {
			shown = all
		}
		for _, s := range shown {
			a.flag(version, s.finding(d))
		}
		a.flag(version, h.scoreFinding("release", all, d))
	}
}

func (e *Engine) packageSignals(pkg *Package) []signal {
	h := e.cfg.Heuristics
	var out []signal
	if m, ok := resembles(pkg.Ecosystem, pkg.Name); ok {
		out = append(out, signal{RuleTyposquat, weightTyposquat,
			fmt.Sprintf("resembles popular package %q (%s)", m.popular, m.how)})
	}
	if created := firstPublished(pkg); !created.IsZero() && h.NewPackageAge > 0 {
		if age := max(e.now().Sub(created), 0); age < h.NewPackageAge {
			out = append(out, signal{RuleNewPackage, weightNewPackage,
				fmt.Sprintf("first published %s ago, under the %s new-package age", humanDuration(age), humanDuration(h.NewPackageAge))})
		}
	}
	if pkg.WeeklyDownloads >= 0 && pkg.WeeklyDownloads < h.LowWeeklyDownloads {
		out = append(out, signal{RuleLowDownloads, weightLowDownloads,
			fmt.Sprintf("%d downloads last week, below %d", pkg.WeeklyDownloads, h.LowWeeklyDownloads)})
	}
	return out
}

func firstPublished(pkg *Package) time.Time {
	if !pkg.Created.IsZero() {
		return pkg.Created
	}
	var first time.Time
	for _, r := range pkg.Releases {
		if !r.Published.IsZero() && (first.IsZero() || r.Published.Before(first)) {
			first = r.Published
		}
	}
	return first
}

// releaseSignals walks releases in publish order. Releases without a publish
// time cannot be placed in that order and get no release signals, but their
// publishers count as earlier publishers of every release that has one.
func releaseSignals(releases []Release) map[string][]signal {
	earlier := make(map[string]bool)
	remember := func(r Release) {
		for _, p := range r.Publishers {
			earlier[strings.ToLower(p)] = true
		}
	}
	var ordered []Release
	for _, r := range releases {
		if r.Published.IsZero() {
			remember(r)
		} else {
			ordered = append(ordered, r)
		}
	}
	slices.SortStableFunc(ordered, func(a, b Release) int { return a.Published.Compare(b.Published) })

	out := make(map[string][]signal)
	for i, r := range ordered {
		if newcomers := newPublishers(r.Publishers, earlier); len(newcomers) > 0 {
			out[r.Version] = append(out[r.Version], signal{RuleMaintainerChange, weightMaintainerChange,
				fmt.Sprintf("published by %s, who never published an earlier release", quoteList(newcomers))})
		}
		if r.InstallScripts {
			switch {
			case i == 0:
				out[r.Version] = append(out[r.Version], signal{RuleInstallScripts, weightInstallScripts,
					"first release runs install scripts"})
			case !ordered[i-1].InstallScripts:
				out[r.Version] = append(out[r.Version], signal{RuleInstallScripts, weightInstallScripts,
					fmt.Sprintf("runs install scripts, which the previous release %s did not", ordered[i-1].Version)})
			}
		}
		remember(r)
	}
	return out
}

// newPublishers returns the accounts in publishers absent from earlier, each
// once. With no earlier publishers known there is nothing to compare against.
func newPublishers(publishers []string, earlier map[string]bool) []string {
	if len(earlier) == 0 {
		return nil
	}
	var out []string
	named := make(map[string]bool)
	for _, p := range publishers {
		if k := strings.ToLower(p); !earlier[k] && !named[k] {
			named[k] = true
			out = append(out, p)
		}
	}
	return out
}

func quoteList(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = fmt.Sprintf("%q", n)
	}
	if len(q) == 1 {
		return q[0]
	}
	return strings.Join(q[:len(q)-1], ", ") + " and " + q[len(q)-1]
}

func total(signals []signal) int {
	sum := 0
	for _, s := range signals {
		sum += s.weight
	}
	return sum
}

func (h HeuristicsConfig) decide(score int) Decision {
	switch {
	case score <= 0:
		return Allow
	case h.BlockScore > 0 && score >= h.BlockScore:
		return Block
	case h.WarnScore > 0 && score >= h.WarnScore:
		return Warn
	}
	return Allow
}

func (h HeuristicsConfig) scoreFinding(subject string, signals []signal, d Decision) Finding {
	threshold := h.WarnScore
	if d == Block {
		threshold = h.BlockScore
	}
	terms := make([]string, len(signals))
	for i, s := range signals {
		terms[i] = fmt.Sprintf("%s %d", strings.TrimPrefix(string(s.rule), "heuristic/"), s.weight)
	}
	return Finding{Rule: RuleHeuristicScore, Decision: d, Reason: fmt.Sprintf(
		"%s scores %d (%s), reaching the %s threshold %d", subject, total(signals), strings.Join(terms, " + "), d, threshold)}
}
