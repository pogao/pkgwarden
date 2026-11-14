package policy

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/pogao/pkgwarden/internal/advisory"
	"github.com/pogao/pkgwarden/internal/ecosystem"
	"github.com/pogao/pkgwarden/internal/version"
)

// Config tunes the engine. The zero value disables every check.
type Config struct {
	// Cooldown is the minimum age a release must reach before it is served.
	Cooldown time.Duration
	// BlockSeverity is the lowest rating at which a vulnerability blocks a
	// release; lower-rated and unrated vulnerabilities only warn. The zero
	// value never blocks for vulnerabilities. Malicious releases always block.
	BlockSeverity advisory.Severity
	// FailOpen serves packages when advisory sources cannot be reached,
	// instead of blocking them.
	FailOpen   bool
	Heuristics HeuristicsConfig
	// Allow exempts packages, keyed by ecosystem, from every check.
	Allow map[ecosystem.Ecosystem][]string
}

// HeuristicsConfig scores signals that often accompany malicious packages.
// Each signal that fires adds its weight; the total is compared against the
// warn and block thresholds.
type HeuristicsConfig struct {
	Enabled bool
	// NewPackageAge is the age below which a package counts as new.
	NewPackageAge time.Duration
	// LowWeeklyDownloads is the weekly download count below which a package
	// counts as unpopular.
	LowWeeklyDownloads int64
	WarnScore          int
	BlockScore         int
}

// Engine assesses packages against the configured policy.
type Engine struct {
	cfg        Config
	advisories advisory.Source
	now        func() time.Time
}

// New returns an Engine that consults src for known-bad releases.
func New(cfg Config, src advisory.Source) *Engine {
	return &Engine{cfg: cfg, advisories: src, now: time.Now}
}

// Assess returns the verdict for every release of pkg. Failures to reach an
// advisory source become findings rather than errors.
func (e *Engine) Assess(ctx context.Context, pkg *Package) *Assessment {
	a := &Assessment{releases: make(map[string]Verdict, len(pkg.Releases)), heldBack: make(map[fileKey]Finding)}
	for _, r := range pkg.Releases {
		a.releases[r.Version] = Verdict{}
	}
	if e.allowlisted(pkg) {
		a.Package.add(Finding{Rule: RuleAllowlist, Decision: Allow, Reason: "package is allowlisted"})
		return a
	}
	e.cooldown(pkg, a)
	e.knownBad(ctx, pkg, a)
	if e.cfg.Heuristics.Enabled {
		e.heuristics(pkg, a)
	}
	return a
}

func (a *Assessment) flag(version string, f Finding) {
	v := a.releases[version]
	v.add(f)
	a.releases[version] = v
}

func (e *Engine) allowlisted(pkg *Package) bool {
	name := pkg.Ecosystem.Normalize(pkg.Name)
	return slices.ContainsFunc(e.cfg.Allow[pkg.Ecosystem], func(s string) bool {
		return pkg.Ecosystem.Normalize(s) == name
	})
}

// cooldown blocks a release whose earliest upload is too young, counting
// from the time upstream first served it when that is later. A release past
// the cooldown can still hold a younger file. That file is blocked on its
// own upload time, and the release warns about it while its other files are
// served.
func (e *Engine) cooldown(pkg *Package, a *Assessment) {
	if e.cfg.Cooldown <= 0 {
		return
	}
	now := e.now()
	for _, r := range pkg.Releases {
		if reason, young := e.releaseTooYoung(r, now); young {
			a.flag(r.Version, Finding{Rule: RuleCooldown, Decision: Block, Reason: reason})
			continue
		}
		for _, f := range r.Files {
			if reason, young := e.tooYoung(f.Published, now); young {
				reason = f.Name + ": " + reason
				a.heldBack[fileKey{r.Version, f.Name}] = Finding{Rule: RuleCooldown, Decision: Block, Reason: reason}
				a.flag(r.Version, Finding{Rule: RuleCooldown, Decision: Warn, Reason: reason})
			}
		}
	}
}

// releaseTooYoung is tooYoung for r, from FirstSeen when it is after a
// known Published.
func (e *Engine) releaseTooYoung(r Release, now time.Time) (string, bool) {
	if r.Published.IsZero() || !r.FirstSeen.After(r.Published) {
		return e.tooYoung(r.Published, now)
	}
	age := max(now.Sub(r.FirstSeen), 0)
	if age >= e.cfg.Cooldown {
		return "", false
	}
	return fmt.Sprintf("first seen upstream %s ago (%s), inside the %s cooldown",
		humanDuration(age), r.FirstSeen.UTC().Format(time.RFC3339), humanDuration(e.cfg.Cooldown)), true
}

// tooYoung reports whether something published at t is inside the
// cooldown, and why.
func (e *Engine) tooYoung(t, now time.Time) (string, bool) {
	switch age := max(now.Sub(t), 0); {
	case t.IsZero():
		return "publish time unknown, so the cooldown cannot be verified", true
	case age < e.cfg.Cooldown:
		return fmt.Sprintf("published %s ago, inside the %s cooldown", humanDuration(age), humanDuration(e.cfg.Cooldown)), true
	}
	return "", false
}

func (e *Engine) knownBad(ctx context.Context, pkg *Package, a *Assessment) {
	names := []string{pkg.Name}
	if pkg.Canonical != "" {
		names = append(names, pkg.Canonical)
	}
	advs, err := advisory.LookupAll(ctx, e.advisories, pkg.Ecosystem, names...)
	if err != nil {
		d := Block
		if e.cfg.FailOpen {
			d = Warn
		}
		a.Package.add(Finding{Rule: RuleAdvisoryLookup, Decision: d, Reason: "advisory lookup failed: " + err.Error()})
	}
	// Keyed by ecosystem because each advisory orders versions by its own.
	parsed := make(map[ecosystem.Ecosystem][]version.Version)
	for _, adv := range advs {
		f := Finding{Rule: RuleVulnerability, Decision: Warn, Reason: describe(adv)}
		switch {
		case adv.Kind == advisory.Malicious:
			f.Rule, f.Decision = RuleMalicious, Block
		case e.cfg.BlockSeverity > advisory.SeverityUnknown && adv.Severity >= e.cfg.BlockSeverity:
			f.Decision = Block
		}
		if len(adv.Versions) == 0 && len(adv.Ranges) == 0 {
			a.Package.add(f)
			continue
		}
		releases, ok := parsed[adv.Ecosystem]
		if !ok {
			releases = make([]version.Version, len(pkg.Releases))
			for i, r := range pkg.Releases {
				releases[i] = version.Parse(adv.Ecosystem, r.Version)
			}
			parsed[adv.Ecosystem] = releases
		}
		m := adv.Matcher()
		for i, r := range pkg.Releases {
			if m.Affects(releases[i]) {
				a.flag(r.Version, f)
			}
		}
	}
}

func describe(adv advisory.Advisory) string {
	kind := adv.Kind.String()
	switch {
	case adv.Severity != advisory.SeverityUnknown:
		kind = strings.ToLower(adv.Severity.String()) + " " + kind
	case adv.Kind == advisory.Vulnerability:
		kind = "unrated " + kind
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%s, via %s)", adv.ID, kind, adv.Source)
	if adv.Summary != "" {
		b.WriteString(": " + adv.Summary)
	}
	if adv.URL != "" {
		b.WriteString(" " + adv.URL)
	}
	return b.String()
}

func humanDuration(d time.Duration) string {
	if d < 24*time.Hour {
		return d.Round(time.Minute).String()
	}
	days := int(d / (24 * time.Hour))
	if h := int((d % (24 * time.Hour)) / time.Hour); h > 0 {
		return fmt.Sprintf("%dd%dh", days, h)
	}
	return fmt.Sprintf("%dd", days)
}
