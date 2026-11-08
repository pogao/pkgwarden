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
	a := &Assessment{releases: make(map[string]Verdict, len(pkg.Releases))}
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

func (e *Engine) cooldown(pkg *Package, a *Assessment) {
	if e.cfg.Cooldown <= 0 {
		return
	}
	now := e.now()
	for _, r := range pkg.Releases {
		switch age := max(now.Sub(r.Published), 0); {
		case r.Published.IsZero():
			a.flag(r.Version, Finding{Rule: RuleCooldown, Decision: Block, Reason: "publish time unknown, so the cooldown cannot be verified"})
		case age < e.cfg.Cooldown:
			a.flag(r.Version, Finding{Rule: RuleCooldown, Decision: Block, Reason: fmt.Sprintf(
				"published %s ago, inside the %s cooldown", humanDuration(age), humanDuration(e.cfg.Cooldown))})
		}
	}
}

func (e *Engine) knownBad(ctx context.Context, pkg *Package, a *Assessment) {
	advs, err := e.advisories.Lookup(ctx, pkg.Ecosystem, pkg.Name)
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
