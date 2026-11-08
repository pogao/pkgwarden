// Package policy decides which package releases pkgwarden lets through.
package policy

import (
	"time"

	"github.com/pogao/pkgwarden/internal/ecosystem"
)

// UnknownDownloads marks a Package whose registry publishes no download counts.
const UnknownDownloads = -1

// Package is what an ecosystem adapter knows about a package, translated out
// of the registry's wire format.
type Package struct {
	Ecosystem ecosystem.Ecosystem
	Name      string
	// Created is when the package was first published; zero when unknown.
	Created time.Time
	// WeeklyDownloads is a recent weekly download estimate, or UnknownDownloads.
	WeeklyDownloads int64
	Releases        []Release
}

// Release is one published version of a Package.
type Release struct {
	Version string
	// Published is the upload time; zero when unknown.
	Published time.Time
	// Publishers are the accounts that published or maintain this release;
	// nil when the registry does not say.
	Publishers []string
	// InstallScripts reports whether installing runs package code (npm
	// preinstall, install and postinstall scripts).
	InstallScripts bool
}

// Decision is the outcome for a release. Values are ordered by severity so
// the strictest of several decisions is their maximum.
type Decision int

const (
	Allow Decision = iota
	Warn
	Block
)

// MarshalText encodes the decision as its name.
func (d Decision) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

func (d Decision) String() string {
	switch d {
	case Warn:
		return "warn"
	case Block:
		return "block"
	default:
		return "allow"
	}
}

// Rule names the check that produced a Finding.
type Rule string

const (
	RuleAllowlist        Rule = "allowlist"
	RuleCooldown         Rule = "cooldown"
	RuleMalicious        Rule = "advisory/malicious"
	RuleVulnerability    Rule = "advisory/vulnerability"
	RuleAdvisoryLookup   Rule = "advisory-lookup"
	RuleNewPackage       Rule = "heuristic/new-package"
	RuleLowDownloads     Rule = "heuristic/low-downloads"
	RuleTyposquat        Rule = "heuristic/typosquat"
	RuleMaintainerChange Rule = "heuristic/maintainer-change"
	RuleInstallScripts   Rule = "heuristic/install-scripts"
	RuleHeuristicScore   Rule = "heuristic/score"
	RuleUnknownRelease   Rule = "unknown-release"
)

// Finding is one reason behind a Verdict.
type Finding struct {
	Rule     Rule     `json:"rule"`
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason"`
}

// Verdict is the combined decision for a release and the findings behind it.
type Verdict struct {
	Decision Decision  `json:"decision"`
	Findings []Finding `json:"findings,omitempty"`
}

func (v *Verdict) add(f Finding) {
	v.Findings = append(v.Findings, f)
	v.Decision = max(v.Decision, f.Decision)
}

func (v Verdict) merge(o Verdict) Verdict {
	out := Verdict{Decision: v.Decision, Findings: append([]Finding(nil), v.Findings...)}
	for _, f := range o.Findings {
		out.add(f)
	}
	return out
}

// Assessment holds the verdict for every release of one package.
type Assessment struct {
	// Package carries findings that apply to every release.
	Package  Verdict
	releases map[string]Verdict
}

// Release returns the verdict for version, including package-wide findings.
// A version the registry did not report is blocked.
func (a *Assessment) Release(version string) Verdict {
	rv, ok := a.releases[version]
	if !ok {
		rv = Verdict{}
		rv.add(Finding{Rule: RuleUnknownRelease, Decision: Block, Reason: "version " + version + " is not published upstream"})
	}
	return a.Package.merge(rv)
}

// Allowed reports whether version may be served.
func (a *Assessment) Allowed(version string) bool {
	return a.Release(version).Decision != Block
}
