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
	// Canonical is the name the package declares for itself when Name is
	// another spelling that the registry also serves, and "" otherwise.
	// Advisories are looked up under both names.
	Canonical string
	// Created is when the package was first published; zero when unknown.
	Created time.Time
	// WeeklyDownloads is a recent weekly download estimate, or UnknownDownloads.
	WeeklyDownloads int64
	Releases        []Release
}

// Release is one published version of a Package.
type Release struct {
	Version string
	// Published is the upload time, the earliest one when the release has
	// several files; zero when unknown.
	Published time.Time
	// Files lists the release's files for registries that accept new files
	// for an existing version, each at its own time. Nil means the release
	// is one file uploaded at Published.
	Files []File
	// Publishers are the accounts that published or maintain this release;
	// nil when the registry does not say.
	Publishers []string
	// InstallScripts reports whether installing runs package code (npm
	// preinstall, install and postinstall scripts).
	InstallScripts bool
}

// File is one uploaded file of a Release.
type File struct {
	Name string
	// Published is the upload time of this file; zero when unknown.
	Published time.Time
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
	// heldBack blocks each file still inside the cooldown in a release
	// that is past it.
	heldBack map[fileKey]Finding
}

type fileKey struct{ version, name string }

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

// File returns the verdict for the file name of version: the release
// verdict, plus a block when that file is still inside the cooldown. A name
// the release does not list gets the release verdict.
func (a *Assessment) File(version, name string) Verdict {
	v := a.Release(version)
	if f, ok := a.heldBack[fileKey{version, name}]; ok {
		v.add(f)
	}
	return v
}

// Allowed reports whether version may be served.
func (a *Assessment) Allowed(version string) bool {
	return a.Release(version).Decision != Block
}
