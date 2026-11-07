package policy

import (
	"context"
	"time"

	"github.com/pogao/pkgwarden/internal/advisory"
	"github.com/pogao/pkgwarden/internal/ecosystem"
)

// Config tunes the engine. The zero value disables every check.
type Config struct {
	// Cooldown is the minimum age a release must reach before it is served.
	Cooldown time.Duration
	// BlockVulnerabilities blocks releases with known vulnerabilities.
	// Malicious releases are always blocked; when false, vulnerable ones only warn.
	BlockVulnerabilities bool
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
	panic("TODO")
}
