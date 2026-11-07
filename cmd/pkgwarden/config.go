package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pogao/pkgwarden/internal/advisory"
	"github.com/pogao/pkgwarden/internal/ecosystem"
	"github.com/pogao/pkgwarden/internal/policy"
)

type config struct {
	listen      string
	publicURL   string
	metadataTTL time.Duration
	advisoryTTL time.Duration
	logLevel    string

	osvURL         string
	ghsaToken      string
	openSSF        bool
	openSSFRefresh time.Duration

	policy policy.Config
}

// parseConfig reads flags, each of which can also be set through an
// environment variable named PKGWARDEN_<FLAG> (upper case, dashes as
// underscores). Command-line flags win over the environment. -ghsa-token
// falls back to GITHUB_TOKEN when neither sets it.
func parseConfig(args []string) (*config, error) {
	var (
		c             config
		allow         string
		blockSeverity string
		h             = &c.policy.Heuristics
	)
	fs := flag.NewFlagSet("pkgwarden", flag.ContinueOnError)
	fs.StringVar(&c.listen, "listen", ":8080", "address to listen on")
	fs.StringVar(&c.publicURL, "public-url", "", "externally visible base URL, used in rewritten download links (default: derived from each request)")
	fs.DurationVar(&c.metadataTTL, "metadata-ttl", 5*time.Minute, "how long upstream metadata is cached")
	fs.DurationVar(&c.advisoryTTL, "advisory-ttl", time.Hour, "how long advisory lookups are cached")
	fs.StringVar(&c.logLevel, "log-level", "info", "debug, info, warn or error")

	fs.DurationVar(&c.policy.Cooldown, "cooldown", 7*24*time.Hour, "minimum age of a release before it is served (0 disables)")
	fs.StringVar(&blockSeverity, "block-severity", "high", "lowest vulnerability rating that blocks a release: low, medium, high, critical or none (lower and unrated ones warn; malicious releases always block)")
	fs.BoolVar(&c.policy.FailOpen, "fail-open", false, "serve packages when advisory sources are unreachable")
	fs.StringVar(&allow, "allow", "", "comma-separated ecosystem:name packages exempt from every check, e.g. npm:my-internal-lib")

	fs.BoolVar(&h.Enabled, "heuristics", true, "score suspicious-package signals")
	fs.DurationVar(&h.NewPackageAge, "new-package-age", 30*24*time.Hour, "packages younger than this count as new")
	fs.Int64Var(&h.LowWeeklyDownloads, "low-downloads", 100, "weekly downloads below this count as unpopular")
	fs.IntVar(&h.WarnScore, "heuristics-warn", 30, "heuristic score at which a release is served with a warning")
	fs.IntVar(&h.BlockScore, "heuristics-block", 70, "heuristic score at which a release is blocked")

	fs.StringVar(&c.osvURL, "osv-url", "https://api.osv.dev", "OSV API base URL")
	fs.StringVar(&c.ghsaToken, "ghsa-token", "", "GitHub token; enables direct GitHub Advisory Database lookups (default $GITHUB_TOKEN)")
	fs.BoolVar(&c.openSSF, "openssf", false, "sync the OpenSSF malicious-packages dataset locally (about 300 MB download per refresh)")
	fs.DurationVar(&c.openSSFRefresh, "openssf-refresh", 6*time.Hour, "how often the OpenSSF dataset is refreshed")

	var envErr error
	fs.VisitAll(func(f *flag.Flag) {
		key := "PKGWARDEN_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if v, ok := os.LookupEnv(key); ok && envErr == nil {
			if err := fs.Set(f.Name, v); err != nil {
				envErr = fmt.Errorf("%s: %w", key, err)
			}
		}
	})
	if envErr != nil {
		return nil, envErr
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	tokenSet := false
	fs.Visit(func(f *flag.Flag) { tokenSet = tokenSet || f.Name == "ghsa-token" })
	if !tokenSet {
		c.ghsaToken = os.Getenv("GITHUB_TOKEN")
	}

	var err error
	if c.policy.Allow, err = parseAllow(allow); err != nil {
		return nil, err
	}
	if c.policy.BlockSeverity, err = parseBlockSeverity(blockSeverity); err != nil {
		return nil, err
	}
	if h.WarnScore > h.BlockScore {
		return nil, fmt.Errorf("-heuristics-warn (%d) must not exceed -heuristics-block (%d)", h.WarnScore, h.BlockScore)
	}
	if c.policy.Cooldown < 0 {
		return nil, fmt.Errorf("-cooldown must not be negative")
	}
	return &c, nil
}

var blockSeverities = map[string]advisory.Severity{
	"none":     advisory.SeverityUnknown,
	"low":      advisory.SeverityLow,
	"medium":   advisory.SeverityMedium,
	"high":     advisory.SeverityHigh,
	"critical": advisory.SeverityCritical,
}

func parseBlockSeverity(s string) (advisory.Severity, error) {
	sev, ok := blockSeverities[strings.ToLower(strings.TrimSpace(s))]
	if !ok {
		return 0, fmt.Errorf("-block-severity %q: want low, medium, high, critical or none", s)
	}
	return sev, nil
}

func parseAllow(s string) (map[ecosystem.Ecosystem][]string, error) {
	allow := make(map[ecosystem.Ecosystem][]string)
	for entry := range strings.SplitSeq(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		eco, name, ok := strings.Cut(entry, ":")
		if !ok || name == "" {
			return nil, fmt.Errorf("-allow entry %q: want ecosystem:name", entry)
		}
		e, err := ecosystem.Parse(eco)
		if err != nil {
			return nil, fmt.Errorf("-allow entry %q: %w", entry, err)
		}
		allow[e] = append(allow[e], name)
	}
	return allow, nil
}
