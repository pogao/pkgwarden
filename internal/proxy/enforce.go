package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/pogao/pkgwarden/internal/ecosystem"
	"github.com/pogao/pkgwarden/internal/policy"
	"github.com/pogao/pkgwarden/internal/telemetry"
)

// Format is the body format a package manager expects in error responses.
type Format int

const (
	Text Format = iota
	// JSON writes {"error": "..."}, which npm prints verbatim.
	JSON
)

// Stage is the point in a package manager's flow where a verdict applies.
type Stage string

const (
	// StageMetadata is a package document: a packument, a simple index
	// page, a version list, a compact index or a sparse index file.
	StageMetadata Stage = "metadata"
	// StageArtifact is a download of one release's files.
	StageArtifact Stage = "artifact"
)

// Subject names what a verdict is about.
type Subject struct {
	Ecosystem ecosystem.Ecosystem
	Name      string
	// Version is empty for a package-wide verdict.
	Version string
}

// String returns the subject as "npm/left-pad@1.3.0", or "npm/left-pad"
// without a version.
func (s Subject) String() string {
	out := string(s.Ecosystem) + "/" + s.Name
	if s.Version != "" {
		out += "@" + s.Version
	}
	return out
}

// Enforce applies a verdict to a response before anything is written.
// It returns false after writing a 403 when the verdict blocks. A warning
// is passed on in the X-Pkgwarden-Warning header. The 403 message names
// the request ID from ctx, so a developer can hand it to whoever reads
// the logs.
func Enforce(ctx context.Context, w http.ResponseWriter, f Format, stage Stage, s Subject, v policy.Verdict) bool {
	rules := RecordVerdict(w, stage, s, v)
	switch v.Decision {
	case policy.Allow:
		return true
	case policy.Warn:
		w.Header().Set("X-Pkgwarden-Warning", reasons(v))
		slog.WarnContext(ctx, "serving with warnings", verdictAttrs(stage, s, v, rules)...)
		return true
	}
	slog.InfoContext(ctx, "blocked", verdictAttrs(stage, s, v, rules)...)
	msg := blockMessage(s.String(), v, telemetry.RequestID(ctx))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if f == JSON {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": msg})
		return false
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(msg + "\n"))
	return false
}

// RecordVerdict marks the response with the verdict's decision and counts
// it in the decision metrics, for adapters that apply a verdict without
// Enforce. It returns the distinct rules behind a warn or block decision.
func RecordVerdict(w http.ResponseWriter, stage Stage, s Subject, v policy.Verdict) []string {
	w.Header().Set("X-Pkgwarden-Decision", v.Decision.String())
	var rules []string
	if v.Decision != policy.Allow {
		for _, f := range v.Findings {
			if f.Decision >= v.Decision && !slices.Contains(rules, string(f.Rule)) {
				rules = append(rules, string(f.Rule))
			}
		}
	}
	telemetry.RecordDecision(string(s.Ecosystem), string(stage), v.Decision.String(), rules)
	return rules
}

func verdictAttrs(stage Stage, s Subject, v policy.Verdict, rules []string) []any {
	attrs := []any{"ecosystem", string(s.Ecosystem), "package", s.Name}
	if s.Version != "" {
		attrs = append(attrs, "version", s.Version)
	}
	return append(attrs, "stage", string(stage), "rules", rules, "reasons", reasons(v))
}

// maxMessage keeps block messages short enough that clients print them:
// the go command replaces a longer body with "[Truncated: too long.]".
const maxMessage = 600

func blockMessage(subject string, v policy.Verdict, requestID string) string {
	var suffix string
	if requestID != "" {
		suffix = " (request " + requestID + ")"
	}
	msg, sep := "pkgwarden blocked "+subject, ": "
	parts := decisive(v)
	for i, part := range parts {
		if len(part) > 160 {
			part = strings.ToValidUTF8(part[:157], "") + "..."
		}
		if len(msg)+len(sep)+len(part) > maxMessage-60-len(suffix) {
			return msg + fmt.Sprintf("%sand %d more, see /api/v1/check", sep, len(parts)-i) + suffix
		}
		msg += sep + part
		sep = "; "
	}
	return msg + suffix
}

func reasons(v policy.Verdict) string {
	return strings.Join(decisive(v), "; ")
}

// decisive describes the findings that set the verdict's decision.
func decisive(v policy.Verdict) []string {
	var parts []string
	for _, f := range v.Findings {
		if f.Decision >= v.Decision {
			parts = append(parts, string(f.Rule)+": "+f.Reason)
		}
	}
	return parts
}

// BaseURL returns the externally visible URL of the proxy, without a
// trailing slash. A configured public URL wins over request headers.
func BaseURL(r *http.Request, public string) string {
	if public != "" {
		return strings.TrimSuffix(public, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p == "http" || p == "https" {
		scheme = p
	}
	return scheme + "://" + r.Host
}
