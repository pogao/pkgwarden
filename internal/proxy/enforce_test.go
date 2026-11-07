package proxy

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pogao/pkgwarden/internal/ecosystem"
	"github.com/pogao/pkgwarden/internal/policy"
	"github.com/pogao/pkgwarden/internal/telemetry"
	"github.com/pogao/pkgwarden/internal/telemetry/telemetrytest"
)

func TestSubjectString(t *testing.T) {
	tests := []struct {
		s    Subject
		want string
	}{
		{Subject{Ecosystem: ecosystem.Npm, Name: "left-pad", Version: "1.3.0"}, "npm/left-pad@1.3.0"},
		{Subject{Ecosystem: ecosystem.Npm, Name: "@acme/widget"}, "npm/@acme/widget"},
		{Subject{Ecosystem: ecosystem.Go, Name: "golang.org/x/text", Version: "v0.3.6"}, "go/golang.org/x/text@v0.3.6"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("%#v.String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestBlockMessageStaysPrintable(t *testing.T) {
	var v policy.Verdict
	for range 12 {
		v.Findings = append(v.Findings, policy.Finding{Rule: policy.RuleVulnerability, Decision: policy.Block,
			Reason: "GHSA-xxxx-xxxx-xxxx (high vulnerability, via osv): " + strings.Repeat("long summary ", 20)})
	}
	v.Decision = policy.Block
	id := strings.Repeat("r", 64)
	ctx := telemetry.WithRequestID(context.Background(), id)
	s := Subject{Ecosystem: ecosystem.Go, Name: "example.com/m", Version: "v1.0.0"}
	for _, f := range []Format{Text, JSON} {
		w := httptest.NewRecorder()
		if Enforce(ctx, w, f, StageArtifact, s, v) {
			t.Fatal("Enforce allowed a blocking verdict")
		}
		body := strings.TrimSpace(w.Body.String())
		if w.Code != 403 || len(body) > maxMessage || !strings.Contains(body, "more, see /api/v1/check") {
			t.Errorf("format %d: status %d, %d bytes: %q", f, w.Code, len(body), body)
		}
		if !strings.HasSuffix(strings.TrimSuffix(body, `"}`), " (request "+id+")") {
			t.Errorf("format %d: body %q does not end with the request ID", f, body)
		}
	}
}

func TestBlockMessageCountsOnlyBlockingFindings(t *testing.T) {
	const blocking = 12
	var v policy.Verdict
	for i := range blocking {
		v.Findings = append(v.Findings,
			policy.Finding{Rule: policy.RuleVulnerability, Decision: policy.Block,
				Reason: fmt.Sprintf("BLOCK-%02d (high vulnerability, via osv): ", i) + strings.Repeat("long summary ", 20)},
			policy.Finding{Rule: policy.RuleVulnerability, Decision: policy.Warn,
				Reason: fmt.Sprintf("WARN-%02d (low vulnerability, via osv): ", i) + strings.Repeat("long summary ", 20)})
	}
	v.Decision = policy.Block
	w := httptest.NewRecorder()
	Enforce(context.Background(), w, Text, StageArtifact, Subject{Ecosystem: ecosystem.RubyGems, Name: "rack", Version: "2.2.3"}, v)
	body := w.Body.String()
	if strings.Contains(body, "WARN-") {
		t.Errorf("message lists a warn finding: %q", body)
	}
	listed := strings.Count(body, "BLOCK-")
	if listed == 0 || listed == blocking {
		t.Fatalf("message lists %d of %d block findings, want a truncated list: %q", listed, blocking, body)
	}
	if want := fmt.Sprintf("and %d more, see /api/v1/check\n", blocking-listed); !strings.HasSuffix(body, want) {
		t.Errorf("message %q does not end with %q", body, want)
	}
}

func TestEnforceCountsDecisionsAndRules(t *testing.T) {
	cooldown := policy.Finding{Rule: policy.RuleCooldown, Decision: policy.Block, Reason: "published 1d ago"}
	malicious := policy.Finding{Rule: policy.RuleMalicious, Decision: policy.Block, Reason: "MAL-2026-1"}
	vuln := policy.Finding{Rule: policy.RuleVulnerability, Decision: policy.Warn, Reason: "GHSA-1"}
	tests := []struct {
		name     string
		v        policy.Verdict
		decision string
		rules    map[string]float64
	}{
		{"allow counts no rules", policy.Verdict{Decision: policy.Allow}, "allow", nil},
		{"warn counts its rule", policy.Verdict{Decision: policy.Warn, Findings: []policy.Finding{vuln, vuln}}, "warn",
			map[string]float64{"advisory/vulnerability": 1}},
		{"block counts only blocking rules, once each", policy.Verdict{Decision: policy.Block,
			Findings: []policy.Finding{cooldown, malicious, malicious, vuln}}, "block",
			map[string]float64{"cooldown": 1, "advisory/malicious": 1, "advisory/vulnerability": 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := map[string]string{"ecosystem": "cargo", "stage": "metadata", "decision": tt.decision}
			finding := func(rule string) map[string]string {
				return map[string]string{"ecosystem": "cargo", "stage": "metadata", "rule": rule, "decision": tt.decision}
			}
			before := telemetrytest.Value(t, "pkgwarden_decisions_total", decision)
			beforeRules := map[string]float64{}
			for r := range tt.rules {
				beforeRules[r] = telemetrytest.Value(t, "pkgwarden_findings_total", finding(r))
			}
			w := httptest.NewRecorder()
			Enforce(context.Background(), w, Text, StageMetadata, Subject{Ecosystem: ecosystem.Cargo, Name: "serde"}, tt.v)
			if got := w.Header().Get("X-Pkgwarden-Decision"); got != tt.decision {
				t.Errorf("X-Pkgwarden-Decision %q, want %q", got, tt.decision)
			}
			if d := telemetrytest.Value(t, "pkgwarden_decisions_total", decision) - before; d != 1 {
				t.Errorf("decisions_total%v grew by %v, want 1", decision, d)
			}
			for r, want := range tt.rules {
				if d := telemetrytest.Value(t, "pkgwarden_findings_total", finding(r)) - beforeRules[r]; d != want {
					t.Errorf("findings_total{rule=%q} grew by %v, want %v", r, d, want)
				}
			}
		})
	}
}
