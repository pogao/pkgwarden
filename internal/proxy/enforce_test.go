package proxy

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pogao/pkgwarden/internal/policy"
)

func TestBlockMessageStaysPrintable(t *testing.T) {
	var v policy.Verdict
	for range 12 {
		v.Findings = append(v.Findings, policy.Finding{Rule: policy.RuleAdvisory, Decision: policy.Block,
			Reason: "GHSA-xxxx-xxxx-xxxx (high vulnerability, via osv): " + strings.Repeat("long summary ", 20)})
	}
	v.Decision = policy.Block
	w := httptest.NewRecorder()
	if Enforce(w, Text, "go/example.com/m@v1.0.0", v) {
		t.Fatal("Enforce allowed a blocking verdict")
	}
	body := w.Body.String()
	if w.Code != 403 || len(body) > maxMessage || !strings.Contains(body, "more, see /api/v1/check") {
		t.Errorf("status %d, %d bytes: %q", w.Code, len(body), body)
	}
}

func TestBlockMessageCountsOnlyBlockingFindings(t *testing.T) {
	const blocking = 12
	var v policy.Verdict
	for i := range blocking {
		v.Findings = append(v.Findings,
			policy.Finding{Rule: policy.RuleAdvisory, Decision: policy.Block,
				Reason: fmt.Sprintf("BLOCK-%02d (high vulnerability, via osv): ", i) + strings.Repeat("long summary ", 20)},
			policy.Finding{Rule: policy.RuleAdvisory, Decision: policy.Warn,
				Reason: fmt.Sprintf("WARN-%02d (low vulnerability, via osv): ", i) + strings.Repeat("long summary ", 20)})
	}
	v.Decision = policy.Block
	w := httptest.NewRecorder()
	Enforce(w, Text, "rubygems/rack@2.2.3", v)
	body := w.Body.String()
	if strings.Contains(body, "WARN-") {
		t.Errorf("message lists a warn finding: %q", body)
	}
	listed := strings.Count(body, "BLOCK-")
	if listed == 0 || listed == blocking {
		t.Fatalf("message lists %d of %d block findings, want a truncated list: %q", listed, blocking, body)
	}
	if want := fmt.Sprintf("and %d more, see /api/v1/check", blocking-listed); !strings.Contains(body, want) {
		t.Errorf("message %q does not end with %q", body, want)
	}
}
