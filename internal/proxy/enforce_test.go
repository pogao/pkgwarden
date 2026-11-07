package proxy

import (
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
