package advisory

import (
	"math"
	"strings"
)

// cvss3Weights holds the base metric weights from the CVSS v3.1
// specification, section 7.4. PR here is the scope-unchanged weight.
var cvss3Weights = map[string]map[string]float64{
	"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
	"AC": {"L": 0.77, "H": 0.44},
	"PR": {"N": 0.85, "L": 0.62, "H": 0.27},
	"UI": {"N": 0.85, "R": 0.62},
	"C":  {"H": 0.56, "L": 0.22, "N": 0},
	"I":  {"H": 0.56, "L": 0.22, "N": 0},
	"A":  {"H": 0.56, "L": 0.22, "N": 0},
}

// Privileges count for more when an exploit reaches beyond the vulnerable
// component.
var cvss3PRScopeChanged = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}

// cvss3Severity rates a CVSS v3.0 or v3.1 vector by its base score. Other
// CVSS versions, malformed vectors, and a score of zero are unknown.
func cvss3Severity(vector string) Severity {
	score, ok := cvss3BaseScore(vector)
	switch {
	case !ok || score == 0:
		return SeverityUnknown
	case score < 4:
		return SeverityLow
	case score < 7:
		return SeverityMedium
	case score < 9:
		return SeverityHigh
	}
	return SeverityCritical
}

// cvss3BaseScore computes the base score of a CVSS v3.0 or v3.1 vector per
// the v3.1 specification. Temporal and environmental metrics are ignored.
// It reports false for a vector that is not v3.x or lacks a valid value for
// any base metric.
func cvss3BaseScore(vector string) (float64, bool) {
	rest, ok := strings.CutPrefix(vector, "CVSS:3.1/")
	if !ok {
		rest, ok = strings.CutPrefix(vector, "CVSS:3.0/")
	}
	if !ok {
		return 0, false
	}
	metrics := make(map[string]string)
	for part := range strings.SplitSeq(rest, "/") {
		name, value, ok := strings.Cut(part, ":")
		if _, dup := metrics[name]; !ok || dup {
			return 0, false
		}
		metrics[name] = value
	}

	var changed bool
	switch metrics["S"] {
	case "U":
	case "C":
		changed = true
	default:
		return 0, false
	}
	w := make(map[string]float64, len(cvss3Weights))
	for name, weights := range cvss3Weights {
		weight, ok := weights[metrics[name]]
		if !ok {
			return 0, false
		}
		w[name] = weight
	}
	if changed {
		w["PR"] = cvss3PRScopeChanged[metrics["PR"]]
	}

	iss := 1 - (1-w["C"])*(1-w["I"])*(1-w["A"])
	impact := 6.42 * iss
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}
	base := impact + 8.22*w["AV"]*w["AC"]*w["PR"]*w["UI"]
	if changed {
		base *= 1.08
	}
	return roundup(min(base, 10)), true
}

// roundup is the CVSS v3.1 Roundup: the smallest one-decimal number not
// below x. Scaling to an integer first keeps floating-point noise such as
// 4.000000000000001 from rounding up to 4.1.
func roundup(x float64) float64 {
	n := int(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n/10000) / 10
	}
	return float64(n/10000+1) / 10
}
