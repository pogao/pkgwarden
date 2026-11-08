package npm_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pogao/pkgwarden/internal/advisory"
	"github.com/pogao/pkgwarden/internal/policy"
	"github.com/pogao/pkgwarden/internal/proxy"
	"github.com/pogao/pkgwarden/internal/proxy/npm"
	"github.com/pogao/pkgwarden/internal/telemetry"
	"github.com/pogao/pkgwarden/internal/telemetry/telemetrytest"
)

// tracedProxy wires telemetry the way cmd/pkgwarden does: the middleware
// around the server and the transport under the upstream client. Closing
// it waits for every request, so their log lines are complete.
func tracedProxy(t *testing.T, src fakeSource) *httptest.Server {
	t.Helper()
	engine := policy.New(policy.Config{Cooldown: week}, src)
	reg := npm.New(npm.Options{
		Registry:  fakeRegistry(t).URL,
		Downloads: fakeDownloads(t).URL,
		Engine:    engine,
		HTTP:      proxy.NewUpstream(&http.Client{Transport: telemetry.Transport(nil)}, "pkgwarden-test", time.Minute),
	})
	srv := httptest.NewServer(telemetry.Middleware(proxy.NewServer(engine, reg)))
	t.Cleanup(srv.Close)
	return srv
}

func linesWithID(lines []map[string]any, id string) []map[string]any {
	var out []map[string]any
	for _, l := range lines {
		if l["request_id"] == id {
			out = append(out, l)
		}
	}
	return out
}

func TestOneRequestIDTracesInboundAndUpstream(t *testing.T) {
	logs := telemetrytest.CaptureLogs(t)
	srv := tracedProxy(t, nil)
	req, _ := http.NewRequest("GET", srv.URL+"/npm/left-pad/-/left-pad-1.0.0.tgz", nil)
	req.Header.Set("X-Request-Id", "trace-npm-1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	srv.Close()

	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Request-Id") != "trace-npm-1" {
		t.Fatalf("status %d, X-Request-Id %q", resp.StatusCode, resp.Header.Get("X-Request-Id"))
	}
	paths := map[string][]string{}
	for _, l := range linesWithID(logs.Lines(t), "trace-npm-1") {
		msg := l["msg"].(string)
		paths[msg] = append(paths[msg], l["path"].(string))
	}
	if got := paths["request"]; len(got) != 1 || got[0] != "/npm/left-pad/-/left-pad-1.0.0.tgz" {
		t.Errorf("request lines for the ID have paths %v, want the tarball once", got)
	}
	wantUpstream := map[string]bool{"/left-pad": true, "/downloads/point/last-week/left-pad": true, "/left-pad/-/left-pad-1.0.0.tgz": true}
	for _, p := range paths["upstream"] {
		delete(wantUpstream, p)
	}
	if len(wantUpstream) != 0 {
		t.Errorf("upstream lines for the ID have paths %v, missing %v:\n%s", paths["upstream"], wantUpstream, logs.Raw())
	}
}

func TestBlockedDownloadIsCountedAndNamesItsRequest(t *testing.T) {
	logs := telemetrytest.CaptureLogs(t)
	srv := tracedProxy(t, fakeSource{"left-pad": {{ID: "MAL-2026-9", Source: "openssf", Kind: advisory.Malicious, Versions: []string{"0.9.0"}}}})
	decision := map[string]string{"ecosystem": "npm", "stage": "artifact", "decision": "block"}
	finding := map[string]string{"ecosystem": "npm", "stage": "artifact", "rule": "advisory/malicious", "decision": "block"}
	beforeDecision := telemetrytest.Value(t, "pkgwarden_decisions_total", decision)
	beforeFinding := telemetrytest.Value(t, "pkgwarden_findings_total", finding)

	resp, body := get(t, srv.URL+"/npm/left-pad/-/left-pad-0.9.0.tgz")
	srv.Close()

	id := resp.Header.Get("X-Request-Id")
	if resp.StatusCode != http.StatusForbidden || id == "" {
		t.Fatalf("status %d, X-Request-Id %q: %s", resp.StatusCode, id, body)
	}
	if msg := strings.TrimSpace(string(body)); !strings.HasSuffix(msg, " (request "+id+")\"}") {
		t.Errorf("403 body %s does not end with the request ID %s", msg, id)
	}
	if d := telemetrytest.Value(t, "pkgwarden_decisions_total", decision) - beforeDecision; d != 1 {
		t.Errorf("decisions_total%v grew by %v, want 1", decision, d)
	}
	if d := telemetrytest.Value(t, "pkgwarden_findings_total", finding) - beforeFinding; d != 1 {
		t.Errorf("findings_total%v grew by %v, want 1", finding, d)
	}
	msgs := map[string]map[string]any{}
	for _, l := range linesWithID(logs.Lines(t), id) {
		msgs[l["msg"].(string)] = l
	}
	if msgs["request"]["decision"] != "block" || msgs["request"]["status"] != 403.0 {
		t.Errorf("request line %v, want status 403 and decision block", msgs["request"])
	}
	blocked := msgs["blocked"]
	if blocked["package"] != "left-pad" || blocked["version"] != "0.9.0" || blocked["stage"] != "artifact" {
		t.Errorf("blocked line %v, want package left-pad version 0.9.0 at the artifact stage", blocked)
	}
	if rules, _ := blocked["rules"].([]any); len(rules) != 1 || rules[0] != "advisory/malicious" {
		t.Errorf("blocked line rules %v, want [advisory/malicious]", blocked["rules"])
	}
}

func TestAllowedDownloadCountsTheBytesServed(t *testing.T) {
	srv := tracedProxy(t, nil)
	labels := map[string]string{"ecosystem": "npm"}
	beforeFiles := telemetrytest.Value(t, "pkgwarden_artifacts_served_total", labels)
	beforeBytes := telemetrytest.Value(t, "pkgwarden_artifact_bytes_total", labels)

	resp, err := http.Get(srv.URL + "/npm/left-pad/-/left-pad-1.0.0.tgz")
	if err != nil {
		t.Fatal(err)
	}
	n, _ := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	srv.Close()

	if want := int64(len(tarballBytes("/left-pad/-/left-pad-1.0.0.tgz"))); resp.StatusCode != http.StatusOK || n != want {
		t.Fatalf("status %d, %d bytes, want 200 and %d bytes", resp.StatusCode, n, want)
	}
	if d := telemetrytest.Value(t, "pkgwarden_artifacts_served_total", labels) - beforeFiles; d != 1 {
		t.Errorf("artifacts_served_total grew by %v, want 1", d)
	}
	if d := telemetrytest.Value(t, "pkgwarden_artifact_bytes_total", labels) - beforeBytes; d != float64(n) {
		t.Errorf("artifact_bytes_total grew by %v, want %d", d, n)
	}
}
