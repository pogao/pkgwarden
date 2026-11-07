package npm_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
