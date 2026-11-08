package telemetry_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/pogao/pkgwarden/internal/telemetry"
	"github.com/pogao/pkgwarden/internal/telemetry/telemetrytest"
)

var generatedID = regexp.MustCompile(`^[0-9a-f]{32}$`)

func TestMiddlewareRequestID(t *testing.T) {
	tests := []struct {
		name    string
		inbound string
		keep    bool
	}{
		{"generated when absent", "", false},
		{"inbound kept", "lb-7f3a.trace_ID-01", true},
		{"64 characters kept", strings.Repeat("a", 64), true},
		{"65 characters replaced", strings.Repeat("a", 65), false},
		{"space replaced", "abc def", false},
		{"markup replaced", "<script>", false},
		{"colon replaced", "trace:1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := telemetrytest.CaptureLogs(t)
			var seen string
			h := telemetry.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = telemetry.RequestID(r.Context())
			}))
			req := httptest.NewRequest("GET", "/npm/left-pad", nil)
			if tt.inbound != "" {
				req.Header.Set("X-Request-Id", tt.inbound)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			echoed := rec.Header().Get("X-Request-Id")
			if echoed == "" || echoed != seen {
				t.Fatalf("response header %q, handler context %q, want the same non-empty ID", echoed, seen)
			}
			if tt.keep && echoed != tt.inbound {
				t.Errorf("ID %q, want inbound %q kept", echoed, tt.inbound)
			}
			if !tt.keep && !generatedID.MatchString(echoed) {
				t.Errorf("ID %q, want a generated 32-hex-digit ID", echoed)
			}
			lines := logs.Messages(t, "request")
			if len(lines) != 1 || lines[0]["request_id"] != echoed {
				t.Errorf("request log lines %v, want one with request_id %q", lines, echoed)
			}
		})
	}
}

func TestMiddlewareLogsAndCountsRequests(t *testing.T) {
	logs := telemetrytest.CaptureLogs(t)
	h := telemetry.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Pkgwarden-Decision", "block")
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, "blocked\n")
	}))
	labels := map[string]string{"ecosystem": "npm", "method": "GET", "code": "403"}
	before := telemetrytest.Value(t, "pkgwarden_http_requests_total", labels)

	req := httptest.NewRequest("GET", "/npm/left-pad/-/left-pad-1.3.0.tgz?secret=1", nil)
	req.Header.Set("User-Agent", "npm/10.9.0")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if d := telemetrytest.Value(t, "pkgwarden_http_requests_total", labels) - before; d != 1 {
		t.Errorf("pkgwarden_http_requests_total%v grew by %v, want 1", labels, d)
	}
	lines := logs.Messages(t, "request")
	if len(lines) != 1 {
		t.Fatalf("got %d request lines, want 1: %s", len(lines), logs.Raw())
	}
	want := map[string]any{
		"level": "INFO", "method": "GET", "path": "/npm/left-pad/-/left-pad-1.3.0.tgz", "status": 403.0,
		"bytes": 8.0, "ecosystem": "npm", "decision": "block", "user_agent": "npm/10.9.0", "remote_addr": "192.0.2.1:1234",
	}
	for k, v := range want {
		if lines[0][k] != v {
			t.Errorf("request line %s = %v, want %v", k, lines[0][k], v)
		}
	}
	if _, ok := lines[0]["duration_ms"].(float64); !ok {
		t.Errorf("request line has no numeric duration_ms: %v", lines[0])
	}
}

func TestMiddlewareLabels(t *testing.T) {
	tests := []struct {
		method, path      string
		ecosystem, mlabel string
		level             string
	}{
		{"GET", "/pypi/simple/requests/", "pypi", "GET", "INFO"},
		{"GET", "/rubygems/info/rack", "rubygems", "GET", "INFO"},
		{"GET", "/go/golang.org/x/text/@v/list", "go", "GET", "INFO"},
		{"GET", "/cargo/index/config.json", "cargo", "GET", "INFO"},
		{"GET", "/api/v1/check", "api", "GET", "INFO"},
		{"GET", "/npmx/left-pad", "other", "GET", "INFO"},
		{"PROPFIND", "/npm/left-pad", "npm", "other", "INFO"},
		{"GET", "/healthz", "other", "GET", "DEBUG"},
		{"GET", "/metrics", "other", "GET", "DEBUG"},
	}
	h := telemetry.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			logs := telemetrytest.CaptureLogs(t)
			labels := map[string]string{"ecosystem": tt.ecosystem, "method": tt.mlabel, "code": "200"}
			before := telemetrytest.Value(t, "pkgwarden_http_requests_total", labels)
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(tt.method, tt.path, nil))
			if d := telemetrytest.Value(t, "pkgwarden_http_requests_total", labels) - before; d != 1 {
				t.Errorf("pkgwarden_http_requests_total%v grew by %v, want 1", labels, d)
			}
			lines := logs.Messages(t, "request")
			if len(lines) != 1 || lines[0]["level"] != tt.level {
				t.Errorf("request lines %v, want one at %s", lines, tt.level)
			}
		})
	}
}

func TestTransportLogsUpstreamWithInboundID(t *testing.T) {
	const token = "ghp_secretvalue"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Request-Id") != "" {
			t.Errorf("upstream received X-Request-Id %q", r.Header.Get("X-Request-Id"))
		}
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	client := &http.Client{Transport: telemetry.Transport(nil)}
	host := strings.TrimPrefix(upstream.URL, "http://")

	logs := telemetrytest.CaptureLogs(t)
	labels := map[string]string{"host": host, "code": "200"}
	before := telemetrytest.Value(t, "pkgwarden_upstream_requests_total", labels)
	h := telemetry.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, _ := http.NewRequestWithContext(r.Context(), "GET", upstream.URL+"/graphql?page=2", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v1/check", nil))

	if d := telemetrytest.Value(t, "pkgwarden_upstream_requests_total", labels) - before; d != 1 {
		t.Errorf("pkgwarden_upstream_requests_total%v grew by %v, want 1", labels, d)
	}
	if strings.Contains(logs.Raw(), token) {
		t.Errorf("log contains the Authorization token: %s", logs.Raw())
	}
	inbound, up := logs.Messages(t, "request"), logs.Messages(t, "upstream")
	if len(inbound) != 1 || len(up) != 1 {
		t.Fatalf("got %d request and %d upstream lines, want 1 each: %s", len(inbound), len(up), logs.Raw())
	}
	if up[0]["request_id"] == nil || up[0]["request_id"] != inbound[0]["request_id"] {
		t.Errorf("upstream request_id %v, inbound %v, want the same", up[0]["request_id"], inbound[0]["request_id"])
	}
	want := map[string]any{"level": "INFO", "method": "GET", "host": host, "path": "/graphql", "status": 200.0, "content_length": 2.0}
	for k, v := range want {
		if up[0][k] != v {
			t.Errorf("upstream line %s = %v, want %v", k, up[0][k], v)
		}
	}
}

func TestTransportCountsFailures(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	host := strings.TrimPrefix(dead.URL, "http://")
	logs := telemetrytest.CaptureLogs(t)
	labels := map[string]string{"host": host, "code": "error"}
	before := telemetrytest.Value(t, "pkgwarden_upstream_requests_total", labels)

	client := &http.Client{Transport: telemetry.Transport(nil)}
	if _, err := client.Get(dead.URL + "/index"); err == nil {
		t.Fatal("request to a closed server succeeded")
	}

	if d := telemetrytest.Value(t, "pkgwarden_upstream_requests_total", labels) - before; d != 1 {
		t.Errorf("pkgwarden_upstream_requests_total%v grew by %v, want 1", labels, d)
	}
	up := logs.Messages(t, "upstream")
	if len(up) != 1 || up[0]["err"] == nil || up[0]["status"] != nil {
		t.Errorf("upstream lines %v, want one with err and no status", up)
	}
}

func TestSetAdvisorySources(t *testing.T) {
	telemetry.SetAdvisorySources(map[string]bool{"osv": true, "ghsa": false, "openssf": true})

	for source, want := range map[string]float64{"osv": 1, "ghsa": 0, "openssf": 1} {
		labels := map[string]string{"source": source}
		if got := telemetrytest.Value(t, "pkgwarden_advisory_source_enabled", labels); got != want {
			t.Errorf("pkgwarden_advisory_source_enabled%v = %v, want %v", labels, got, want)
		}
	}
}
