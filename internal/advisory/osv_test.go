package advisory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pogao/pkgwarden/internal/ecosystem"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// osvServer answers /v1/query with respond(query) and records each query.
func osvServer(t *testing.T, respond func(q osvQuery) string) (*OSV, *[]osvQuery) {
	t.Helper()
	var queries []osvQuery
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/query" {
			http.Error(w, "unexpected request", http.StatusNotFound)
			return
		}
		if ua := r.Header.Get("User-Agent"); ua != "pkgwarden" {
			t.Errorf("User-Agent = %q, want pkgwarden", ua)
		}
		var q osvQuery
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		queries = append(queries, q)
		w.Write([]byte(respond(q)))
	}))
	t.Cleanup(srv.Close)
	return NewOSV(srv.Client(), srv.URL), &queries
}

func byID(t *testing.T, advs []Advisory, id string) Advisory {
	t.Helper()
	i := slices.IndexFunc(advs, func(a Advisory) bool { return a.ID == id })
	if i < 0 {
		t.Fatalf("advisory %s missing from %d results", id, len(advs))
	}
	return advs[i]
}

func checkAffects(t *testing.T, a Advisory, affected, safe []string) {
	t.Helper()
	for _, v := range affected {
		if !a.Affects(v) {
			t.Errorf("%s: Affects(%q) = false, want true", a.ID, v)
		}
	}
	for _, v := range safe {
		if a.Affects(v) {
			t.Errorf("%s: Affects(%q) = true, want false", a.ID, v)
		}
	}
}

func TestOSVLookupNpm(t *testing.T) {
	src, queries := osvServer(t, func(osvQuery) string { return string(fixture(t, "osv_event-stream.json")) })
	advs, err := src.Lookup(context.Background(), ecosystem.Npm, "event-stream")
	if err != nil {
		t.Fatal(err)
	}
	if want := (osvPackage{Name: "event-stream", Ecosystem: "npm"}); (*queries)[0].Package != want {
		t.Errorf("query package = %+v, want %+v", (*queries)[0].Package, want)
	}
	if len(advs) != 1 {
		t.Fatalf("got %d advisories, want 1", len(advs))
	}
	a := advs[0]
	if a.ID != "GHSA-mh6f-8j2x-4483" || a.Source != "osv" || a.Severity != "CRITICAL" ||
		a.URL != "https://osv.dev/vulnerability/GHSA-mh6f-8j2x-4483" || a.Ecosystem != ecosystem.Npm ||
		a.Summary != "Critical severity vulnerability that affects event-stream and flatmap-stream" {
		t.Errorf("unexpected advisory %+v", a)
	}
	// The flatmap-stream entry in the same record covers every release; it
	// must not leak into event-stream's ranges.
	checkAffects(t, a, []string{"3.3.6", "3.3.9"}, []string{"3.3.4", "3.3.5", "4.0.0"})
}

func TestOSVLookupPyPI(t *testing.T) {
	src, queries := osvServer(t, func(osvQuery) string { return string(fixture(t, "osv_jinja2.json")) })
	advs, err := src.Lookup(context.Background(), ecosystem.PyPI, "Jinja2")
	if err != nil {
		t.Fatal(err)
	}
	if got := (*queries)[0].Package.Ecosystem; got != "PyPI" {
		t.Errorf("query ecosystem = %q, want PyPI", got)
	}
	if len(advs) != 4 {
		t.Fatalf("got %d advisories, want 4", len(advs))
	}

	moderate := byID(t, advs, "GHSA-gmj6-6f8f-6699")
	if moderate.Severity != "MEDIUM" || !slices.Contains(moderate.Aliases, "CVE-2024-56201") {
		t.Errorf("unexpected advisory %+v", moderate)
	}
	checkAffects(t, moderate, []string{"3.0.0", "3.1.4"}, []string{"2.11.3", "3.1.5"})

	// PYSEC-2014-82 pairs a GIT range ending at a commit hash with an
	// ECOSYSTEM range; only the latter describes releases.
	pysec := byID(t, advs, "PYSEC-2014-82")
	if pysec.Severity != "" {
		t.Errorf("PYSEC severity = %q, want empty", pysec.Severity)
	}
	checkAffects(t, pysec, []string{"2.7.2", "2.0"}, []string{"2.7.3", "2.8", "3.0.0"})
}

func TestOSVLastAffected(t *testing.T) {
	src, _ := osvServer(t, func(osvQuery) string { return string(fixture(t, "osv_crossenv.json")) })
	advs, err := src.Lookup(context.Background(), ecosystem.Npm, "crossenv")
	if err != nil {
		t.Fatal(err)
	}
	a := byID(t, advs, "GHSA-c2m4-w5hm-vqjw")
	if a.Kind != Vulnerability || a.Severity != "HIGH" {
		t.Errorf("unexpected advisory %+v", a)
	}
	checkAffects(t, a, []string{"0.0.1", "1.0.1"}, []string{"1.0.2"})
}

func TestOSVRecordMapping(t *testing.T) {
	body := `{"vulns":[
	{"id":"MAL-2024-9","details":"\n\n  Package exfiltrates credentials.\nMore text.","affected":[{"package":{"name":"evil","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]},
	{"id":"GHSA-aaaa-bbbb-cccc","aliases":["MAL-2024-10"],"summary":"aliased malware","affected":[{"package":{"name":"evil","ecosystem":"npm"}}]},
	{"id":"GHSA-dddd-eeee-ffff","withdrawn":"2024-01-01T00:00:00Z","summary":"withdrawn","affected":[{"package":{"name":"evil","ecosystem":"npm"}}]},
	{"id":"GHSA-gggg-hhhh-iiii","summary":"other package only","affected":[{"package":{"name":"other","ecosystem":"npm"}}]},
	{"id":"GHSA-mmmm-nnnn-oooo","summary":"same name in another ecosystem","affected":[{"package":{"name":"evil","ecosystem":"PyPI"}}]},
	{"id":"GHSA-jjjj-kkkk-llll","details":"` + strings.Repeat("x", 300) + `","database_specific":{"severity":7},"affected":[{"package":{"name":"evil","ecosystem":"npm"},"versions":["1.0.0"]}]}
	]}`
	src, _ := osvServer(t, func(osvQuery) string { return body })
	advs, err := src.Lookup(context.Background(), ecosystem.Npm, "evil")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, a := range advs {
		ids = append(ids, a.ID)
	}
	if want := []string{"MAL-2024-9", "GHSA-aaaa-bbbb-cccc", "GHSA-jjjj-kkkk-llll"}; !slices.Equal(ids, want) {
		t.Fatalf("advisory IDs = %v, want %v", ids, want)
	}

	mal := advs[0]
	if mal.Kind != Malicious || mal.Summary != "Package exfiltrates credentials." {
		t.Errorf("unexpected advisory %+v", mal)
	}
	checkAffects(t, mal, []string{"0.0.1", "5.0.0"}, nil)

	if advs[1].Kind != Malicious {
		t.Errorf("%s: kind = %v, want malicious via its MAL- alias", advs[1].ID, advs[1].Kind)
	}
	checkAffects(t, advs[1], []string{"1.2.3"}, nil)

	long := advs[2]
	if want := strings.Repeat("x", 200) + "..."; long.Summary != want || long.Severity != "" || long.Kind != Vulnerability {
		t.Errorf("unexpected advisory %+v", long)
	}
}

func TestOSVPagination(t *testing.T) {
	src, queries := osvServer(t, func(q osvQuery) string {
		if q.PageToken == "" {
			return `{"vulns":[{"id":"OSV-1","affected":[{"package":{"name":"p","ecosystem":"crates.io"}}]}],"next_page_token":"page-2"}`
		}
		return `{"vulns":[{"id":"OSV-2","affected":[{"package":{"name":"p","ecosystem":"crates.io"}}]}]}`
	})
	advs, err := src.Lookup(context.Background(), ecosystem.Cargo, "p")
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 2 || advs[0].ID != "OSV-1" || advs[1].ID != "OSV-2" {
		t.Errorf("got %+v, want OSV-1 and OSV-2", advs)
	}
	if len(*queries) != 2 || (*queries)[1].PageToken != "page-2" {
		t.Errorf("queries = %+v, want a second query carrying page-2", *queries)
	}
}

func TestOSVUnknownPackage(t *testing.T) {
	src, _ := osvServer(t, func(osvQuery) string { return `{}` })
	advs, err := src.Lookup(context.Background(), ecosystem.Npm, "nothing-here")
	if err != nil || advs != nil {
		t.Errorf("Lookup = %v, %v; want nil, nil", advs, err)
	}
}

func TestOSVHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "overloaded", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	_, err := NewOSV(srv.Client(), srv.URL).Lookup(context.Background(), ecosystem.Npm, "x")
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Errorf("err = %v, want a 503 error", err)
	}
}
