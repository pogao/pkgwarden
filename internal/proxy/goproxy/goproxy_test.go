package goproxy_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/mod/module"

	"github.com/pogao/pkgwarden/internal/advisory"
	"github.com/pogao/pkgwarden/internal/ecosystem"
	"github.com/pogao/pkgwarden/internal/policy"
	"github.com/pogao/pkgwarden/internal/proxy"
	"github.com/pogao/pkgwarden/internal/proxy/goproxy"
	"github.com/pogao/pkgwarden/internal/telemetry/telemetrytest"
)

type fakeSource map[string][]advisory.Advisory

func (f fakeSource) Lookup(_ context.Context, _ ecosystem.Ecosystem, name string) ([]advisory.Advisory, error) {
	return f[name], nil
}

var (
	ancient = time.Now().Add(-40 * 24 * time.Hour).UTC().Truncate(time.Second)
	old     = time.Now().Add(-30 * 24 * time.Hour).UTC().Truncate(time.Second)
	young   = time.Now().Add(-2 * 24 * time.Hour).UTC().Truncate(time.Second)
)

const (
	fooBar             = "example.com/Foo/bar"
	pseudoV            = "v0.0.0-20261001000000-abcdefabcdef"
	pseudoV2           = "v0.0.0-20261105000000-123456123456"
	unpublishedPseudoV = "v0.0.0-20261106000000-000000000000"
)

type fakeModule struct {
	listed     []string
	times      map[string]time.Time
	infoStatus map[string]int
	latest     string
}

func manyVersions(n int) fakeModule {
	m := fakeModule{times: map[string]time.Time{}}
	for i := range n {
		v := fmt.Sprintf("v1.0.%d", i)
		m.listed = append(m.listed, v)
		m.times[v] = old
	}
	return m
}

// modules is keyed by escaped module path, the only form a real proxy serves.
var modules = map[string]fakeModule{
	"example.com/!foo/bar": {
		listed: []string{"v0.9.0", "v1.0.0-RC.1", "v1.0.0", "v1.1.0", "v1.2.0-rc.1"},
		times: map[string]time.Time{
			"v0.9.0": ancient, "v1.0.0-RC.1": old, "v1.0.0": old, "v1.1.0": young, "v1.2.0-rc.1": young, pseudoV: old,
			pseudoV2: young, "v2.0.0+incompatible": old,
		},
		latest: "v1.2.0-rc.1",
	},
	"example.com/pseudo/old":   {times: map[string]time.Time{pseudoV: old}, latest: pseudoV},
	"example.com/pseudo/young": {times: map[string]time.Time{pseudoV2: young}, latest: pseudoV2},
	"example.com/prerelease": {
		listed: []string{"v0.1.0-alpha.1"},
		times:  map[string]time.Time{"v0.1.0-alpha.1": old},
		latest: "v0.1.0-alpha.1",
	},
	"example.com/gap": {
		listed:     []string{"v1.0.0", "v1.1.0", "v1.2.0"},
		times:      map[string]time.Time{"v1.0.0": old, "v1.1.0": old, "v1.2.0": old},
		infoStatus: map[string]int{"v1.1.0": http.StatusNotFound, "v1.2.0": http.StatusGone},
	},
	"example.com/broken": {
		listed:     []string{"v1.0.0", "v1.1.0"},
		times:      map[string]time.Time{"v1.0.0": old, "v1.1.0": old},
		infoStatus: map[string]int{"v1.1.0": http.StatusInternalServerError},
	},
	"example.com/many": manyVersions(600),
}

func infoJSON(v string, t time.Time) string {
	return fmt.Sprintf(`{"Version":%q,"Time":%q,"Origin":{"VCS":"git","URL":"https://example.com/repo","Ref":"refs/tags/%s","Hash":"b324da5ffbb2a87e4a611b1703bd03bffbe7ffbf"}}`,
		v, t.Format(time.RFC3339), v)
}

func zipBytes(path string) []byte { return []byte("PK\x03\x04 module zip " + path) }

func fakeProxy(t *testing.T, requests, infoHits *atomic.Int64) *httptest.Server {
	t.Helper()
	versionEscapes := strings.NewReplacer("!r!c", "RC")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		p := strings.TrimPrefix(r.URL.Path, "/")
		notFound := func() {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "not found: %s", p)
		}
		if esc, ok := strings.CutSuffix(p, "/@latest"); ok {
			m, ok := modules[esc]
			if !ok {
				notFound()
				return
			}
			w.Write([]byte(infoJSON(m.latest, m.times[m.latest])))
			return
		}
		esc, file, _ := strings.Cut(p, "/@v/")
		m, ok := modules[esc]
		if !ok {
			notFound()
			return
		}
		if file == "list" {
			for _, v := range m.listed {
				fmt.Fprintln(w, v)
			}
			return
		}
		dot := strings.LastIndex(file, ".")
		if dot < 0 {
			notFound()
			return
		}
		v := versionEscapes.Replace(file[:dot])
		// Like proxy.golang.org, resolve a query such as v1.0 for .info only.
		if c := module.CanonicalVersion(v); c != "" && file[dot:] == ".info" {
			v = c
		}
		if v == "master" && file[dot:] == ".info" {
			v = m.latest
		}
		tm, ok := m.times[v]
		if !ok {
			notFound()
			return
		}
		if file[dot:] == ".info" {
			infoHits.Add(1)
			if status, ok := m.infoStatus[v]; ok {
				w.WriteHeader(status)
				return
			}
		}
		switch file[dot:] {
		case ".info":
			w.Write([]byte(infoJSON(v, tm)))
		case ".mod":
			fmt.Fprintf(w, "module %s\n", esc)
		case ".zip":
			w.Header().Set("Content-Type", "application/zip")
			w.Write(zipBytes(p))
		default:
			notFound()
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

type env struct {
	proxy    *httptest.Server
	reg      *goproxy.Registry
	requests *atomic.Int64
	infoHits *atomic.Int64
}

func newEnv(t *testing.T, src fakeSource) env {
	t.Helper()
	engine := policy.New(policy.Config{Cooldown: 7 * 24 * time.Hour}, src)
	requests, infoHits := new(atomic.Int64), new(atomic.Int64)
	reg := goproxy.New(goproxy.Options{
		Upstream: fakeProxy(t, requests, infoHits).URL,
		Engine:   engine,
		HTTP:     proxy.NewUpstream(http.DefaultClient, "pkgwarden-test", time.Minute),
	})
	srv := httptest.NewServer(proxy.NewServer(engine, reg))
	t.Cleanup(srv.Close)
	return env{proxy: srv, reg: reg, requests: requests, infoHits: infoHits}
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

func assertBlocked(t *testing.T, status int, body string, want ...string) {
	t.Helper()
	if status != http.StatusForbidden {
		t.Fatalf("status %d, want 403 (404 and 410 would let GOPROXY fall through to direct): %s", status, body)
	}
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("body %q does not mention %q", body, w)
		}
	}
}

func TestListHidesBlockedVersions(t *testing.T) {
	e := newEnv(t, nil)
	tests := []struct{ module, want string }{
		{"example.com/!foo/bar", "v0.9.0\nv1.0.0-RC.1\nv1.0.0\n"},
		{"example.com/pseudo/old", ""},
	}
	for _, tt := range tests {
		status, body := get(t, e.proxy.URL+"/go/"+tt.module+"/@v/list")
		if status != http.StatusOK || body != tt.want {
			t.Errorf("%s: status %d list %q, want %q", tt.module, status, body, tt.want)
		}
	}
}

func TestLatest(t *testing.T) {
	e := newEnv(t, nil)
	tests := []struct {
		module, want string
		published    time.Time
	}{
		{"example.com/!foo/bar", "v1.0.0", old},
		{"example.com/pseudo/old", pseudoV, old},
		{"example.com/prerelease", "v0.1.0-alpha.1", old},
	}
	for _, tt := range tests {
		status, body := get(t, e.proxy.URL+"/go/"+tt.module+"/@latest")
		if want := infoJSON(tt.want, tt.published); status != http.StatusOK || body != want {
			t.Errorf("%s: status %d body %s, want upstream .info %s", tt.module, status, body, want)
		}
	}

	status, body := get(t, e.proxy.URL+"/go/example.com/pseudo/young/@latest")
	assertBlocked(t, status, body, "go/example.com/pseudo/young@"+pseudoV2, "cooldown")
}

func TestZip(t *testing.T) {
	e := newEnv(t, nil)
	allowed := []string{
		"example.com/!foo/bar/@v/v1.0.0.zip",
		"example.com/!foo/bar/@v/v1.0.0-!r!c.1.zip",
		"example.com/!foo/bar/@v/" + pseudoV + ".zip",
		"example.com/!foo/bar/@v/v2.0.0+incompatible.zip",
		"example.com/pseudo/old/@v/" + pseudoV + ".zip",
	}
	for _, p := range allowed {
		before := telemetrytest.Value(t, "pkgwarden_artifacts_served_total", map[string]string{"ecosystem": "go"})
		status, body := get(t, e.proxy.URL+"/go/"+p)
		if want := string(zipBytes(p)); status != http.StatusOK || body != want {
			t.Errorf("%s: status %d body %q, want upstream bytes %q", p, status, body, want)
		}
		if d := telemetrytest.Value(t, "pkgwarden_artifacts_served_total", map[string]string{"ecosystem": "go"}) - before; d != 1 {
			t.Errorf("%s: artifacts_served_total grew by %v, want 1", p, d)
		}
	}

	status, body := get(t, e.proxy.URL+"/go/example.com/!foo/bar/@v/v1.1.0.zip")
	assertBlocked(t, status, body, "go/example.com/Foo/bar@v1.1.0", "cooldown")

	for _, p := range []string{
		"example.com/!foo/bar/@v/master.zip",
		"example.com/Foo/bar/@v/v1.0.0.zip",
		"example.com/!foo/bar/@v/v1.0.0-RC.1.zip",
		"example.com/!foo/bar/@v/v1.0.zip",
		"example.com/!foo/bar/@v/v1.zip",
	} {
		before := e.requests.Load()
		if status, body := get(t, e.proxy.URL+"/go/"+p); status != http.StatusBadRequest {
			t.Errorf("%s: status %d body %q, want 400", p, status, body)
		}
		if n := e.requests.Load() - before; n != 0 {
			t.Errorf("%s: sent %d upstream requests, want 0", p, n)
		}
	}

	if status, body := get(t, e.proxy.URL+"/go/example.com/!foo/bar/@v/v1.0.info"); status != http.StatusOK || body != infoJSON("v1.0.0", old) {
		t.Errorf("v1.0.info: status %d body %q, want the upstream .info of v1.0.0", status, body)
	}
}

func TestMissingInfoIsAnUnknownPublishTime(t *testing.T) {
	e := newEnv(t, nil)
	if status, body := get(t, e.proxy.URL+"/go/example.com/gap/@v/list"); status != http.StatusOK || body != "v1.0.0\n" {
		t.Errorf("list: status %d body %q, want 200 with only v1.0.0", status, body)
	}
	for _, v := range []string{"v1.1.0", "v1.2.0"} {
		status, body := get(t, e.proxy.URL+"/go/example.com/gap/@v/"+v+".zip")
		assertBlocked(t, status, body, "go/example.com/gap@"+v, "cooldown", "publish time unknown")
	}
	if status, body := get(t, e.proxy.URL+"/go/example.com/gap/@v/v1.0.0.zip"); status != http.StatusOK {
		t.Errorf("v1.0.0.zip: status %d body %q, want 200", status, body)
	}
}

func TestUnlistedVersionWithoutInfoIsUnknown(t *testing.T) {
	e := newEnv(t, nil)
	for _, v := range []string{"v1.3.0", unpublishedPseudoV} {
		status, body := get(t, e.proxy.URL+"/go/example.com/gap/@v/"+v+".zip")
		assertBlocked(t, status, body, "go/example.com/gap@"+v, "unknown-release", "not published upstream")
	}
}

func checkAPI(t *testing.T, e env, name, version string) (decision string, rules []string) {
	t.Helper()
	q := url.Values{"ecosystem": {"go"}, "name": {name}, "version": {version}}
	status, body := get(t, e.proxy.URL+"/api/v1/check?"+q.Encode())
	if status != http.StatusOK {
		t.Fatalf("check %s@%s: status %d body %q", name, version, status, body)
	}
	var res struct {
		Decision string
		Findings []struct{ Rule string }
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		rules = append(rules, f.Rule)
	}
	return res.Decision, rules
}

func TestCheckAgreesWithZip(t *testing.T) {
	e := newEnv(t, nil)
	tests := []struct {
		module, version, decision string
		rules                     []string
	}{
		{fooBar, pseudoV, "allow", nil},
		{fooBar, pseudoV2, "block", []string{"cooldown"}},
		{fooBar, unpublishedPseudoV, "block", []string{"unknown-release"}},
		{fooBar, "v1.9.9", "block", []string{"unknown-release"}},
		{"example.com/gap", "v1.1.0", "block", []string{"cooldown"}},
	}
	for _, tt := range tests {
		esc, err := module.EscapePath(tt.module)
		if err != nil {
			t.Fatal(err)
		}
		status, body := get(t, e.proxy.URL+"/go/"+esc+"/@v/"+tt.version+".zip")
		if tt.decision == "allow" && status != http.StatusOK {
			t.Errorf("%s@%s zip: status %d body %q, want 200", tt.module, tt.version, status, body)
		}
		if tt.decision == "block" {
			assertBlocked(t, status, body, tt.rules...)
		}
		if d, rules := checkAPI(t, e, tt.module, tt.version); d != tt.decision || !slices.Equal(rules, tt.rules) {
			t.Errorf("%s@%s check: %s %v, want %s %v", tt.module, tt.version, d, rules, tt.decision, tt.rules)
		}
	}

	// The zip of a non-canonical version is a 400, and upstream would
	// resolve its .info as a query.
	for _, v := range []string{"v1.0", "master"} {
		if d, rules := checkAPI(t, e, fooBar, v); d != "block" || !slices.Equal(rules, []string{"unknown-release"}) {
			t.Errorf("%s check: %s %v, want block [unknown-release]", v, d, rules)
		}
	}
}

func TestInfoServerErrorFailsTheModule(t *testing.T) {
	e := newEnv(t, nil)
	for _, p := range []string{"@v/list", "@v/v1.0.0.zip"} {
		if status, body := get(t, e.proxy.URL+"/go/example.com/broken/"+p); status != http.StatusBadGateway {
			t.Errorf("%s: status %d body %q, want 502", p, status, body)
		}
	}
}

func TestPublishTimesAreFetchedOnce(t *testing.T) {
	e := newEnv(t, nil)
	tests := []struct {
		module string
		lines  int
	}{
		{"example.com/!foo/bar", 3},
		{"example.com/many", 600},
	}
	for _, tt := range tests {
		for i := range 2 {
			before := e.infoHits.Load()
			status, body := get(t, e.proxy.URL+"/go/"+tt.module+"/@v/list")
			if n := strings.Count(body, "\n"); status != http.StatusOK || n != tt.lines {
				t.Fatalf("%s request %d: status %d with %d versions, want 200 with %d", tt.module, i+1, status, n, tt.lines)
			}
			hits := e.infoHits.Load() - before
			if i == 0 && hits == 0 {
				t.Errorf("%s: first list fetched no .info files", tt.module)
			}
			if i == 1 && hits != 0 {
				t.Errorf("%s: second list fetched %d .info files, want 0", tt.module, hits)
			}
		}
	}
}

func TestInfoAndModStayAvailableForBlockedVersions(t *testing.T) {
	e := newEnv(t, nil)
	tests := []struct{ path, want string }{
		{"example.com/!foo/bar/@v/v1.1.0.info", infoJSON("v1.1.0", young)},
		{"example.com/!foo/bar/@v/v1.1.0.mod", "module example.com/!foo/bar\n"},
		{"example.com/!foo/bar/@v/v1.0.0-!r!c.1.info", infoJSON("v1.0.0-RC.1", old)},
		{"example.com/!foo/bar/@v/" + pseudoV2 + ".info", infoJSON(pseudoV2, young)},
		{"example.com/!foo/bar/@v/" + pseudoV2 + ".mod", "module example.com/!foo/bar\n"},
		{"example.com/!foo/bar/@v/master.info", infoJSON("v1.2.0-rc.1", young)},
	}
	for _, tt := range tests {
		if status, body := get(t, e.proxy.URL+"/go/"+tt.path); status != http.StatusOK || body != tt.want {
			t.Errorf("%s: status %d body %q, want %q", tt.path, status, body, tt.want)
		}
	}
}

func TestCraftedPathsNeverReachUpstream(t *testing.T) {
	e := newEnv(t, nil)
	const blocked = "example.com/!foo/bar/@v/v1.1.0"
	for _, p := range []string{
		blocked + ".zip%23.info",
		blocked + ".zip%23.mod",
		blocked + ".zip%3F.info",
		blocked + ".zip%3F.mod",
		blocked + ".zip%2523.info",
		blocked + ".zip%253F.mod",
		blocked + "%25.info",
		"example.com/!foo/bar/@v/list%23.info",
		"example.com/!foo/bar/@v/%2e%2e%2f%2e%2e%2f@latest%23.info",
		"example.com/!foo/bar/@v/..%2f..%2f@latest%23.mod",
		"sumdb/sum.golang.org/supported",
		"sumdb/%2e%2e/" + blocked + ".zip",
		"sumdb/..%2f" + blocked + ".zip",
		"sumdb/%2e%2e/" + blocked + ".info",
		"sumdb/%252e%252e/" + blocked + ".zip",
		"sumdb/%2e%2e/example.com/!foo/bar/@v/list",
		"sumdb/%2e%2e/example.com/!foo/bar/@latest",
	} {
		before := e.requests.Load()
		status, body := get(t, e.proxy.URL+"/go/"+p)
		if status != http.StatusBadRequest && status != http.StatusNotFound {
			t.Errorf("%s: status %d body %q, want 400 or 404", p, status, body)
		}
		if n := e.requests.Load() - before; n != 0 {
			t.Errorf("%s: sent %d upstream requests, want 0", p, n)
		}
	}
}

func TestPackageWideAdvisoryBlocks(t *testing.T) {
	e := newEnv(t, fakeSource{fooBar: {{
		ID: "GO-2026-0001", Source: "osv", Kind: advisory.Malicious, Summary: "Malicious code in example.com/Foo/bar",
	}}})
	for _, p := range []string{"@v/list", "@latest", "@v/v1.0.0.zip"} {
		status, body := get(t, e.proxy.URL+"/go/example.com/!foo/bar/"+p)
		assertBlocked(t, status, body, "GO-2026-0001")
	}
	if status, _ := get(t, e.proxy.URL+"/go/example.com/prerelease/@v/list"); status != http.StatusOK {
		t.Errorf("unrelated module status %d", status)
	}
}

func TestPackage(t *testing.T) {
	e := newEnv(t, nil)
	pkg, err := e.reg.Package(context.Background(), fooBar)
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Ecosystem != ecosystem.Go || pkg.Name != fooBar || pkg.WeeklyDownloads != policy.UnknownDownloads || !pkg.Created.Equal(ancient) {
		t.Errorf("package = %s %q downloads %d created %v", pkg.Ecosystem, pkg.Name, pkg.WeeklyDownloads, pkg.Created)
	}
	want := map[string]time.Time{"v0.9.0": ancient, "v1.0.0-RC.1": old, "v1.0.0": old, "v1.1.0": young, "v1.2.0-rc.1": young}
	if len(pkg.Releases) != len(want) {
		t.Errorf("got %d releases, want %d", len(pkg.Releases), len(want))
	}
	for _, r := range pkg.Releases {
		if !r.Published.Equal(want[r.Version]) || r.Publishers != nil {
			t.Errorf("release %+v, want published %v", r, want[r.Version])
		}
	}

	pseudo, err := e.reg.Package(context.Background(), "example.com/pseudo/old")
	if err != nil {
		t.Fatal(err)
	}
	if len(pseudo.Releases) != 1 || pseudo.Releases[0].Version != pseudoV || !pseudo.Releases[0].Published.Equal(old) {
		t.Errorf("pseudo-version-only module releases = %+v", pseudo.Releases)
	}

	for _, name := range []string{"example.com/missing", "not a module path"} {
		if _, err := e.reg.Package(context.Background(), name); !errors.Is(err, proxy.ErrNotFound) {
			t.Errorf("Package(%q) error = %v, want ErrNotFound", name, err)
		}
	}
}

func TestMethods(t *testing.T) {
	e := newEnv(t, nil)
	resp, err := http.Post(e.proxy.URL+"/go/example.com/!foo/bar/@v/list", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST status %d, want 405", resp.StatusCode)
	}
}
