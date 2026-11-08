package cargo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pogao/pkgwarden/internal/advisory"
	"github.com/pogao/pkgwarden/internal/ecosystem"
	"github.com/pogao/pkgwarden/internal/policy"
	"github.com/pogao/pkgwarden/internal/proxy"
	"github.com/pogao/pkgwarden/internal/proxy/proxytest"
	"github.com/pogao/pkgwarden/internal/telemetry/telemetrytest"
)

const day = 24 * time.Hour

var (
	older = time.Now().Add(-60 * day).UTC()
	old   = time.Now().Add(-30 * day).UTC()
	young = time.Now().Add(-2 * day).UTC()

	crateBytes = []byte("\x1f\x8b\x08\x00demo_crate-0.2.0 tarball\x00\xff")
)

type advisories map[string][]advisory.Advisory

func (s advisories) Lookup(_ context.Context, _ ecosystem.Ecosystem, name string) ([]advisory.Advisory, error) {
	return s[name], nil
}

type fakeCratesIO struct {
	url   string
	index []byte

	mu        sync.Mutex
	indexHits []string
}

func (f *fakeCratesIO) hits() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.indexHits)
}

// setup starts a fake crates.io (index under /idx, API under /api, crate
// files under /dl) and a proxy server with the registry mounted at /cargo.
func setup(t *testing.T, src advisories, tweak func(*Options)) (*Registry, string, *fakeCratesIO) {
	t.Helper()
	index, err := os.ReadFile("testdata/demo_crate.index")
	if err != nil {
		t.Fatal(err)
	}
	api, err := os.ReadFile("testdata/demo_crate.json")
	if err != nil {
		t.Fatal(err)
	}
	times := strings.NewReplacer(
		"{{OLDER}}", older.Format(time.RFC3339Nano),
		"{{OLD}}", old.Format(time.RFC3339Nano),
		"{{YOUNG}}", young.Format(time.RFC3339Nano),
	)
	fake := &fakeCratesIO{index: []byte(times.Replace(string(index)))}
	apiDoc := times.Replace(string(api))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /idx/{path...}", func(w http.ResponseWriter, r *http.Request) {
		fake.mu.Lock()
		fake.indexHits = append(fake.indexHits, r.PathValue("path"))
		fake.mu.Unlock()
		if r.PathValue("path") != "de/mo/demo_crate" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("ETag", `"upstream-etag"`)
		w.Header().Set("Last-Modified", "Mon, 02 Nov 2026 10:00:00 GMT")
		w.Write(fake.index)
	})
	mux.HandleFunc("GET /api/api/v1/crates/{name}", func(w http.ResponseWriter, r *http.Request) {
		if ecosystem.Cargo.Normalize(r.PathValue("name")) != "demo-crate" {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"errors":[{"detail":"crate does not exist"}]}`)
			return
		}
		io.WriteString(w, apiDoc)
	})
	mux.HandleFunc("GET /dl/demo_crate/demo_crate-0.2.0.crate", func(w http.ResponseWriter, _ *http.Request) { w.Write(crateBytes) })
	upstream := httptest.NewServer(mux)
	t.Cleanup(upstream.Close)
	fake.url = upstream.URL

	o := Options{
		Index:    upstream.URL + "/idx",
		API:      upstream.URL + "/api",
		Download: upstream.URL + "/dl",
		Engine:   policy.New(policy.Config{Cooldown: 7 * day}, src),
		HTTP:     proxy.NewUpstream(upstream.Client(), "pkgwarden-test", time.Minute),
	}
	if tweak != nil {
		tweak(&o)
	}
	reg := New(o)
	srv := httptest.NewServer(proxy.NewServer(o.Engine, reg))
	t.Cleanup(srv.Close)
	return reg, srv.URL, fake
}

type response struct {
	status int
	header http.Header
	body   []byte
}

func get(t *testing.T, url string) response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response{resp.StatusCode, resp.Header, body}
}

func TestConfig(t *testing.T) {
	for _, tc := range []struct {
		name, public, wantDL string
	}{
		{"from request host", "", ""},
		{"from public URL", "https://proxy.example/", "https://proxy.example/cargo/api/v1/crates"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, base, fake := setup(t, nil, func(o *Options) { o.PublicURL = tc.public })
			if tc.wantDL == "" {
				tc.wantDL = base + "/cargo/api/v1/crates"
			}
			resp := get(t, base+"/cargo/index/config.json")
			var cfg map[string]string
			if err := json.Unmarshal(resp.body, &cfg); err != nil {
				t.Fatalf("status %d body %q: %v", resp.status, resp.body, err)
			}
			want := map[string]string{"dl": tc.wantDL, "api": fake.url + "/api"}
			if resp.status != http.StatusOK || len(cfg) != len(want) || cfg["dl"] != want["dl"] || cfg["api"] != want["api"] {
				t.Errorf("status %d config %v, want %v", resp.status, cfg, want)
			}
		})
	}
}

func TestIndexHidesBlockedVersions(t *testing.T) {
	_, base, fake := setup(t, nil, nil)
	resp := get(t, base+"/cargo/index/de/mo/demo_crate")
	if resp.status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.status, resp.body)
	}
	lines := bytes.SplitAfter(fake.index, []byte("\n"))
	if want := slices.Concat(lines[0], lines[1]); !bytes.Equal(resp.body, want) {
		t.Errorf("index body\n%s\nwant the upstream lines for 0.1.0 and 0.2.0\n%s", resp.body, want)
	}
	if etag, lm := resp.header.Get("ETag"), resp.header.Get("Last-Modified"); etag != "" || lm != "" {
		t.Errorf("filtered index carries upstream validators ETag %q Last-Modified %q", etag, lm)
	}
}

func TestIndexPathValidation(t *testing.T) {
	_, base, fake := setup(t, nil, nil)
	valid := []string{"1/a", "2/ab", "3/a/abc", "ab/cd/abcd", "de/mo/demo_crate"}
	invalid := []string{"1/ab", "2/a", "3/b/abc", "3/abc", "ab/ce/abcd", "de/demo_crate", "demo_crate", "x/de/mo/demo_crate", "De/mo/Demo_crate", "de/mo/Demo_crate", "de/mo/demo.crate"}
	for _, p := range invalid {
		if resp := get(t, base+"/cargo/index/"+p); resp.status != http.StatusNotFound {
			t.Errorf("GET index/%s: status %d, want 404", p, resp.status)
		}
	}
	for _, p := range valid {
		get(t, base+"/cargo/index/"+p)
	}
	if hits := fake.hits(); !slices.Equal(hits, valid) {
		t.Errorf("upstream index requests %v, want only the valid paths %v", hits, valid)
	}
}

func TestDownloads(t *testing.T) {
	_, base, _ := setup(t, nil, nil)
	for _, tc := range []struct {
		name, path string
		status     int
		body       []byte
		bodyHas    string
	}{
		{"allowed version streams upstream bytes", "/cargo/api/v1/crates/demo_crate/0.2.0/download", http.StatusOK, crateBytes, ""},
		{"crate name differing in case and separator", "/cargo/api/v1/crates/Demo-Crate/0.2.0/download", http.StatusOK, crateBytes, ""},
		{"version inside cooldown", "/cargo/api/v1/crates/demo_crate/0.3.0/download", http.StatusForbidden, nil, "cooldown"},
		{"unpublished version", "/cargo/api/v1/crates/demo_crate/9.9.9/download", http.StatusForbidden, nil, "not published upstream"},
		{"crate file missing upstream", "/cargo/api/v1/crates/demo_crate/0.1.0/download", http.StatusNotFound, nil, ""},
		{"unknown crate", "/cargo/api/v1/crates/no_such_crate/1.0.0/download", http.StatusNotFound, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := telemetrytest.Value(t, "pkgwarden_artifacts_served_total", map[string]string{"ecosystem": "cargo"})
			resp := get(t, base+tc.path)
			served := telemetrytest.Value(t, "pkgwarden_artifacts_served_total", map[string]string{"ecosystem": "cargo"}) - before
			want := 0.0
			if tc.status == http.StatusOK {
				want = 1
			}
			if served != want {
				t.Errorf("artifacts_served_total grew by %v, want %v", served, want)
			}
			if resp.status != tc.status {
				t.Fatalf("status %d, want %d: %s", resp.status, tc.status, resp.body)
			}
			if tc.body != nil && !bytes.Equal(resp.body, tc.body) {
				t.Errorf("body %q, want %q", resp.body, tc.body)
			}
			if !strings.Contains(string(resp.body), tc.bodyHas) {
				t.Errorf("body %q lacks %q", resp.body, tc.bodyHas)
			}
		})
	}
}

func TestHeadOnACrateSkipsTheDownload(t *testing.T) {
	file := proxytest.NewFile()
	dl := httptest.NewServer(file)
	t.Cleanup(dl.Close)
	reg, _, _ := setup(t, nil, func(o *Options) { o.Download = dl.URL })
	// The registry counts a file after its last byte has gone out, so the
	// metrics are read once srv.Close has waited for every handler.
	srv := httptest.NewServer(reg)
	t.Cleanup(srv.Close)
	labels := map[string]string{"ecosystem": "cargo"}
	served := telemetrytest.Value(t, "pkgwarden_artifacts_served_total", labels)
	sent := telemetrytest.Value(t, "pkgwarden_artifact_bytes_total", labels)
	head := func(path string) *http.Response {
		t.Helper()
		resp, err := http.Head(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}

	allowed := head("/api/v1/crates/demo_crate/0.2.0/download")
	if cl := allowed.Header.Get("Content-Length"); allowed.StatusCode != http.StatusOK || cl != strconv.Itoa(file.Size) {
		t.Errorf("HEAD: status %d Content-Length %q, want 200 and %d", allowed.StatusCode, cl, file.Size)
	}
	if n := file.Written(t); n >= file.Size/2 {
		t.Errorf("upstream sent %d of %d bytes for a HEAD, want the transfer cut short", n, file.Size)
	}
	if blocked := head("/api/v1/crates/demo_crate/0.3.0/download"); blocked.StatusCode != http.StatusForbidden {
		t.Errorf("HEAD on a version inside the cooldown: status %d, want 403", blocked.StatusCode)
	}
	resp := get(t, srv.URL+"/api/v1/crates/demo_crate/0.2.0/download")
	if resp.status != http.StatusOK || len(resp.body) != file.Size {
		t.Errorf("GET: status %d with %d bytes, want 200 with %d", resp.status, len(resp.body), file.Size)
	}
	if n := file.Written(t); n != file.Size {
		t.Errorf("upstream sent %d of %d bytes for a GET", n, file.Size)
	}
	srv.Close()

	if d := telemetrytest.Value(t, "pkgwarden_artifacts_served_total", labels) - served; d != 1 {
		t.Errorf("artifacts_served_total grew by %v over a HEAD and a GET, want 1", d)
	}
	if d := telemetrytest.Value(t, "pkgwarden_artifact_bytes_total", labels) - sent; d != float64(file.Size) {
		t.Errorf("artifact_bytes_total grew by %.0f over a HEAD and a GET, want %d", d, file.Size)
	}
}

func TestPackageWideAdvisoryBlocks(t *testing.T) {
	src := advisories{"demo_crate": {{ID: "RUSTSEC-2026-0001", Source: "osv", Kind: advisory.Malicious, Summary: "demo_crate is malware", Ecosystem: ecosystem.Cargo}}}
	_, base, _ := setup(t, src, nil)
	for _, p := range []string{"/cargo/index/de/mo/demo_crate", "/cargo/api/v1/crates/demo_crate/0.2.0/download"} {
		resp := get(t, base+p)
		if resp.status != http.StatusForbidden || !strings.Contains(string(resp.body), "RUSTSEC-2026-0001") {
			t.Errorf("GET %s: status %d body %q", p, resp.status, resp.body)
		}
	}
}

func TestPackage(t *testing.T) {
	reg, _, _ := setup(t, nil, nil)
	pkg, err := reg.Package(context.Background(), "Demo-Crate")
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Ecosystem != ecosystem.Cargo || pkg.Name != "demo_crate" || pkg.WeeklyDownloads != 10000 || !pkg.Created.Equal(older) {
		t.Errorf("package %s/%s downloads %d created %v", pkg.Ecosystem, pkg.Name, pkg.WeeklyDownloads, pkg.Created)
	}
	want := []policy.Release{
		{Version: "0.3.0", Published: young, Publishers: []string{"newcomer"}},
		{Version: "0.2.0", Published: old, Publishers: []string{"maintainer"}},
		{Version: "0.1.0", Published: older},
	}
	if !slices.EqualFunc(pkg.Releases, want, func(a, b policy.Release) bool {
		return a.Version == b.Version && a.Published.Equal(b.Published) && slices.Equal(a.Publishers, b.Publishers) && (a.Publishers == nil) == (b.Publishers == nil)
	}) {
		t.Errorf("releases %+v, want %+v", pkg.Releases, want)
	}
}

func TestUnknownCrate(t *testing.T) {
	reg, _, _ := setup(t, nil, nil)
	if _, err := reg.Package(context.Background(), "no_such_crate"); !errors.Is(err, proxy.ErrNotFound) {
		t.Errorf("Package error %v, want ErrNotFound", err)
	}
}
