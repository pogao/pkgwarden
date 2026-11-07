package npm_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pogao/pkgwarden/internal/advisory"
	"github.com/pogao/pkgwarden/internal/ecosystem"
	"github.com/pogao/pkgwarden/internal/policy"
	"github.com/pogao/pkgwarden/internal/proxy"
	"github.com/pogao/pkgwarden/internal/proxy/npm"
)

type fakeSource map[string][]advisory.Advisory

func (f fakeSource) Lookup(_ context.Context, _ ecosystem.Ecosystem, name string) ([]advisory.Advisory, error) {
	return f[name], nil
}

var (
	old   = time.Now().Add(-30 * 24 * time.Hour).UTC()
	young = time.Now().Add(-2 * 24 * time.Hour).UTC()
)

const npmTime = "2006-01-02T15:04:05.000Z07:00"

func tarballBytes(path string) []byte { return []byte("\x1f\x8b\x08\x00 tarball " + path) }

func fakeRegistry(t *testing.T) *httptest.Server {
	t.Helper()
	tmpl, err := os.ReadFile("testdata/packument.json")
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case r.Method == http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			json.NewEncoder(w).Encode(map[string]string{"path": p, "contentType": r.Header.Get("Content-Type"), "body": string(body)})
		case p == "/-/v1/search":
			w.Write([]byte(`{"objects":[],"text":"` + r.URL.Query().Get("text") + `"}`))
		case strings.HasSuffix(p, ".tgz"):
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(tarballBytes(p))
		case p == "/@acme/widget" || p == "/left-pad":
			if r.Header.Get("Accept") != "application/json" {
				t.Errorf("packument requested with Accept %q, want the full document", r.Header.Get("Accept"))
			}
			name := strings.TrimPrefix(p, "/")
			doc := strings.NewReplacer(
				"__NAME__", name,
				"__UNSCOPED__", name[strings.LastIndex(name, "/")+1:],
				"__REGISTRY__", srv.URL,
				"__OLD__", old.Format(npmTime),
				"__YOUNG__", young.Format(npmTime),
			).Replace(string(tmpl))
			w.Header().Set("ETag", `W/"upstream"`)
			w.Header().Set("Last-Modified", "Mon, 02 Nov 2026 10:00:00 GMT")
			w.Write([]byte(doc))
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"Not found"}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func fakeDownloads(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/downloads/point/last-week/@acme/widget" {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"package not found"}`))
			return
		}
		w.Write([]byte(`{"downloads":1234,"start":"2026-10-31","end":"2026-11-06","package":"@acme/widget"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

type env struct {
	proxy *httptest.Server
	reg   *npm.Registry
}

func newEnv(t *testing.T, cooldown time.Duration, src fakeSource) env {
	t.Helper()
	engine := policy.New(policy.Config{Cooldown: cooldown}, src)
	reg := npm.New(npm.Options{
		Registry:  fakeRegistry(t).URL,
		Downloads: fakeDownloads(t).URL,
		Engine:    engine,
		HTTP:      proxy.NewUpstream(http.DefaultClient, "pkgwarden-test", time.Minute),
	})
	srv := httptest.NewServer(proxy.NewServer(engine, reg))
	t.Cleanup(srv.Close)
	return env{proxy: srv, reg: reg}
}

const week = 7 * 24 * time.Hour

func get(t *testing.T, url string) (*http.Response, []byte) {
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
	return resp, b
}

type packumentView struct {
	DistTags map[string]string `json:"dist-tags"`
	Versions map[string]struct {
		HasShrinkwrap *bool `json:"_hasShrinkwrap"`
		Dist          struct {
			Tarball   string `json:"tarball"`
			Integrity string `json:"integrity"`
		} `json:"dist"`
	} `json:"versions"`
	Time        map[string]string `json:"time"`
	Readme      string            `json:"readme"`
	Description string            `json:"description"`
}

func TestPackumentHidesBlockedVersions(t *testing.T) {
	e := newEnv(t, week, nil)
	tests := []struct {
		path, name string
	}{
		{"/npm/left-pad", "left-pad"},
		{"/npm/@acme/widget", "@acme/widget"},
		{"/npm/@acme%2fwidget", "@acme/widget"},
		{"/npm/@acme%2Fwidget", "@acme/widget"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			resp, body := get(t, e.proxy.URL+tt.path)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d: %s", resp.StatusCode, body)
			}
			if h := resp.Header.Get("ETag") + resp.Header.Get("Last-Modified"); h != "" {
				t.Errorf("upstream validators forwarded for a rewritten body: %q", h)
			}
			var doc packumentView
			if err := json.Unmarshal(body, &doc); err != nil {
				t.Fatal(err)
			}
			wantVersions := []string{"0.9.0", "1.0.0", "1.0.1-beta.0", "3.0.0"}
			if got := slices.Sorted(maps.Keys(doc.Versions)); !slices.Equal(got, wantVersions) {
				t.Errorf("versions = %v, want %v", got, wantVersions)
			}
			wantTags := map[string]string{"latest": "1.0.0", "legacy": "0.9.0", "v3": "3.0.0"}
			if !maps.Equal(doc.DistTags, wantTags) {
				t.Errorf("dist-tags = %v, want %v", doc.DistTags, wantTags)
			}
			for _, v := range []string{"1.1.0", "2.0.0-rc.1"} {
				if _, ok := doc.Time[v]; ok {
					t.Errorf("time still lists blocked version %s", v)
				}
			}
			if doc.Time["created"] == "" || doc.Time["1.0.0"] == "" {
				t.Errorf("time lost allowed entries: %v", doc.Time)
			}
			unscoped := tt.name[strings.LastIndex(tt.name, "/")+1:]
			for v, m := range doc.Versions {
				want := e.proxy.URL + "/npm/" + tt.name + "/-/" + unscoped + "-" + v + ".tgz"
				if m.Dist.Tarball != want {
					t.Errorf("version %s tarball = %q, want %q", v, m.Dist.Tarball, want)
				}
				if m.Dist.Integrity == "" || m.HasShrinkwrap == nil {
					t.Errorf("version %s lost upstream fields", v)
				}
			}
			if doc.Readme != "# widget\n\nUse `<Widget />` & enjoy." || doc.Description != "Compare strings <fast> & safe" {
				t.Errorf("unrewritten fields changed: readme %q description %q", doc.Readme, doc.Description)
			}
			if bytes.Contains(body, []byte("\\u003c")) {
				t.Error("body HTML-escapes upstream text")
			}
		})
	}
}

func TestPublicURLWinsForTarballs(t *testing.T) {
	engine := policy.New(policy.Config{Cooldown: week}, fakeSource(nil))
	reg := npm.New(npm.Options{
		Registry:  fakeRegistry(t).URL,
		Downloads: fakeDownloads(t).URL,
		PublicURL: "https://pkgs.example.com/",
		Engine:    engine,
		HTTP:      proxy.NewUpstream(http.DefaultClient, "pkgwarden-test", time.Minute),
	})
	srv := httptest.NewServer(proxy.NewServer(engine, reg))
	defer srv.Close()
	_, body := get(t, srv.URL+"/npm/left-pad")
	var doc packumentView
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if got, want := doc.Versions["1.0.0"].Dist.Tarball, "https://pkgs.example.com/npm/left-pad/-/left-pad-1.0.0.tgz"; got != want {
		t.Errorf("tarball = %q, want %q", got, want)
	}
}

func TestTarball(t *testing.T) {
	e := newEnv(t, week, nil)
	_, body := get(t, e.proxy.URL+"/npm/@acme%2fwidget")
	var doc packumentView
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}

	t.Run("allowed version streams upstream bytes", func(t *testing.T) {
		for _, name := range []string{"@acme/widget", "left-pad"} {
			unscoped := name[strings.LastIndex(name, "/")+1:]
			resp, got := get(t, e.proxy.URL+"/npm/"+name+"/-/"+unscoped+"-1.0.0.tgz")
			want := tarballBytes("/" + name + "/-/" + unscoped + "-1.0.0.tgz")
			if resp.StatusCode != http.StatusOK || !bytes.Equal(got, want) {
				t.Errorf("%s: status %d body %q, want 200 %q", name, resp.StatusCode, got, want)
			}
		}
		resp, got := get(t, doc.Versions["1.0.0"].Dist.Tarball)
		if resp.StatusCode != http.StatusOK || !bytes.Equal(got, tarballBytes("/@acme/widget/-/widget-1.0.0.tgz")) {
			t.Errorf("rewritten tarball URL: status %d body %q", resp.StatusCode, got)
		}
	})

	tests := []struct {
		name, path string
		want       []string
	}{
		{"young version", "/npm/@acme/widget/-/widget-1.1.0.tgz", []string{"npm/@acme/widget@1.1.0", "cooldown"}},
		{"young unscoped version", "/npm/left-pad/-/left-pad-2.0.0-rc.1.tgz", []string{"npm/left-pad@2.0.0-rc.1", "cooldown"}},
		{"unpublished version", "/npm/left-pad/-/left-pad-9.9.9.tgz", []string{"unknown-release"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := get(t, e.proxy.URL+tt.path)
			assertBlocked(t, resp, body, tt.want...)
		})
	}
}

func TestVersionManifest(t *testing.T) {
	e := newEnv(t, week, nil)
	for _, path := range []string{"/npm/@acme/widget/1.0.0", "/npm/@acme%2fwidget/latest"} {
		resp, body := get(t, e.proxy.URL+path)
		var m struct {
			Version string `json:"version"`
			Dist    struct {
				Tarball string `json:"tarball"`
			} `json:"dist"`
		}
		if err := json.Unmarshal(body, &m); err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d body %s", path, resp.StatusCode, body)
		}
		if m.Version != "1.0.0" || !strings.HasPrefix(m.Dist.Tarball, e.proxy.URL+"/npm/") {
			t.Errorf("%s: version %q tarball %q, want 1.0.0 served through the proxy", path, m.Version, m.Dist.Tarball)
		}
	}
	resp, body := get(t, e.proxy.URL+"/npm/@acme/widget/1.1.0")
	assertBlocked(t, resp, body, "npm/@acme/widget@1.1.0", "cooldown")
}

func assertBlocked(t *testing.T, resp *http.Response, body []byte, want ...string) {
	t.Helper()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", resp.StatusCode, body)
	}
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatalf("403 body is not npm's JSON error: %s", body)
	}
	for _, w := range want {
		if !strings.Contains(e.Error, w) {
			t.Errorf("error %q does not mention %q", e.Error, w)
		}
	}
}

func TestPackageWideAdvisoryBlocks(t *testing.T) {
	e := newEnv(t, week, fakeSource{"@acme/widget": {{
		ID: "MAL-2026-0001", Source: "openssf", Kind: advisory.Malicious, Summary: "Malicious code in @acme/widget",
	}}})
	for _, path := range []string{"/npm/@acme%2fwidget", "/npm/@acme/widget/-/widget-1.0.0.tgz"} {
		resp, body := get(t, e.proxy.URL+path)
		assertBlocked(t, resp, body, "MAL-2026-0001")
	}
	if resp, _ := get(t, e.proxy.URL+"/npm/left-pad"); resp.StatusCode != http.StatusOK {
		t.Errorf("unrelated package status %d", resp.StatusCode)
	}
}

func TestNothingAllowedBlocksWithLatestReasons(t *testing.T) {
	e := newEnv(t, 365*24*time.Hour, nil)
	resp, body := get(t, e.proxy.URL+"/npm/@acme/widget")
	assertBlocked(t, resp, body, "npm/@acme/widget@1.1.0", "cooldown")
}

func TestPackage(t *testing.T) {
	e := newEnv(t, week, nil)
	pkg, err := e.reg.Package(context.Background(), "@acme/widget")
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Ecosystem != ecosystem.Npm || pkg.Name != "@acme/widget" || pkg.WeeklyDownloads != 1234 {
		t.Errorf("package = %s %q downloads %d", pkg.Ecosystem, pkg.Name, pkg.WeeklyDownloads)
	}
	if d := pkg.Created.Sub(old); d < -time.Millisecond || d > time.Millisecond {
		t.Errorf("created = %v, want %v", pkg.Created, old)
	}
	releases := map[string]policy.Release{}
	for _, r := range pkg.Releases {
		releases[r.Version] = r
	}
	tests := []struct {
		version    string
		publishers []string
		scripts    bool
		published  time.Time
	}{
		{"0.9.0", []string{"alice"}, false, old},
		{"1.0.0", []string{"alice", "bob"}, false, old},
		{"1.1.0", []string{"mallory"}, true, young},
	}
	for _, tt := range tests {
		r, ok := releases[tt.version]
		if !ok {
			t.Errorf("release %s missing", tt.version)
			continue
		}
		if !slices.Equal(r.Publishers, tt.publishers) || r.InstallScripts != tt.scripts || r.Published.Sub(tt.published).Abs() > time.Millisecond {
			t.Errorf("release %s = %+v", tt.version, r)
		}
	}
	if len(releases) != 6 {
		t.Errorf("got %d releases, want 6", len(releases))
	}

	left, err := e.reg.Package(context.Background(), "left-pad")
	if err != nil {
		t.Fatal(err)
	}
	if left.WeeklyDownloads != policy.UnknownDownloads {
		t.Errorf("failed download lookup gave %d, want UnknownDownloads", left.WeeklyDownloads)
	}

	if _, err := e.reg.Package(context.Background(), "no-such-package"); !errors.Is(err, proxy.ErrNotFound) {
		t.Errorf("unknown package error = %v, want ErrNotFound", err)
	}
}

func TestPassthrough(t *testing.T) {
	e := newEnv(t, week, nil)

	resp, body := get(t, e.proxy.URL+"/npm/-/v1/search?text=widget")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"text":"widget"`) {
		t.Errorf("search: status %d body %s", resp.StatusCode, body)
	}

	for _, path := range []string{"/-/npm/v1/security/advisories/bulk", "/-/npm/v1/security/audits/quick"} {
		resp, err := http.Post(e.proxy.URL+"/npm"+path, "application/json", strings.NewReader(`{"left-pad":["1.0.0"]}`))
		if err != nil {
			t.Fatal(err)
		}
		var echo map[string]string
		json.NewDecoder(resp.Body).Decode(&echo)
		resp.Body.Close()
		want := map[string]string{"path": path, "contentType": "application/json", "body": `{"left-pad":["1.0.0"]}`}
		if resp.StatusCode != http.StatusOK || !maps.Equal(echo, want) {
			t.Errorf("POST %s: status %d upstream saw %v", path, resp.StatusCode, echo)
		}
	}

	for _, req := range []struct{ method, path string }{
		{http.MethodPut, "/npm/left-pad"},
		{http.MethodPost, "/npm/left-pad"},
		{http.MethodDelete, "/npm/-/v1/search"},
	} {
		r, _ := http.NewRequest(req.method, e.proxy.URL+req.path, strings.NewReader("{}"))
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: status %d, want 405", req.method, req.path, resp.StatusCode)
		}
	}
}
