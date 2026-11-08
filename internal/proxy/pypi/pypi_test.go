package pypi

import (
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

	wheelPath     = "/files/packages/10/e3/a7f8eea80a9fa8358c1cd89ef489bc03675e69e54ed2982cd6f2a28d8295/demo_pkg-1.0.0-py3-none-any.whl"
	wheelBytes    = []byte("PK\x03\x04\x14\x00demo_pkg-1.0.0 wheel\x00\xff")
	sdistPath     = "/files/packages/71/dc/2a1e4e5c8f0e0e3d4b8e9c7f9e5b2a1b6c4f3e2d1c0b9a8f7e6d5c4b3a29/demo_pkg-1.0.0.tar.gz"
	metadataBytes = []byte("Metadata-Version: 2.1\nName: demo-pkg\nVersion: 1.0.0\n")
	rootIndex     = "<!DOCTYPE html>\n<html><body><a href=\"/simple/demo-pkg/\">demo-pkg</a></body></html>\n"
)

const pipAccept = "application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html;q=0.1, text/html;q=0.01"

type advisories map[string][]advisory.Advisory

func (s advisories) Lookup(_ context.Context, _ ecosystem.Ecosystem, name string) ([]advisory.Advisory, error) {
	return s[name], nil
}

// setup starts a fake PyPI and a proxy server with the registry mounted at
// /pypi, and returns the registry and the proxy's URL. tweak may change the
// options and add routes to the fake PyPI.
func setup(t *testing.T, src advisories, tweak func(*Options, *http.ServeMux)) (*Registry, string) {
	t.Helper()
	fixture, err := os.ReadFile("testdata/demo-pkg.json")
	if err != nil {
		t.Fatal(err)
	}
	stats, err := os.ReadFile("testdata/demo-pkg-recent.json")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	upstream := httptest.NewServer(mux)
	t.Cleanup(upstream.Close)
	meta := strings.NewReplacer(
		"{{FILES}}", upstream.URL+"/files",
		"{{OLDER}}", older.Format(time.RFC3339Nano),
		"{{OLD}}", old.Format(time.RFC3339Nano),
		"{{YOUNG}}", young.Format(time.RFC3339Nano),
	).Replace(string(fixture))
	mux.HandleFunc("GET /pypi/demo-pkg/json", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, meta) })
	mux.HandleFunc("GET /stats/api/packages/demo-pkg/recent", func(w http.ResponseWriter, _ *http.Request) { w.Write(stats) })
	mux.HandleFunc("GET "+wheelPath, func(w http.ResponseWriter, _ *http.Request) { w.Write(wheelBytes) })
	mux.HandleFunc("GET "+wheelPath+".metadata", func(w http.ResponseWriter, _ *http.Request) { w.Write(metadataBytes) })
	mux.HandleFunc("GET /simple/{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", r.Header.Get("Accept"))
		io.WriteString(w, rootIndex)
	})

	o := Options{
		PyPI:   upstream.URL,
		Files:  upstream.URL + "/files",
		Stats:  upstream.URL + "/stats",
		Engine: policy.New(policy.Config{Cooldown: 7 * day}, src),
		HTTP:   proxy.NewUpstream(upstream.Client(), "pkgwarden-test", time.Minute),
	}
	if tweak != nil {
		tweak(&o, mux)
	}
	reg := New(o)
	srv := httptest.NewServer(proxy.NewServer(o.Engine, reg))
	t.Cleanup(srv.Close)
	return reg, srv.URL
}

type response struct {
	status int
	header http.Header
	body   []byte
}

func get(t *testing.T, url, accept string) response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
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

type simpleFile struct {
	Filename       string            `json:"filename"`
	URL            string            `json:"url"`
	Hashes         map[string]string `json:"hashes"`
	RequiresPython *string           `json:"requires-python"`
	Yanked         any               `json:"yanked"`
	Size           int64             `json:"size"`
	UploadTime     time.Time         `json:"upload-time"`
	CoreMetadata   any               `json:"core-metadata"`
}

type simplePage struct {
	Meta struct {
		APIVersion string `json:"api-version"`
	} `json:"meta"`
	Name     string       `json:"name"`
	Versions []string     `json:"versions"`
	Files    []simpleFile `json:"files"`
}

func TestSimpleJSONListsOnlyAllowedReleases(t *testing.T) {
	_, base := setup(t, nil, nil)
	resp := get(t, base+"/pypi/simple/demo-pkg/", pipAccept)
	if resp.status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.status, resp.body)
	}
	if ct := resp.header.Get("Content-Type"); ct != "application/vnd.pypi.simple.v1+json" {
		t.Fatalf("Content-Type %q", ct)
	}
	var page simplePage
	if err := json.Unmarshal(resp.body, &page); err != nil {
		t.Fatal(err)
	}
	if page.Meta.APIVersion != "1.1" || page.Name != "demo-pkg" {
		t.Errorf("meta %+v name %q", page.Meta, page.Name)
	}
	if want := []string{"0.8.0", "0.9.0", "1.0.0"}; !slices.Equal(page.Versions, want) {
		t.Errorf("versions %v, want %v", page.Versions, want)
	}
	var names []string
	byName := map[string]simpleFile{}
	for _, f := range page.Files {
		names = append(names, f.Filename)
		byName[f.Filename] = f
	}
	if want := []string{"demo_pkg-0.8.0.tar.gz", "demo_pkg-0.9.0.tar.gz", "demo_pkg-1.0.0-py3-none-any.whl", "demo_pkg-1.0.0.tar.gz"}; !slices.Equal(names, want) {
		t.Errorf("files %v, want %v", names, want)
	}

	wheel := byName["demo_pkg-1.0.0-py3-none-any.whl"]
	if want := base + "/pypi/files/demo-pkg/1.0.0/demo_pkg-1.0.0-py3-none-any.whl"; wheel.URL != want {
		t.Errorf("wheel url %q, want %q", wheel.URL, want)
	}
	if wheel.Hashes["sha256"] != strings.Repeat("10", 32) || wheel.Size != 11053 || !wheel.UploadTime.Equal(old) {
		t.Errorf("wheel hashes %v size %d upload-time %v", wheel.Hashes, wheel.Size, wheel.UploadTime)
	}
	if wheel.RequiresPython == nil || *wheel.RequiresPython != ">=3.8, !=3.9.*" {
		t.Errorf("wheel requires-python %v", wheel.RequiresPython)
	}
	if cm, ok := wheel.CoreMetadata.(map[string]any); !ok || cm["sha256"] != strings.Repeat("c", 64) {
		t.Errorf("wheel core-metadata %v", wheel.CoreMetadata)
	}
	if wheel.Yanked != false {
		t.Errorf("wheel yanked %v", wheel.Yanked)
	}
	if y := byName["demo_pkg-0.9.0.tar.gz"].Yanked; y != "broken <build> & bad metadata" {
		t.Errorf("0.9.0 yanked %v", y)
	}
	if sdist := byName["demo_pkg-0.8.0.tar.gz"]; sdist.RequiresPython != nil || sdist.CoreMetadata != false {
		t.Errorf("0.8.0 requires-python %v core-metadata %v", sdist.RequiresPython, sdist.CoreMetadata)
	}
}

func TestSimpleHTML(t *testing.T) {
	_, base := setup(t, nil, nil)
	resp := get(t, base+"/pypi/simple/demo-pkg/", "text/html")
	if resp.status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.status, resp.body)
	}
	body := string(resp.body)
	for _, want := range []string{
		`<meta name="pypi:repository-version" content="1.1">`,
		`<a href="` + base + `/pypi/files/demo-pkg/1.0.0/demo_pkg-1.0.0-py3-none-any.whl#sha256=` + strings.Repeat("10", 32) +
			`" data-requires-python="&gt;=3.8, !=3.9.*" data-core-metadata="sha256=` + strings.Repeat("c", 64) +
			`" data-dist-info-metadata="sha256=` + strings.Repeat("c", 64) + `">demo_pkg-1.0.0-py3-none-any.whl</a>`,
		`<a href="` + base + `/pypi/files/demo-pkg/0.9.0/demo_pkg-0.9.0.tar.gz#sha256=` + strings.Repeat("90", 32) +
			`" data-yanked="broken &lt;build&gt; &amp; bad metadata">demo_pkg-0.9.0.tar.gz</a>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s\n%s", want, body)
		}
	}
	if strings.Contains(body, "1.1.0") {
		t.Errorf("page lists the release inside the cooldown:\n%s", body)
	}
}

func TestSimpleContentNegotiation(t *testing.T) {
	_, base := setup(t, nil, nil)
	for _, tc := range []struct {
		accept, want string
	}{
		{"", "text/html"},
		{pipAccept, "application/vnd.pypi.simple.v1+json"},
		{"application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html;q=0.2, text/html;q=0.01", "application/vnd.pypi.simple.v1+json"},
		{"application/vnd.pypi.simple.latest+json", "application/vnd.pypi.simple.v1+json"},
		{"text/html", "text/html"},
		{"application/vnd.pypi.simple.v1+html", "application/vnd.pypi.simple.v1+html"},
		{"application/vnd.pypi.simple.v1+json;q=0.1, text/html", "text/html"},
		{"application/vnd.pypi.simple.v1+json;q=0, */*", "text/html"},
		{"application/json", "text/html"},
		{"text/html, application/vnd.pypi.simple.v1+json", "text/html"},
		{"application/vnd.pypi.simple.v1+json, text/html", "application/vnd.pypi.simple.v1+json"},
	} {
		resp := get(t, base+"/pypi/simple/demo-pkg/", tc.accept)
		ct := resp.header.Get("Content-Type")
		isJSON := json.Valid(resp.body)
		if ct != tc.want || isJSON != strings.HasSuffix(tc.want, "+json") {
			t.Errorf("Accept %q: Content-Type %q (JSON body %v), want %q", tc.accept, ct, isJSON, tc.want)
		}
	}
}

func TestSimpleRedirectsToNormalizedName(t *testing.T) {
	_, base := setup(t, nil, nil)
	for _, p := range []string{"/pypi/simple/Demo_Pkg/", "/pypi/simple/demo.pkg", "/pypi/simple/demo-pkg"} {
		resp := get(t, base+p, "")
		if loc := resp.header.Get("Location"); resp.status != http.StatusMovedPermanently || loc != base+"/pypi/simple/demo-pkg/" {
			t.Errorf("GET %s: status %d Location %q", p, resp.status, loc)
		}
	}
}

func TestFiles(t *testing.T) {
	_, base := setup(t, nil, nil)
	for _, tc := range []struct {
		name, path string
		status     int
		body       []byte
		bodyHas    string
		artifact   bool
	}{
		{"allowed wheel streams upstream bytes", "/pypi/files/demo-pkg/1.0.0/demo_pkg-1.0.0-py3-none-any.whl", http.StatusOK, wheelBytes, "", true},
		{"PEP 658 metadata", "/pypi/files/demo-pkg/1.0.0/demo_pkg-1.0.0-py3-none-any.whl.metadata", http.StatusOK, metadataBytes, "", false},
		{"release inside cooldown", "/pypi/files/demo-pkg/1.1.0/demo_pkg-1.1.0-py3-none-any.whl", http.StatusForbidden, nil, "cooldown", false},
		{"unpublished version", "/pypi/files/demo-pkg/9.9.9/demo_pkg-9.9.9.tar.gz", http.StatusForbidden, nil, "not published upstream", false},
		{"filename from another release", "/pypi/files/demo-pkg/1.0.0/demo_pkg-1.1.0-py3-none-any.whl", http.StatusNotFound, nil, "", false},
		{"metadata upstream lacks", "/pypi/files/demo-pkg/1.0.0/demo_pkg-1.0.0.tar.gz.metadata", http.StatusNotFound, nil, "", false},
		{"file URL outside the files host", "/pypi/files/demo-pkg/0.8.0/demo_pkg-0.8.0.tar.gz", http.StatusBadGateway, nil, "not under", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := telemetrytest.Value(t, "pkgwarden_artifacts_served_total", map[string]string{"ecosystem": "pypi"})
			resp := get(t, base+tc.path, "")
			served := telemetrytest.Value(t, "pkgwarden_artifacts_served_total", map[string]string{"ecosystem": "pypi"}) - before
			want := 0.0
			if tc.artifact {
				want = 1
			}
			if served != want {
				t.Errorf("artifacts_served_total grew by %v, want %v", served, want)
			}
			if resp.status != tc.status {
				t.Fatalf("status %d, want %d: %s", resp.status, tc.status, resp.body)
			}
			if tc.body != nil && string(resp.body) != string(tc.body) {
				t.Errorf("body %q, want %q", resp.body, tc.body)
			}
			if !strings.Contains(string(resp.body), tc.bodyHas) {
				t.Errorf("body %q lacks %q", resp.body, tc.bodyHas)
			}
		})
	}
}

func TestHeadOnAFileSkipsTheDownload(t *testing.T) {
	file := proxytest.NewFile()
	reg, _ := setup(t, nil, func(_ *Options, upstream *http.ServeMux) { upstream.Handle("GET "+sdistPath, file) })
	// The registry counts a file after its last byte has gone out, so the
	// metrics are read once srv.Close has waited for every handler.
	srv := httptest.NewServer(reg)
	t.Cleanup(srv.Close)
	labels := map[string]string{"ecosystem": "pypi"}
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

	allowed := head("/files/demo-pkg/1.0.0/demo_pkg-1.0.0.tar.gz")
	if cl := allowed.Header.Get("Content-Length"); allowed.StatusCode != http.StatusOK || cl != strconv.Itoa(file.Size) {
		t.Errorf("HEAD: status %d Content-Length %q, want 200 and %d", allowed.StatusCode, cl, file.Size)
	}
	if n := file.Written(t); n >= file.Size/2 {
		t.Errorf("upstream sent %d of %d bytes for a HEAD, want the transfer cut short", n, file.Size)
	}
	if blocked := head("/files/demo-pkg/1.1.0/demo_pkg-1.1.0-py3-none-any.whl"); blocked.StatusCode != http.StatusForbidden {
		t.Errorf("HEAD on a release inside the cooldown: status %d, want 403", blocked.StatusCode)
	}
	resp := get(t, srv.URL+"/files/demo-pkg/1.0.0/demo_pkg-1.0.0.tar.gz", "")
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
	src := advisories{"demo-pkg": {{ID: "MAL-2026-0001", Source: "openssf", Kind: advisory.Malicious, Summary: "Malicious code in demo-pkg", Ecosystem: ecosystem.PyPI}}}
	_, base := setup(t, src, nil)
	for _, p := range []string{"/pypi/simple/demo-pkg/", "/pypi/files/demo-pkg/1.0.0/demo_pkg-1.0.0-py3-none-any.whl"} {
		resp := get(t, base+p, pipAccept)
		if resp.status != http.StatusForbidden || !strings.Contains(string(resp.body), "MAL-2026-0001") {
			t.Errorf("GET %s: status %d body %q", p, resp.status, resp.body)
		}
	}
}

func TestRootIndexPassesThrough(t *testing.T) {
	_, base := setup(t, nil, nil)
	resp := get(t, base+"/pypi/simple/", "text/html")
	if resp.status != http.StatusOK || string(resp.body) != rootIndex || resp.header.Get("Content-Type") != "text/html" {
		t.Errorf("status %d Content-Type %q body %q", resp.status, resp.header.Get("Content-Type"), resp.body)
	}
}

func TestUnknownProject(t *testing.T) {
	reg, base := setup(t, nil, nil)
	if resp := get(t, base+"/pypi/simple/no-such-project/", ""); resp.status != http.StatusNotFound {
		t.Errorf("simple page status %d", resp.status)
	}
	if _, err := reg.Package(context.Background(), "no-such-project"); !errors.Is(err, proxy.ErrNotFound) {
		t.Errorf("Package error %v, want ErrNotFound", err)
	}
}

func TestPackage(t *testing.T) {
	reg, _ := setup(t, nil, nil)
	pkg, err := reg.Package(context.Background(), "Demo_Pkg")
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Ecosystem != ecosystem.PyPI || pkg.Name != "demo-pkg" || pkg.WeeklyDownloads != 40321 || !pkg.Created.Equal(older) {
		t.Errorf("package %s/%s downloads %d created %v", pkg.Ecosystem, pkg.Name, pkg.WeeklyDownloads, pkg.Created)
	}
	want := map[string]time.Time{"0.8.0": older, "0.9.0": older, "1.0.0": old, "1.1.0": young}
	if len(pkg.Releases) != len(want) {
		t.Errorf("releases %+v, want versions of %v", pkg.Releases, want)
	}
	for _, r := range pkg.Releases {
		if !r.Published.Equal(want[r.Version]) || r.Publishers != nil {
			t.Errorf("release %+v, want published %v and no publishers", r, want[r.Version])
		}
	}
}

func TestPackageWithoutDownloadStats(t *testing.T) {
	reg, _ := setup(t, nil, func(o *Options, _ *http.ServeMux) { o.Stats += "/missing" })
	pkg, err := reg.Package(context.Background(), "demo-pkg")
	if err != nil {
		t.Fatal(err)
	}
	if pkg.WeeklyDownloads != policy.UnknownDownloads {
		t.Errorf("downloads %d, want UnknownDownloads", pkg.WeeklyDownloads)
	}
}

// The fake JSON API answers only once the stats request has arrived, so the
// test also fails when the two lookups run one after the other.
func TestPackageWhenDownloadStatsHang(t *testing.T) {
	statsAsked := make(chan struct{})
	release := make(chan struct{})
	hung := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(statsAsked)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(hung.Close)
	t.Cleanup(func() { close(release) })
	reg, _ := setup(t, nil, func(o *Options, _ *http.ServeMux) {
		o.Stats = hung.URL
		api := o.PyPI
		gated := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-statsAsked:
			case <-time.After(3 * time.Second):
				http.Error(w, "stats never requested", http.StatusServiceUnavailable)
				return
			}
			resp, err := http.Get(api + r.URL.Path)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			io.Copy(w, resp.Body)
		}))
		t.Cleanup(gated.Close)
		o.PyPI = gated.URL
	})

	start := time.Now()
	pkg, err := reg.Package(context.Background(), "demo-pkg")
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("Package took %v, want the stats lookup cut short", elapsed)
	}
	if pkg.WeeklyDownloads != policy.UnknownDownloads || len(pkg.Releases) == 0 {
		t.Errorf("downloads %d with %d releases, want UnknownDownloads and the project's releases", pkg.WeeklyDownloads, len(pkg.Releases))
	}
}
