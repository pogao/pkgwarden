package rubygems_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pogao/pkgwarden/internal/advisory"
	"github.com/pogao/pkgwarden/internal/ecosystem"
	"github.com/pogao/pkgwarden/internal/policy"
	"github.com/pogao/pkgwarden/internal/proxy"
	"github.com/pogao/pkgwarden/internal/proxy/rubygems"
	"github.com/pogao/pkgwarden/internal/telemetry/telemetrytest"
)

const day = 24 * time.Hour

type fakeVersion struct {
	number, platform string
	age              time.Duration
}

type fakeGem struct {
	versions  []fakeVersion
	downloads int64
	info      []byte
}

// fakeRubyGems serves the rubygems.org endpoints the adapter reads, with
// publish times relative to now so the cooldown applies.
func fakeRubyGems(t *testing.T, gems map[string]fakeGem) *httptest.Server {
	t.Helper()
	now := time.Now()
	versionsFile := bytes.Repeat([]byte("created_at: 2024-04-01T00:00:05Z\n---\nrack 1.0.0,2.0.0 0123456789abcdef\n"), 4)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/versions/{file}", func(w http.ResponseWriter, r *http.Request) {
		g, ok := gems[strings.TrimSuffix(r.PathValue("file"), ".json")]
		if !ok {
			http.Error(w, "This rubygem could not be found.", http.StatusNotFound)
			return
		}
		var out []map[string]any
		for _, v := range g.versions {
			platform := v.platform
			if platform == "" {
				platform = "ruby"
			}
			out = append(out, map[string]any{
				"authors": "someone", "number": v.number, "platform": platform, "prerelease": false,
				"created_at": now.Add(-v.age).UTC().Format("2006-01-02T15:04:05.000Z"),
				"sha":        "ffd13740c573b7301cf7a2e61fc857b2a8e3d3aff32545d6f8300d8bae10e3ef",
			})
		}
		json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("GET /api/v1/gems/{file}", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSuffix(r.PathValue("file"), ".json")
		g, ok := gems[name]
		if !ok || g.downloads < 0 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"name": name, "downloads": g.downloads})
	})
	mux.HandleFunc("GET /info/{name}", func(w http.ResponseWriter, r *http.Request) {
		g, ok := gems[r.PathValue("name")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("ETag", `"upstream-etag"`)
		w.Header().Set("Repr-Digest", `sha-256="dXBzdHJlYW0="`)
		w.Header().Set("Digest", `sha-256="dXBzdHJlYW0="`)
		w.Write(g.info)
	})
	artifact := func(w http.ResponseWriter, r *http.Request) {
		w.Write(artifactBytes(r.PathValue("file")))
	}
	mux.HandleFunc("GET /gems/{file}", artifact)
	mux.HandleFunc("GET /downloads/{file}", artifact)
	mux.HandleFunc("GET /quick/Marshal.4.8/{file}", artifact)
	mux.HandleFunc("GET /versions", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"versions-etag"`)
		http.ServeContent(w, r, "versions", time.Time{}, bytes.NewReader(versionsFile))
	})
	mux.HandleFunc("GET /names", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("---\nnokogiri\n"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func artifactBytes(file string) []byte {
	return append([]byte("\x00\x01binary:"+file+":"), bytes.Repeat([]byte{0xff, 0x00}, 64)...)
}

type fakeAdvisories map[string][]advisory.Advisory

func (f fakeAdvisories) Lookup(_ context.Context, _ ecosystem.Ecosystem, name string) ([]advisory.Advisory, error) {
	return f[name], nil
}

func newProxy(t *testing.T, gems map[string]fakeGem, advs fakeAdvisories) *httptest.Server {
	t.Helper()
	upstream := fakeRubyGems(t, gems)
	engine := policy.New(policy.Config{Cooldown: 7 * day}, advs)
	reg := rubygems.New(rubygems.Options{
		Upstream: upstream.URL,
		Engine:   engine,
		HTTP:     proxy.NewUpstream(upstream.Client(), "pkgwarden-test", time.Minute),
	})
	srv := httptest.NewServer(proxy.NewServer(engine, reg))
	t.Cleanup(srv.Close)
	return srv
}

func nokogiri(t *testing.T) fakeGem {
	t.Helper()
	info, err := os.ReadFile("testdata/info-nokogiri")
	if err != nil {
		t.Fatal(err)
	}
	return fakeGem{
		info:      info,
		downloads: 1_000_000,
		versions: []fakeVersion{
			{number: "1.16.0", platform: "x86_64-linux", age: 2 * day},
			{number: "1.16.0", age: 2 * day},
			{number: "1.15.0", platform: "x86_64-linux", age: 30 * day},
			{number: "1.15.0", age: 30*day + time.Hour},
		},
	}
}

type response struct {
	status int
	header http.Header
	body   []byte
}

func get(t *testing.T, method, url string, header map[string]string) response {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
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

func TestInfoHidesReleasesInsideCooldown(t *testing.T) {
	gem := nokogiri(t)
	srv := newProxy(t, map[string]fakeGem{"nokogiri": gem}, nil)
	lines := strings.SplitAfter(string(gem.info), "\n")
	want := lines[0] + lines[1] + lines[2]

	resp := get(t, "GET", srv.URL+"/rubygems/info/nokogiri", nil)
	if resp.status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.status, resp.body)
	}
	if string(resp.body) != want {
		t.Fatalf("filtered info:\n%s\nwant:\n%s", resp.body, want)
	}
	sum := sha256.Sum256(resp.body)
	if got, want := resp.header.Get("Repr-Digest"), "sha-256=:"+base64.StdEncoding.EncodeToString(sum[:])+":"; got != want {
		t.Errorf("Repr-Digest = %q, want %q for the filtered body", got, want)
	}
	if d := resp.header.Get("Digest"); d != "" {
		t.Errorf("upstream Digest %q relayed for a filtered body", d)
	}
	etag := resp.header.Get("ETag")
	if etag == "" || etag == `"upstream-etag"` {
		t.Errorf("ETag = %q, want one computed over the filtered body", etag)
	}

	ranged := get(t, "GET", srv.URL+"/rubygems/info/nokogiri", map[string]string{"Range": "bytes=10-"})
	if ranged.status != http.StatusOK || string(ranged.body) != want {
		t.Errorf("Range request: status %d body %q, want 200 with the full filtered body", ranged.status, ranged.body)
	}

	cached := get(t, "GET", srv.URL+"/rubygems/info/nokogiri", map[string]string{"If-None-Match": etag, "Range": "bytes=10-"})
	if cached.status != http.StatusNotModified {
		t.Errorf("If-None-Match with the served ETag: status %d, want 304", cached.status)
	}
	stale := get(t, "GET", srv.URL+"/rubygems/info/nokogiri", map[string]string{"If-None-Match": `"upstream-etag"`})
	if stale.status != http.StatusOK || string(stale.body) != want {
		t.Errorf("If-None-Match with upstream's ETag: status %d, want 200 with the filtered body", stale.status)
	}
}

func TestPackageWideAdvisoryHidesEveryVersion(t *testing.T) {
	advs := fakeAdvisories{"nokogiri": {{
		ID: "MAL-2026-1", Source: "openssf", Kind: advisory.Malicious, Ecosystem: ecosystem.RubyGems,
		Summary: "Malicious code in nokogiri (rubygems)",
	}}}
	srv := newProxy(t, map[string]fakeGem{"nokogiri": nokogiri(t)}, advs)
	block := map[string]string{"ecosystem": "rubygems", "stage": "metadata", "decision": "block"}
	malicious := map[string]string{"ecosystem": "rubygems", "stage": "metadata", "rule": "advisory/malicious", "decision": "block"}
	beforeBlock := telemetrytest.Value(t, "pkgwarden_decisions_total", block)
	beforeMalicious := telemetrytest.Value(t, "pkgwarden_findings_total", malicious)

	info := get(t, "GET", srv.URL+"/rubygems/info/nokogiri", nil)
	if d := telemetrytest.Value(t, "pkgwarden_decisions_total", block) - beforeBlock; d != 1 {
		t.Errorf("decisions_total%v grew by %v, want 1", block, d)
	}
	if d := telemetrytest.Value(t, "pkgwarden_findings_total", malicious) - beforeMalicious; d != 1 {
		t.Errorf("findings_total%v grew by %v, want 1", malicious, d)
	}
	if info.status != http.StatusOK || string(info.body) != "---\n" {
		t.Errorf("info: status %d body %q, want 200 with only the header", info.status, info.body)
	}
	if d := info.header.Get("X-Pkgwarden-Decision"); d != "block" {
		t.Errorf("X-Pkgwarden-Decision = %q, want block", d)
	}

	gem := get(t, "GET", srv.URL+"/rubygems/gems/nokogiri-1.15.0.gem", nil)
	if gem.status != http.StatusForbidden || !strings.Contains(string(gem.body), "MAL-2026-1") {
		t.Errorf("old release of a malicious package: status %d body %q, want 403 naming the advisory", gem.status, gem.body)
	}
}

func TestArtifactEnforcement(t *testing.T) {
	srv := newProxy(t, map[string]fakeGem{"nokogiri": nokogiri(t)}, nil)
	tests := []struct {
		path       string
		wantStatus int
		wantBody   string
	}{
		{"/gems/nokogiri-1.15.0.gem", http.StatusOK, string(artifactBytes("nokogiri-1.15.0.gem"))},
		{"/gems/nokogiri-1.15.0-x86_64-linux.gem", http.StatusOK, string(artifactBytes("nokogiri-1.15.0-x86_64-linux.gem"))},
		{"/gems/nokogiri-1.16.0.gem", http.StatusForbidden, "pkgwarden blocked rubygems/nokogiri@1.16.0: cooldown: published 2d ago, inside the 7d cooldown\n"},
		{"/gems/nokogiri-1.16.0-x86_64-linux.gem", http.StatusForbidden, "pkgwarden blocked rubygems/nokogiri@1.16.0: cooldown: published 2d ago, inside the 7d cooldown\n"},
		{"/downloads/nokogiri-1.15.0.gem", http.StatusOK, string(artifactBytes("nokogiri-1.15.0.gem"))},
		{"/downloads/nokogiri-1.16.0.gem", http.StatusForbidden, "pkgwarden blocked rubygems/nokogiri@1.16.0: cooldown: published 2d ago, inside the 7d cooldown\n"},
		{"/quick/Marshal.4.8/nokogiri-1.15.0.gemspec.rz", http.StatusOK, string(artifactBytes("nokogiri-1.15.0.gemspec.rz"))},
		{"/quick/Marshal.4.8/nokogiri-1.16.0.gemspec.rz", http.StatusForbidden, "pkgwarden blocked rubygems/nokogiri@1.16.0: cooldown: published 2d ago, inside the 7d cooldown\n"},
		{"/gems/nokogiri-9.9.9.gem", http.StatusNotFound, "not found\n"},
		{"/gems/left-pad-1.0.0.gem", http.StatusNotFound, "not found\n"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			before := telemetrytest.Value(t, "pkgwarden_artifacts_served_total", map[string]string{"ecosystem": "rubygems"})
			resp := get(t, "GET", srv.URL+"/rubygems"+tt.path, nil)
			served := telemetrytest.Value(t, "pkgwarden_artifacts_served_total", map[string]string{"ecosystem": "rubygems"}) - before
			gem := tt.wantStatus == http.StatusOK && strings.HasSuffix(tt.path, ".gem")
			want := 0.0
			if gem {
				want = 1
			}
			if served != want {
				t.Errorf("artifacts_served_total grew by %v, want %v", served, want)
			}
			if resp.status != tt.wantStatus || string(resp.body) != tt.wantBody {
				t.Errorf("status %d body %q, want %d %q", resp.status, resp.body, tt.wantStatus, tt.wantBody)
			}
		})
	}
}

func TestHeadOnGemDownloads(t *testing.T) {
	srv := newProxy(t, map[string]fakeGem{"nokogiri": nokogiri(t)}, nil)
	for _, dir := range []string{"/gems/", "/downloads/"} {
		blocked := get(t, "HEAD", srv.URL+"/rubygems"+dir+"nokogiri-1.16.0.gem", nil)
		if d := blocked.header.Get("X-Pkgwarden-Decision"); blocked.status != http.StatusForbidden || d != "block" {
			t.Errorf("HEAD %s of a release in cooldown: status %d decision %q, want 403 block", dir, blocked.status, d)
		}
		if allowed := get(t, "HEAD", srv.URL+"/rubygems"+dir+"nokogiri-1.15.0.gem", nil); allowed.status != http.StatusOK {
			t.Errorf("HEAD %s of an allowed release: status %d, want 200", dir, allowed.status)
		}
	}
}

func TestUnroutedPathsUnderFilteredPrefixes(t *testing.T) {
	upstream, err := url.Parse(fakeRubyGems(t, map[string]fakeGem{"nokogiri": nokogiri(t)}).URL)
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int64
	relay := httputil.NewSingleHostReverseProxy(upstream)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		relay.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	engine := policy.New(policy.Config{Cooldown: 7 * day}, nil)
	reg := rubygems.New(rubygems.Options{
		Upstream: front.URL,
		Engine:   engine,
		HTTP:     proxy.NewUpstream(front.Client(), "pkgwarden-test", time.Minute),
	})
	srv := httptest.NewServer(proxy.NewServer(engine, reg))
	t.Cleanup(srv.Close)

	for _, path := range []string{
		"/info/nokogiri/",
		"/info/nokogiri/x",
		"/gems/nokogiri-1.15.0.gem/",
		"/downloads/nokogiri-1.15.0.gem/",
		"/quick/Marshal.4.8/nokogiri-1.15.0.gemspec.rz/",
	} {
		before := hits.Load()
		resp := get(t, "GET", srv.URL+"/rubygems"+path, nil)
		if n := hits.Load() - before; resp.status != http.StatusNotFound || n != 0 {
			t.Errorf("%s: status %d after %d upstream requests, want 404 after none", path, resp.status, n)
		}
	}
	for _, path := range []string{"/versions", "/names"} {
		before := hits.Load()
		resp := get(t, "GET", srv.URL+"/rubygems"+path, nil)
		if n := hits.Load() - before; resp.status != http.StatusOK || n != 1 {
			t.Errorf("%s: status %d after %d upstream requests, want 200 relayed in one", path, resp.status, n)
		}
	}
}

func TestHeadOnAGemCountsNothing(t *testing.T) {
	srv := newProxy(t, map[string]fakeGem{"nokogiri": nokogiri(t)}, nil)
	labels := map[string]string{"ecosystem": "rubygems"}
	before := telemetrytest.Value(t, "pkgwarden_artifacts_served_total", labels)

	allowed := get(t, "HEAD", srv.URL+"/rubygems/gems/nokogiri-1.15.0.gem", nil)
	blocked := get(t, "HEAD", srv.URL+"/rubygems/gems/nokogiri-1.16.0.gem", nil)
	srv.Close()

	if want := strconv.Itoa(len(artifactBytes("nokogiri-1.15.0.gem"))); allowed.status != http.StatusOK || allowed.header.Get("Content-Length") != want {
		t.Errorf("HEAD: status %d Content-Length %q, want 200 and %s", allowed.status, allowed.header.Get("Content-Length"), want)
	}
	if blocked.status != http.StatusForbidden {
		t.Errorf("HEAD on a release inside the cooldown: status %d, want 403", blocked.status)
	}
	if d := telemetrytest.Value(t, "pkgwarden_artifacts_served_total", labels) - before; d != 0 {
		t.Errorf("artifacts_served_total grew by %v over two HEADs, want 0", d)
	}
}

func TestGemFileNames(t *testing.T) {
	gem := func(age time.Duration, versions ...fakeVersion) fakeGem {
		for i := range versions {
			versions[i].age = age
		}
		return fakeGem{downloads: 10, versions: versions}
	}
	srv := newProxy(t, map[string]fakeGem{
		"nokogiri":       gem(day, fakeVersion{number: "1.16.0"}, fakeVersion{number: "1.16.0", platform: "x86_64-linux"}),
		"aws-sdk-s3":     gem(day, fakeVersion{number: "1.2.3"}),
		"aws-sdk":        gem(day, fakeVersion{number: "3.0.0"}),
		"net-http":       gem(day, fakeVersion{number: "0.4.1"}),
		"ruby2_keywords": gem(day, fakeVersion{number: "0.0.5"}),
		"sass-embedded":  gem(day, fakeVersion{number: "1.77.0", platform: "arm64-darwin"}),
		"foo":            gem(90*day, fakeVersion{number: "1"}),
		"foo-1-java":     gem(day, fakeVersion{number: "2.0"}),
	}, nil)
	tests := []struct{ file, subject string }{
		{"nokogiri-1.16.0-x86_64-linux.gem", "rubygems/nokogiri@1.16.0"},
		{"aws-sdk-s3-1.2.3.gem", "rubygems/aws-sdk-s3@1.2.3"},
		{"net-http-0.4.1.gem", "rubygems/net-http@0.4.1"},
		{"ruby2_keywords-0.0.5.gem", "rubygems/ruby2_keywords@0.0.5"},
		{"sass-embedded-1.77.0-arm64-darwin.gem", "rubygems/sass-embedded@1.77.0"},
		{"foo-1-java-2.0.gem", "rubygems/foo-1-java@2.0"},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			resp := get(t, "GET", srv.URL+"/rubygems/gems/"+tt.file, nil)
			if resp.status != http.StatusForbidden || !strings.HasPrefix(string(resp.body), "pkgwarden blocked "+tt.subject+": cooldown") {
				t.Errorf("status %d body %q, want a cooldown 403 for %s", resp.status, resp.body, tt.subject)
			}
		})
	}
	for _, file := range []string{"nonsense.gem", "sass-embedded-1.77.0.gem", "nokogiri-1.16.0-java.gem"} {
		if resp := get(t, "GET", srv.URL+"/rubygems/gems/"+file, nil); resp.status != http.StatusNotFound {
			t.Errorf("%s matches no uploaded file: status %d, want 404", file, resp.status)
		}
	}
}

func TestVersionsPassThrough(t *testing.T) {
	srv := newProxy(t, map[string]fakeGem{}, nil)
	full := get(t, "GET", srv.URL+"/rubygems/versions", nil)
	if full.status != http.StatusOK {
		t.Fatalf("status %d", full.status)
	}

	ranged := get(t, "GET", srv.URL+"/rubygems/versions", map[string]string{"Range": "bytes=10-29"})
	if ranged.status != http.StatusPartialContent {
		t.Fatalf("Range: status %d, want 206", ranged.status)
	}
	if !bytes.Equal(ranged.body, full.body[10:30]) {
		t.Errorf("Range body %q, want %q", ranged.body, full.body[10:30])
	}
	if cr := ranged.header.Get("Content-Range"); cr != "bytes 10-29/"+strconv.Itoa(len(full.body)) {
		t.Errorf("Content-Range = %q", cr)
	}

	notModified := get(t, "GET", srv.URL+"/rubygems/versions", map[string]string{"If-None-Match": `"versions-etag"`})
	if notModified.status != http.StatusNotModified {
		t.Errorf("If-None-Match: status %d, want 304", notModified.status)
	}

	head := get(t, "HEAD", srv.URL+"/rubygems/versions", nil)
	if head.status != http.StatusOK || head.header.Get("ETag") != `"versions-etag"` {
		t.Errorf("HEAD: status %d ETag %q, want 200 with upstream's ETag", head.status, head.header.Get("ETag"))
	}
}

func TestPackage(t *testing.T) {
	gems := map[string]fakeGem{
		"nokogiri": nokogiri(t),
		"quiet":    {downloads: -1, versions: []fakeVersion{{number: "0.1.0", age: 3 * day}}},
	}
	upstream := fakeRubyGems(t, gems)
	reg := rubygems.New(rubygems.Options{
		Upstream: upstream.URL,
		Engine:   policy.New(policy.Config{}, fakeAdvisories{}),
		HTTP:     proxy.NewUpstream(upstream.Client(), "pkgwarden-test", time.Minute),
	})
	ctx := context.Background()

	pkg, err := reg.Package(ctx, "nokogiri")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkg.Releases) != 2 {
		t.Fatalf("releases %+v, want one per version number", pkg.Releases)
	}
	published := map[string]time.Time{}
	for _, r := range pkg.Releases {
		published[r.Version] = r.Published
		if r.Publishers != nil {
			t.Errorf("%s publishers %v, want nil", r.Version, r.Publishers)
		}
	}
	if age := time.Since(published["1.15.0"]); age < 30*day+time.Hour-time.Minute || age > 30*day+time.Hour+time.Minute {
		t.Errorf("1.15.0 published %s ago, want the earliest platform upload (30d1h)", age)
	}
	if !pkg.Created.Equal(published["1.15.0"]) {
		t.Errorf("Created %s, want the earliest upload %s", pkg.Created, published["1.15.0"])
	}
	if want := int64(1_000_000 / 4); pkg.WeeklyDownloads != want {
		t.Errorf("WeeklyDownloads %d, want %d (all-time downloads over 4 weeks)", pkg.WeeklyDownloads, want)
	}

	quiet, err := reg.Package(ctx, "quiet")
	if err != nil {
		t.Fatal(err)
	}
	if quiet.WeeklyDownloads != policy.UnknownDownloads {
		t.Errorf("WeeklyDownloads %d when the gem API fails, want UnknownDownloads", quiet.WeeklyDownloads)
	}

	if _, err := reg.Package(ctx, "missing"); !errors.Is(err, proxy.ErrNotFound) {
		t.Errorf("missing package: err %v, want ErrNotFound", err)
	}
}

func TestPackageWhenGemAPIHangs(t *testing.T) {
	upstream, err := url.Parse(fakeRubyGems(t, map[string]fakeGem{"nokogiri": nokogiri(t)}).URL)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	mux := http.NewServeMux()
	mux.Handle("/", httputil.NewSingleHostReverseProxy(upstream))
	mux.HandleFunc("GET /api/v1/gems/{file}", func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	front := httptest.NewServer(mux)
	t.Cleanup(front.Close)
	t.Cleanup(func() { close(release) })
	reg := rubygems.New(rubygems.Options{
		Upstream: front.URL,
		Engine:   policy.New(policy.Config{Cooldown: 7 * day}, nil),
		HTTP:     proxy.NewUpstream(front.Client(), "pkgwarden-test", time.Minute),
	})

	start := time.Now()
	pkg, err := reg.Package(context.Background(), "nokogiri")
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("Package took %v, want the gem API lookup cut short", elapsed)
	}
	if pkg.WeeklyDownloads != policy.UnknownDownloads || len(pkg.Releases) != 2 {
		t.Errorf("downloads %d with releases %+v, want UnknownDownloads and two releases", pkg.WeeklyDownloads, pkg.Releases)
	}
}
