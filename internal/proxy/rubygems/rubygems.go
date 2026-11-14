// Package rubygems proxies a RubyGems registry for Bundler and the gem
// command, hiding releases the policy blocks from the compact index and
// refusing their downloads.
package rubygems

import (
	"bytes"
	"cmp"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/pogao/pkgwarden/internal/ecosystem"
	"github.com/pogao/pkgwarden/internal/policy"
	"github.com/pogao/pkgwarden/internal/proxy"
)

// Options configures a Registry.
type Options struct {
	// Upstream is the registry base URL. Defaults to https://rubygems.org.
	Upstream string
	// PublicURL is accepted for symmetry with the other adapters. The
	// RubyGems protocols carry no absolute URLs, so nothing is rewritten.
	PublicURL string
	// Engine decides which releases are served. Required.
	Engine *policy.Engine
	// HTTP fetches from Upstream. Defaults to an Upstream over http.DefaultClient.
	HTTP *proxy.Upstream
}

// Registry serves the RubyGems compact index and gem downloads relative to
// its mount point.
type Registry struct {
	upstream string
	engine   *policy.Engine
	http     *proxy.Upstream
	mux      *http.ServeMux
}

// New returns a Registry for o.
func New(o Options) *Registry {
	r := &Registry{
		upstream: strings.TrimSuffix(o.Upstream, "/"),
		engine:   o.Engine,
		http:     o.HTTP,
		mux:      http.NewServeMux(),
	}
	if r.upstream == "" {
		r.upstream = "https://rubygems.org"
	}
	if r.http == nil {
		r.http = proxy.NewUpstream(http.DefaultClient, "pkgwarden", time.Minute)
	}
	r.mux.HandleFunc("GET /info/{name}", r.serveInfo)
	r.mux.HandleFunc("GET /gems/{file}", r.serveArtifact(".gem", true))
	r.mux.HandleFunc("GET /downloads/{file}", r.serveArtifact(".gem", true))
	r.mux.HandleFunc("GET /quick/Marshal.4.8/{file}", r.serveArtifact(".gemspec.rz", false))
	// rubygems.org answers spellings these routes miss, such as /info/<gem>/,
	// with unfiltered content, so the rest of each filtered prefix gets 404.
	r.mux.HandleFunc("GET /", func(w http.ResponseWriter, req *http.Request) {
		for _, prefix := range []string{"/info/", "/gems/", "/downloads/", "/quick/"} {
			if strings.HasPrefix(req.URL.Path, prefix) {
				http.NotFound(w, req)
				return
			}
		}
		r.relay(w, req, r.upstream+req.URL.EscapedPath())
	})
	return r
}

// Ecosystem reports rubygems.
func (r *Registry) Ecosystem() ecosystem.Ecosystem { return ecosystem.RubyGems }

func (r *Registry) ServeHTTP(w http.ResponseWriter, req *http.Request) { r.mux.ServeHTTP(w, req) }

type versionEntry struct {
	Number    string    `json:"number"`
	Platform  string    `json:"platform"`
	CreatedAt time.Time `json:"created_at"`
}

// versions lists every uploaded file of name, one entry per version and
// platform.
func (r *Registry) versions(ctx context.Context, name string) ([]versionEntry, error) {
	var entries []versionEntry
	if err := r.http.FetchJSON(ctx, r.upstream+"/api/v1/versions/"+url.PathEscape(name)+".json", &entries); err != nil {
		return nil, fmt.Errorf("rubygems package %s: %w", name, err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("rubygems package %s has no versions: %w", name, proxy.ErrNotFound)
	}
	return entries, nil
}

// Package describes name from the versions and gem APIs. RubyGems names no
// pusher per release in these endpoints, so Publishers stays nil.
func (r *Registry) Package(ctx context.Context, name string) (*policy.Package, error) {
	var entries []versionEntry
	var gem struct {
		Downloads int64 `json:"downloads"`
	}
	var downloadsErr error
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() (err error) {
		entries, err = r.versions(gctx, name)
		return err
	})
	g.Go(func() error {
		ctx, cancel := context.WithTimeout(gctx, proxy.DownloadsTimeout)
		defer cancel()
		downloadsErr = r.http.FetchJSON(ctx, r.upstream+"/api/v1/gems/"+url.PathEscape(name)+".json", &gem)
		return nil
	})
	if err := g.Wait(); err != nil {
		return nil, err
	}

	pkg := &policy.Package{Ecosystem: ecosystem.RubyGems, Name: name, WeeklyDownloads: policy.UnknownDownloads}
	index := make(map[string]int, len(entries))
	for _, e := range entries {
		if pkg.Created.IsZero() || e.CreatedAt.Before(pkg.Created) {
			pkg.Created = e.CreatedAt
		}
		i, seen := index[e.Number]
		if !seen {
			index[e.Number] = len(pkg.Releases)
			pkg.Releases = append(pkg.Releases, policy.Release{Version: e.Number, Published: e.CreatedAt})
			continue
		}
		if e.CreatedAt.Before(pkg.Releases[i].Published) {
			pkg.Releases[i].Published = e.CreatedAt
		}
	}
	if downloadsErr == nil {
		weeks := int64(time.Since(pkg.Created) / (7 * 24 * time.Hour))
		pkg.WeeklyDownloads = gem.Downloads / max(1, weeks)
	}
	return pkg, nil
}

// serveInfo answers /info/<gem> with the upstream file minus the lines of
// blocked versions. The body no longer matches upstream, so upstream's ETag
// and digests are replaced with ones computed over the filtered body, and a
// Range request gets the whole file. When the package itself is blocked,
// every version line goes and the client sees a gem with no versions, rather
// than a 403 that makes Bundler abandon the compact index for the whole
// source and resolve from the unfiltered full index.
func (r *Registry) serveInfo(w http.ResponseWriter, req *http.Request) {
	name := req.PathValue("name")
	var body []byte
	var pkg *policy.Package
	g, gctx := errgroup.WithContext(req.Context())
	g.Go(func() (err error) {
		body, err = r.http.Fetch(gctx, r.upstream+"/info/"+url.PathEscape(name), nil)
		return err
	})
	g.Go(func() (err error) {
		pkg, err = r.Package(gctx, name)
		return err
	})
	if err := g.Wait(); err != nil {
		proxy.WriteError(w, err)
		return
	}
	ctx := req.Context()
	a := r.engine.Assess(ctx, pkg)
	s := proxy.Subject{Ecosystem: ecosystem.RubyGems, Name: name}
	if a.Package.Decision == policy.Block {
		rules := proxy.RecordVerdict(w, proxy.StageMetadata, s, a.Package)
		slog.InfoContext(ctx, "hiding every version", "ecosystem", string(s.Ecosystem), "package", name,
			"stage", string(proxy.StageMetadata), "rules", rules, "findings", a.Package.Findings)
	} else {
		proxy.Enforce(ctx, w, proxy.Text, proxy.StageMetadata, s, a.Package)
	}
	writeInfo(w, req, filterInfo(body, a.Allowed))
}

// filterInfo keeps the "---" header and every line whose version is
// allowed, byte for byte. A line reads "VERSION[-PLATFORM] DEPS|REQS";
// anything without a recognisable allowed version is dropped.
func filterInfo(body []byte, allowed func(version string) bool) []byte {
	var out bytes.Buffer
	for line := range bytes.Lines(body) {
		text := bytes.TrimSuffix(line, []byte("\n"))
		if string(text) == "---" {
			out.Write(line)
			continue
		}
		head, _, _ := bytes.Cut(text, []byte(" "))
		version, _, _ := bytes.Cut(head, []byte("-"))
		if allowed(string(version)) {
			out.Write(line)
		}
	}
	return out.Bytes()
}

func writeInfo(w http.ResponseWriter, req *http.Request, body []byte) {
	sum := md5.Sum(body)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	digest := sha256.Sum256(body)
	h := w.Header()
	h.Set("ETag", etag)
	h.Set("Repr-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(digest[:])+":")
	h.Set("Content-Type", "text/plain; charset=utf-8")
	if etagMatches(req.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.Write(body)
}

func etagMatches(ifNoneMatch, etag string) bool {
	for tag := range strings.SplitSeq(ifNoneMatch, ",") {
		tag = strings.TrimPrefix(strings.TrimSpace(tag), "W/")
		if tag == etag || tag == "*" {
			return true
		}
	}
	return false
}

// serveArtifact enforces the policy on a file named
// <name>-<version>[-<platform>]<suffix> before streaming it from upstream.
// Any other file name gets 404. A package file (a .gem, not a gemspec)
// counts in the artifact metrics.
func (r *Registry) serveArtifact(suffix string, packageFile bool) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		target := r.upstream + req.URL.EscapedPath()
		base, ok := strings.CutSuffix(req.PathValue("file"), suffix)
		if !ok {
			http.NotFound(w, req)
			return
		}
		pkg, version, err := r.resolve(ctx, base)
		if err != nil {
			proxy.WriteError(w, err)
			return
		}
		s := proxy.Subject{Ecosystem: ecosystem.RubyGems, Name: pkg.Name, Version: version}
		v := r.engine.Assess(ctx, pkg).Release(version)
		if !proxy.Enforce(ctx, w, proxy.Text, proxy.StageArtifact, s, v) {
			return
		}
		if !packageFile {
			r.relay(w, req, target)
			return
		}
		resp, err := r.open(req, target)
		if err != nil {
			proxy.WriteError(w, err)
			return
		}
		defer resp.Body.Close()
		proxy.ServeArtifact(w, req, s, resp)
	}
}

// resolve finds the package and version a file name refers to. Names may
// contain "-" followed by digits, so a name like foo-1-java-2.0 reads as
// several splits. Only a split matching an uploaded version and platform
// exactly counts: judging foo-1-java-2.0.gem as foo 1 would let a young
// gem named foo-1-java ride on an old release of foo.
func (r *Registry) resolve(ctx context.Context, base string) (*policy.Package, string, error) {
	for _, c := range parseFileName(base) {
		entries, err := r.versions(ctx, c.name)
		if errors.Is(err, proxy.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		if slices.ContainsFunc(entries, func(e versionEntry) bool { return e.Number == c.version && e.Platform == c.platform }) {
			pkg, err := r.Package(ctx, c.name)
			return pkg, c.version, err
		}
	}
	return nil, "", fmt.Errorf("rubygems file %s matches no uploaded release: %w", base, proxy.ErrNotFound)
}

type fileName struct {
	name, version, platform string
}

var versionPattern = regexp.MustCompile(`^[0-9]+(\.[0-9A-Za-z]+)*$`)

// parseFileName lists every reading of base as
// <name>-<version>[-<platform>], shortest name first. A file without a
// platform suffix is the "ruby" platform.
func parseFileName(base string) []fileName {
	var out []fileName
	for i := 1; i < len(base)-1; i++ {
		if base[i] != '-' || base[i+1] < '0' || base[i+1] > '9' {
			continue
		}
		version, platform, _ := strings.Cut(base[i+1:], "-")
		if versionPattern.MatchString(version) {
			out = append(out, fileName{name: base[:i], version: version, platform: cmp.Or(platform, "ruby")})
		}
	}
	return out
}

var forwardHeaders = []string{"Range", "If-None-Match", "If-Modified-Since", "Accept-Encoding"}

// relay streams target to w unchanged.
func (r *Registry) relay(w http.ResponseWriter, req *http.Request, target string) {
	resp, err := r.open(req, target)
	if err != nil {
		proxy.WriteError(w, err)
		return
	}
	defer resp.Body.Close()
	proxy.Relay(w, req, resp)
}

// open issues the upstream GET for target, carrying the client's query and
// its conditional and range headers so 206 and 304 answers pass through.
func (r *Registry) open(req *http.Request, target string) (*http.Response, error) {
	if req.URL.RawQuery != "" {
		target += "?" + req.URL.RawQuery
	}
	h := http.Header{}
	for _, k := range forwardHeaders {
		if v := req.Header.Values(k); len(v) > 0 {
			h[k] = v
		}
	}
	return r.http.Open(req.Context(), target, h)
}
