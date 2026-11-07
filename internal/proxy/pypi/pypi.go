// Package pypi proxies the Python package index: the simple repository API
// (PEP 503 and PEP 691) that pip and uv resolve against, and the
// distribution files it links to.
package pypi

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/pogao/pkgwarden/internal/ecosystem"
	"github.com/pogao/pkgwarden/internal/policy"
	"github.com/pogao/pkgwarden/internal/proxy"
)

// statsTimeout bounds the download-count lookup, which only feeds
// heuristics and must not stall an install when pypistats is slow.
const statsTimeout = 5 * time.Second

// Options configures a Registry. Engine and HTTP are required.
type Options struct {
	// PyPI is the base URL of the index serving /pypi/<project>/json and
	// /simple/. Defaults to https://pypi.org.
	PyPI string
	// Files is the base URL distribution files must live under. Defaults
	// to https://files.pythonhosted.org.
	Files string
	// Stats is the base URL of the pypistats API. Defaults to https://pypistats.org.
	Stats string
	// PublicURL is the externally visible proxy URL; see proxy.BaseURL.
	PublicURL string
	Engine    *policy.Engine
	HTTP      *proxy.Upstream
}

// Registry serves the PyPI protocol relative to its /pypi mount point.
type Registry struct {
	o   Options
	mux *http.ServeMux
}

// New returns a Registry, filling in the public PyPI hosts for empty URLs.
func New(o Options) *Registry {
	o.PyPI = baseURL(o.PyPI, "https://pypi.org")
	o.Files = baseURL(o.Files, "https://files.pythonhosted.org")
	o.Stats = baseURL(o.Stats, "https://pypistats.org")
	r := &Registry{o: o, mux: http.NewServeMux()}
	r.mux.HandleFunc("GET /simple/{$}", r.root)
	r.mux.HandleFunc("GET /simple/{project}", r.simple)
	r.mux.HandleFunc("GET /simple/{project}/{$}", r.simple)
	r.mux.HandleFunc("GET /files/{project}/{version}/{filename}", r.file)
	return r
}

func baseURL(s, def string) string {
	if s == "" {
		return def
	}
	return strings.TrimSuffix(s, "/")
}

// ServeHTTP implements http.Handler.
func (r *Registry) ServeHTTP(w http.ResponseWriter, req *http.Request) { r.mux.ServeHTTP(w, req) }

// Ecosystem implements proxy.Registry.
func (r *Registry) Ecosystem() ecosystem.Ecosystem { return ecosystem.PyPI }

// Package implements proxy.Registry. PyPI records no publisher per release,
// so every Release has nil Publishers.
func (r *Registry) Package(ctx context.Context, name string) (*policy.Package, error) {
	p, err := r.project(ctx, name)
	if err != nil {
		return nil, err
	}
	return r.describe(ctx, p), nil
}

// project is a PyPI project as the JSON API reports it.
type project struct {
	// name is the PEP 503 normalized name.
	name string
	// releases maps each version that has at least one file to its files.
	releases map[string][]file
}

// file is one distribution file in the JSON API's releases map.
type file struct {
	Filename string `json:"filename"`
	URL      string `json:"url"`
	Digests  struct {
		SHA256 string `json:"sha256"`
	} `json:"digests"`
	RequiresPython string       `json:"requires_python"`
	Yanked         bool         `json:"yanked"`
	YankedReason   string       `json:"yanked_reason"`
	UploadTime     time.Time    `json:"upload_time_iso_8601"`
	Size           int64        `json:"size"`
	CoreMetadata   metadataHash `json:"core-metadata"`
}

// metadataHash is the sha256 of a file's PEP 658 metadata file, empty when
// upstream has none. The JSON API spells "none" as false.
type metadataHash string

func (m *metadataHash) UnmarshalJSON(b []byte) error {
	var v struct {
		SHA256 string `json:"sha256"`
	}
	if json.Unmarshal(b, &v) == nil {
		*m = metadataHash(v.SHA256)
	}
	return nil
}

func (r *Registry) project(ctx context.Context, name string) (*project, error) {
	name = ecosystem.PyPI.Normalize(name)
	var doc struct {
		Releases map[string][]file `json:"releases"`
	}
	if err := r.o.HTTP.FetchJSON(ctx, r.o.PyPI+"/pypi/"+url.PathEscape(name)+"/json", &doc); err != nil {
		return nil, err
	}
	p := &project{name: name, releases: make(map[string][]file, len(doc.Releases))}
	for v, fs := range doc.Releases {
		if len(fs) > 0 {
			p.releases[v] = fs
		}
	}
	return p, nil
}

// describe translates p for the policy engine. Releases come out oldest first.
func (r *Registry) describe(ctx context.Context, p *project) *policy.Package {
	pkg := &policy.Package{Ecosystem: ecosystem.PyPI, Name: p.name, WeeklyDownloads: r.weeklyDownloads(ctx, p.name)}
	for v, fs := range p.releases {
		rel := policy.Release{Version: v}
		for _, f := range fs {
			if !f.UploadTime.IsZero() && (rel.Published.IsZero() || f.UploadTime.Before(rel.Published)) {
				rel.Published = f.UploadTime
			}
		}
		if !rel.Published.IsZero() && (pkg.Created.IsZero() || rel.Published.Before(pkg.Created)) {
			pkg.Created = rel.Published
		}
		pkg.Releases = append(pkg.Releases, rel)
	}
	slices.SortFunc(pkg.Releases, func(a, b policy.Release) int {
		return cmp.Or(a.Published.Compare(b.Published), strings.Compare(a.Version, b.Version))
	})
	return pkg
}

func (r *Registry) weeklyDownloads(ctx context.Context, name string) int64 {
	ctx, cancel := context.WithTimeout(ctx, statsTimeout)
	defer cancel()
	var doc struct {
		Data struct {
			LastWeek *int64 `json:"last_week"`
		} `json:"data"`
	}
	err := r.o.HTTP.FetchJSON(ctx, r.o.Stats+"/api/packages/"+url.PathEscape(name)+"/recent", &doc)
	if err != nil || doc.Data.LastWeek == nil {
		slog.DebugContext(ctx, "pypi download count unavailable", "project", name, "err", err)
		return policy.UnknownDownloads
	}
	return *doc.Data.LastWeek
}

func (r *Registry) root(w http.ResponseWriter, req *http.Request) {
	if resp, ok := open(w, req, r.o.HTTP, r.o.PyPI+"/simple/", "Accept"); ok {
		defer resp.Body.Close()
		proxy.Relay(w, resp)
	}
}

func (r *Registry) simple(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	requested := req.PathValue("project")
	name := ecosystem.PyPI.Normalize(requested)
	if requested != name || !strings.HasSuffix(req.URL.Path, "/") {
		http.Redirect(w, req, r.base(req)+"/pypi/simple/"+url.PathEscape(name)+"/", http.StatusMovedPermanently)
		return
	}
	p, err := r.project(ctx, name)
	if err != nil {
		proxy.WriteError(w, err)
		return
	}
	pkg := r.describe(ctx, p)
	a := r.o.Engine.Assess(ctx, pkg)
	if !proxy.Enforce(ctx, w, proxy.Text, proxy.StageMetadata, proxy.Subject{Ecosystem: ecosystem.PyPI, Name: name}, a.Package) {
		return
	}
	page := index{name: name}
	for _, rel := range pkg.Releases {
		if !a.Allowed(rel.Version) {
			continue
		}
		page.versions = append(page.versions, rel.Version)
		for _, f := range p.releases[rel.Version] {
			href := r.base(req) + "/pypi/files/" + url.PathEscape(name) + "/" + url.PathEscape(rel.Version) + "/" + url.PathEscape(f.Filename)
			page.links = append(page.links, link{file: f, href: href})
		}
	}
	ct := negotiate(req.Header.Get("Accept"))
	w.Header().Set("Content-Type", ct)
	w.Header().Add("Vary", "Accept")
	if ct == jsonType {
		page.writeJSON(w)
		return
	}
	page.writeHTML(w)
}

// file serves a distribution file, or its PEP 658 metadata, from the
// upstream URL recorded in the project's metadata. The client's path only
// selects among those URLs.
func (r *Registry) file(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	version, filename := req.PathValue("version"), req.PathValue("filename")
	p, err := r.project(ctx, req.PathValue("project"))
	if err != nil {
		proxy.WriteError(w, err)
		return
	}
	s := proxy.Subject{Ecosystem: ecosystem.PyPI, Name: p.name, Version: version}
	a := r.o.Engine.Assess(ctx, r.describe(ctx, p))
	if !proxy.Enforce(ctx, w, proxy.Text, proxy.StageArtifact, s, a.Release(version)) {
		return
	}
	src, metadata, ok := p.source(version, filename)
	if !ok {
		http.NotFound(w, req)
		return
	}
	if !strings.HasPrefix(src, r.o.Files+"/") {
		proxy.WriteError(w, fmt.Errorf("%s: file URL %s is not under %s", filename, src, r.o.Files))
		return
	}
	resp, ok := open(w, req, r.o.HTTP, src, "Range")
	if !ok {
		return
	}
	defer resp.Body.Close()
	if metadata {
		proxy.Relay(w, resp)
		return
	}
	proxy.ServeArtifact(ctx, w, s, resp)
}

// source returns the upstream URL of a distribution file, or of its PEP 658
// metadata file when metadata is true.
func (p *project) source(version, filename string) (src string, metadata, ok bool) {
	for _, f := range p.releases[version] {
		switch {
		case f.Filename == filename:
			return f.URL, false, true
		case f.CoreMetadata != "" && f.Filename+".metadata" == filename:
			return f.URL + ".metadata", true, true
		}
	}
	return "", false, false
}

func (r *Registry) base(req *http.Request) string { return proxy.BaseURL(req, r.o.PublicURL) }

// open issues an upstream GET, forwarding the named request headers. It
// returns the response when upstream answered 200 or 206; otherwise it has
// written an error response and returns false.
func open(w http.ResponseWriter, req *http.Request, up *proxy.Upstream, src string, forward ...string) (*http.Response, bool) {
	h := http.Header{}
	for _, k := range forward {
		if v := req.Header.Get(k); v != "" {
			h.Set(k, v)
		}
	}
	resp, err := up.Open(req.Context(), src, h)
	if err != nil {
		proxy.WriteError(w, err)
		return nil, false
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusPartialContent:
		return resp, true
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		proxy.WriteError(w, fmt.Errorf("GET %s: %w", src, proxy.ErrNotFound))
	} else {
		proxy.WriteError(w, &proxy.StatusError{URL: src, Status: resp.StatusCode})
	}
	return nil, false
}
