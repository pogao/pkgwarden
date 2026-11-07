// Package cargo proxies the crates.io sparse index and crate downloads.
//
// Cargo resolves a dependency name by requesting index files for several
// spellings that differ only in "-" versus "_"; upstream answers 404 for
// every spelling but the published one, and so does this proxy. Index paths
// must be the lowercase form cargo derives. Crate metadata and downloads
// look the crate up through the crates.io API, which matches names
// case-insensitively and across "-" and "_", and then use the canonical
// name it returns.
package cargo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/pogao/pkgwarden/internal/ecosystem"
	"github.com/pogao/pkgwarden/internal/policy"
	"github.com/pogao/pkgwarden/internal/proxy"
)

// Options configures a Registry. Engine and HTTP are required.
type Options struct {
	// Index is the sparse index base URL. Defaults to https://index.crates.io.
	Index string
	// API is the crates.io web API base URL. Defaults to https://crates.io.
	API string
	// Download is the base URL crate files live under as
	// <Download>/<crate>/<crate>-<version>.crate. Defaults to
	// https://static.crates.io/crates.
	Download string
	// PublicURL is the externally visible proxy URL; see proxy.BaseURL.
	PublicURL string
	Engine    *policy.Engine
	HTTP      *proxy.Upstream
}

// Registry serves the cargo sparse registry protocol relative to its
// /cargo mount point.
type Registry struct {
	o   Options
	mux *http.ServeMux
}

// New returns a Registry, filling in the crates.io hosts for empty URLs.
func New(o Options) *Registry {
	o.Index = baseURL(o.Index, "https://index.crates.io")
	o.API = baseURL(o.API, "https://crates.io")
	o.Download = baseURL(o.Download, "https://static.crates.io/crates")
	r := &Registry{o: o, mux: http.NewServeMux()}
	r.mux.HandleFunc("GET /index/config.json", r.config)
	r.mux.HandleFunc("GET /index/{path...}", r.index)
	r.mux.HandleFunc("GET /api/v1/crates/{crate}/{version}/download", r.download)
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
func (r *Registry) Ecosystem() ecosystem.Ecosystem { return ecosystem.Cargo }

// Package implements proxy.Registry. The returned Name is the crate's
// canonical name, which may differ from name in case or separators.
func (r *Registry) Package(ctx context.Context, name string) (*policy.Package, error) {
	var doc struct {
		Crate struct {
			Name      string    `json:"name"`
			CreatedAt time.Time `json:"created_at"`
			// RecentDownloads counts the last 90 days.
			RecentDownloads *int64 `json:"recent_downloads"`
		} `json:"crate"`
		Versions []struct {
			Num         string    `json:"num"`
			CreatedAt   time.Time `json:"created_at"`
			PublishedBy *struct {
				Login string `json:"login"`
			} `json:"published_by"`
		} `json:"versions"`
	}
	src := r.o.API + "/api/v1/crates/" + url.PathEscape(name)
	if err := r.o.HTTP.FetchJSON(ctx, src, &doc); err != nil {
		return nil, err
	}
	if doc.Crate.Name == "" {
		return nil, fmt.Errorf("decode %s: crate name missing", src)
	}
	pkg := &policy.Package{
		Ecosystem:       ecosystem.Cargo,
		Name:            doc.Crate.Name,
		Created:         doc.Crate.CreatedAt,
		WeeklyDownloads: policy.UnknownDownloads,
	}
	if d := doc.Crate.RecentDownloads; d != nil {
		pkg.WeeklyDownloads = *d / 13
	}
	for _, v := range doc.Versions {
		rel := policy.Release{Version: v.Num, Published: v.CreatedAt}
		if v.PublishedBy != nil && v.PublishedBy.Login != "" {
			rel.Publishers = []string{v.PublishedBy.Login}
		}
		pkg.Releases = append(pkg.Releases, rel)
	}
	return pkg, nil
}

func (r *Registry) config(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		DL  string `json:"dl"`
		API string `json:"api"`
	}{proxy.BaseURL(req, r.o.PublicURL) + "/cargo/api/v1/crates", r.o.API})
}

func (r *Registry) index(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	p := req.PathValue("path")
	name, ok := indexName(p)
	if !ok {
		http.NotFound(w, req)
		return
	}
	body, err := r.o.HTTP.Fetch(ctx, r.o.Index+"/"+p, nil)
	if err != nil {
		proxy.WriteError(w, err)
		return
	}
	pkg, err := r.Package(ctx, name)
	if err != nil {
		proxy.WriteError(w, err)
		return
	}
	a := r.o.Engine.Assess(ctx, pkg)
	if !proxy.Enforce(w, proxy.Text, "cargo/"+pkg.Name, a.Package) {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(filterIndex(body, a))
}

// indexName returns the crate name a sparse index path ends in, and whether
// the directories before it are the ones cargo derives from that name.
func indexName(p string) (string, bool) {
	dir, name := path.Split(p)
	if !validName(name) {
		return "", false
	}
	return name, strings.TrimSuffix(dir, "/") == indexPrefix(name)
}

func indexPrefix(name string) string {
	switch len(name) {
	case 1:
		return "1"
	case 2:
		return "2"
	case 3:
		return "3/" + name[:1]
	}
	return name[:2] + "/" + name[2:4]
}

// validName accepts the lowercase crate names cargo puts in index paths.
func validName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// filterIndex keeps, byte for byte, the index lines whose version a allows.
func filterIndex(body []byte, a *policy.Assessment) []byte {
	var out []byte
	for line := range bytes.Lines(body) {
		var entry struct {
			Vers string `json:"vers"`
		}
		if json.Unmarshal(line, &entry) != nil || !a.Allowed(entry.Vers) {
			continue
		}
		out = append(out, line...)
	}
	return out
}

func (r *Registry) download(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	version := req.PathValue("version")
	pkg, err := r.Package(ctx, req.PathValue("crate"))
	if err != nil {
		proxy.WriteError(w, err)
		return
	}
	a := r.o.Engine.Assess(ctx, pkg)
	if !proxy.Enforce(w, proxy.Text, "cargo/"+pkg.Name+"@"+version, a.Release(version)) {
		return
	}
	src := r.o.Download + "/" + url.PathEscape(pkg.Name) + "/" + url.PathEscape(pkg.Name+"-"+version+".crate")
	resp, err := r.o.HTTP.Open(ctx, src, nil)
	if err != nil {
		proxy.WriteError(w, err)
		return
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		proxy.Relay(w, resp)
	// static.crates.io is an object store that answers 403 for a missing key.
	case http.StatusNotFound, http.StatusGone, http.StatusForbidden:
		proxy.WriteError(w, fmt.Errorf("GET %s: %w", src, proxy.ErrNotFound))
	default:
		proxy.WriteError(w, &proxy.StatusError{URL: src, Status: resp.StatusCode})
	}
}
