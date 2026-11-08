// Package goproxy adapts the Go module proxy protocol (GOPROXY) for
// pkgwarden. Version lists only show versions the policy allows, and module
// zips of blocked versions are refused.
//
// A block is always a 403, never a 404 or 410: the go command treats those
// two as "try the next GOPROXY entry", which would let direct bypass the
// proxy.
package goproxy

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"golang.org/x/sync/errgroup"

	"github.com/pogao/pkgwarden/internal/ecosystem"
	"github.com/pogao/pkgwarden/internal/policy"
	"github.com/pogao/pkgwarden/internal/proxy"
)

// Options configures a Registry.
type Options struct {
	// Upstream is the upstream module proxy base URL. Default https://proxy.golang.org.
	Upstream string
	Engine   *policy.Engine
	HTTP     *proxy.Upstream
}

// Registry serves the GOPROXY protocol relative to its mount point.
type Registry struct {
	o Options
}

// New returns a Registry, filling in defaults for empty Options fields.
func New(o Options) *Registry {
	if o.Upstream == "" {
		o.Upstream = "https://proxy.golang.org"
	}
	o.Upstream = strings.TrimSuffix(o.Upstream, "/")
	return &Registry{o: o}
}

// Ecosystem returns ecosystem.Go.
func (*Registry) Ecosystem() ecosystem.Ecosystem { return ecosystem.Go }

// info is the JSON body of a .info or @latest response.
type info struct {
	Version string
	Time    time.Time
}

// Package describes the module at path name from its tagged versions, or
// from @latest when it has none.
func (r *Registry) Package(ctx context.Context, name string) (*policy.Package, error) {
	pkg, _, err := r.load(ctx, name, "")
	return pkg, err
}

// load describes a module and returns the versions upstream lists. extra
// adds a version the list may lack: pseudo-versions are never listed.
func (r *Registry) load(ctx context.Context, mod, extra string) (*policy.Package, []string, error) {
	esc, err := module.EscapePath(mod)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", proxy.ErrNotFound, err)
	}
	base := r.o.Upstream + "/" + esc
	b, err := r.o.HTTP.Fetch(ctx, base+"/@v/list", nil)
	if err != nil {
		return nil, nil, err
	}
	listed := strings.Fields(string(b))
	versions := listed
	if extra != "" && !slices.Contains(listed, extra) {
		versions = append(slices.Clip(listed), extra)
	}

	var releases []policy.Release
	if len(versions) == 0 {
		var latest info
		if err := r.o.HTTP.FetchJSON(ctx, base+"/@latest", &latest); err != nil {
			return nil, nil, err
		}
		if !semver.IsValid(latest.Version) {
			return nil, nil, fmt.Errorf("%s/@latest: invalid version %q", base, latest.Version)
		}
		releases = []policy.Release{{Version: latest.Version, Published: latest.Time}}
	} else {
		releases = make([]policy.Release, len(versions))
		g, gctx := errgroup.WithContext(ctx)
		g.SetLimit(8)
		for i, v := range versions {
			g.Go(func() error {
				ev, err := module.EscapeVersion(v)
				if err != nil {
					return fmt.Errorf("%s/@v/list: %w", base, err)
				}
				var in info
				if err := r.o.HTTP.FetchJSON(gctx, base+"/@v/"+ev+".info", &in); err != nil {
					return err
				}
				releases[i] = policy.Release{Version: v, Published: in.Time}
				return nil
			})
		}
		if err := g.Wait(); err != nil {
			return nil, nil, err
		}
	}

	pkg := &policy.Package{Ecosystem: ecosystem.Go, Name: mod, WeeklyDownloads: policy.UnknownDownloads, Releases: releases}
	for _, rel := range releases {
		if !rel.Published.IsZero() && (pkg.Created.IsZero() || rel.Published.Before(pkg.Created)) {
			pkg.Created = rel.Published
		}
	}
	return pkg, listed, nil
}

type endpoint int

const (
	list endpoint = iota
	latest
	infoFile
	modFile
	zipFile
)

// route is a parsed module proxy request.
type route struct {
	endpoint endpoint
	module   string
	version  string // only for .info, .mod and .zip
}

var fileEndpoints = map[string]endpoint{".info": infoFile, ".mod": modFile, ".zip": zipFile}

// parseRoute parses a request path in its escaped form, such as
// github.com/!burnt!sushi/toml/@v/v1.3.2.zip.
func parseRoute(p string) (route, error) {
	if esc, ok := strings.CutSuffix(p, "/@latest"); ok {
		mod, err := module.UnescapePath(esc)
		return route{endpoint: latest, module: mod}, err
	}
	esc, file, ok := strings.Cut(p, "/@v/")
	if !ok {
		return route{}, fmt.Errorf("unknown endpoint %q", p)
	}
	mod, err := module.UnescapePath(esc)
	if err != nil {
		return route{}, err
	}
	if file == "list" {
		return route{endpoint: list, module: mod}, nil
	}
	ext := path.Ext(file)
	e, ok := fileEndpoints[ext]
	if !ok {
		return route{}, fmt.Errorf("unknown endpoint %q", p)
	}
	v, err := module.UnescapeVersion(strings.TrimSuffix(file, ext))
	if err != nil {
		return route{}, err
	}
	// A query such as master.info resolves upstream, but a zip must name a
	// canonical version so advisories match it.
	if e == zipFile {
		if err := module.Check(mod, v); err != nil {
			return route{}, err
		}
	}
	return route{endpoint: e, module: mod, version: v}, nil
}

func (r *Registry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p := strings.TrimPrefix(req.URL.Path, "/")
	if strings.HasPrefix(p, "sumdb/") {
		r.passthrough(w, req, p)
		return
	}
	rt, err := parseRoute(p)
	if err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	switch rt.endpoint {
	case list:
		r.serveList(w, req, rt)
	case latest:
		r.serveLatest(w, req, rt)
	case zipFile:
		r.serveZip(w, req, rt, p)
	default:
		// MVS reads go.mod files of versions it will not select, so .info
		// and .mod stay available for blocked versions.
		r.passthrough(w, req, p)
	}
}

func (r *Registry) serveList(w http.ResponseWriter, req *http.Request, rt route) {
	pkg, listed, err := r.load(req.Context(), rt.module, "")
	if err != nil {
		proxy.WriteError(w, err)
		return
	}
	a := r.o.Engine.Assess(req.Context(), pkg)
	if !proxy.Enforce(req.Context(), w, proxy.Text, proxy.StageMetadata, proxy.Subject{Ecosystem: ecosystem.Go, Name: rt.module}, a.Package) {
		return
	}
	var b strings.Builder
	for _, v := range listed {
		if a.Allowed(v) {
			b.WriteString(v + "\n")
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(b.String()))
}

func (r *Registry) serveLatest(w http.ResponseWriter, req *http.Request, rt route) {
	pkg, _, err := r.load(req.Context(), rt.module, "")
	if err != nil {
		proxy.WriteError(w, err)
		return
	}
	ctx := req.Context()
	a := r.o.Engine.Assess(ctx, pkg)
	s := proxy.Subject{Ecosystem: ecosystem.Go, Name: rt.module}
	if !proxy.Enforce(ctx, w, proxy.Text, proxy.StageMetadata, s, a.Package) {
		return
	}
	versions := make([]string, len(pkg.Releases))
	for i, rel := range pkg.Releases {
		versions[i] = rel.Version
	}
	v := newest(versions, a.Allowed)
	if v == "" {
		s.Version = newest(versions, func(string) bool { return true })
		proxy.Enforce(ctx, w, proxy.Text, proxy.StageMetadata, s, a.Release(s.Version))
		return
	}
	esc, _ := module.EscapePath(rt.module)
	ev, err := module.EscapeVersion(v)
	if err != nil {
		proxy.WriteError(w, err)
		return
	}
	b, err := r.o.HTTP.Fetch(req.Context(), r.o.Upstream+"/"+esc+"/@v/"+ev+".info", http.Header{"Accept": {"application/json"}})
	if err != nil {
		proxy.WriteError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

// newest picks the version the go command would call latest among those ok
// accepts: the highest release, else the highest prerelease.
func newest(versions []string, ok func(string) bool) string {
	var release, pre string
	for _, v := range versions {
		if !ok(v) || !semver.IsValid(v) {
			continue
		}
		best := &release
		if semver.Prerelease(v) != "" {
			best = &pre
		}
		if *best == "" || semver.Compare(v, *best) > 0 {
			*best = v
		}
	}
	if release != "" {
		return release
	}
	return pre
}

func (r *Registry) serveZip(w http.ResponseWriter, req *http.Request, rt route, p string) {
	pkg, _, err := r.load(req.Context(), rt.module, rt.version)
	if err != nil {
		proxy.WriteError(w, err)
		return
	}
	ctx := req.Context()
	s := proxy.Subject{Ecosystem: ecosystem.Go, Name: rt.module, Version: rt.version}
	a := r.o.Engine.Assess(ctx, pkg)
	if !proxy.Enforce(ctx, w, proxy.Text, proxy.StageArtifact, s, a.Release(rt.version)) {
		return
	}
	resp, err := r.o.HTTP.Open(ctx, r.o.Upstream+"/"+p, nil)
	if err != nil {
		proxy.WriteError(w, err)
		return
	}
	defer resp.Body.Close()
	proxy.ServeArtifact(ctx, w, s, resp)
}

func (r *Registry) passthrough(w http.ResponseWriter, req *http.Request, p string) {
	resp, err := r.o.HTTP.Open(req.Context(), r.o.Upstream+"/"+p, nil)
	if err != nil {
		proxy.WriteError(w, err)
		return
	}
	defer resp.Body.Close()
	proxy.Relay(w, resp)
}
