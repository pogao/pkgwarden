// Package npm adapts the npm registry protocol for pkgwarden. Packuments are
// filtered so npm only sees versions the policy allows, and tarball
// downloads of blocked versions are refused.
package npm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/pogao/pkgwarden/internal/ecosystem"
	"github.com/pogao/pkgwarden/internal/policy"
	"github.com/pogao/pkgwarden/internal/proxy"
)

// Options configures a Registry.
type Options struct {
	// Registry is the upstream registry base URL. Default https://registry.npmjs.org.
	Registry string
	// Downloads is the npm download counts API base URL. Default https://api.npmjs.org.
	Downloads string
	// PublicURL is the externally visible proxy URL used in rewritten
	// tarball links. Empty means derive it from each request.
	PublicURL string
	Engine    *policy.Engine
	HTTP      *proxy.Upstream
}

// Registry serves the npm registry protocol relative to its mount point.
type Registry struct {
	o            Options
	registryPath string
}

// New returns a Registry, filling in defaults for empty Options fields.
func New(o Options) *Registry {
	if o.Registry == "" {
		o.Registry = "https://registry.npmjs.org"
	}
	if o.Downloads == "" {
		o.Downloads = "https://api.npmjs.org"
	}
	o.Registry = strings.TrimSuffix(o.Registry, "/")
	o.Downloads = strings.TrimSuffix(o.Downloads, "/")
	r := &Registry{o: o}
	if u, err := url.Parse(o.Registry); err == nil {
		r.registryPath = u.EscapedPath()
	}
	return r
}

// Ecosystem returns ecosystem.Npm.
func (*Registry) Ecosystem() ecosystem.Ecosystem { return ecosystem.Npm }

// Package describes the named package from its packument.
func (r *Registry) Package(ctx context.Context, name string) (*policy.Package, error) {
	_, pkg, err := r.load(ctx, name)
	return pkg, err
}

var auditPaths = map[string]bool{
	"/-/npm/v1/security/advisories/bulk": true,
	"/-/npm/v1/security/audits/quick":    true,
}

func (r *Registry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost && auditPaths[req.URL.Path] {
		r.forwardPost(w, req)
		return
	}
	if req.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rt, ok := parseRoute(req.URL.Path)
	switch {
	case !ok:
		r.passthrough(w, req)
	case rt.spec != "":
		r.serveManifest(w, req, rt)
	case rt.file == "":
		r.servePackument(w, req, rt.name)
	default:
		r.serveTarball(w, req, rt)
	}
}

// route is a request for a packument, a single version manifest (spec set
// to a version or dist-tag), or a tarball (file set).
type route struct {
	name string // scoped names as "@scope/name"
	spec string
	file string
}

// parseRoute recognizes /<name>, /@scope/<name>, and the tarball paths
// under them. req.URL.Path is already decoded, so @scope%2fname arrives as
// @scope/name.
func parseRoute(p string) (route, bool) {
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	n := 1
	if strings.HasPrefix(segs[0], "@") {
		n = 2
	}
	if len(segs) < n || segs[0] == "-" {
		return route{}, false
	}
	for _, s := range segs[:n] {
		if s == "" || s == "@" {
			return route{}, false
		}
	}
	name, rest := strings.Join(segs[:n], "/"), segs[n:]
	switch {
	case len(rest) == 0:
		return route{name: name}, true
	case len(rest) == 1 && rest[0] != "" && rest[0] != "-":
		return route{name: name, spec: rest[0]}, true
	case len(rest) == 2 && rest[0] == "-" && strings.HasSuffix(rest[1], ".tgz"):
		return route{name: name, file: rest[1]}, true
	}
	return route{}, false
}

// version extracts the version from a tarball file name such as
// widget-1.2.3.tgz. A name that does not fit yields a string no release
// matches, so the policy blocks it as unknown.
func (rt route) version() string {
	unscoped := rt.name[strings.LastIndex(rt.name, "/")+1:]
	v, _ := strings.CutPrefix(strings.TrimSuffix(rt.file, ".tgz"), unscoped+"-")
	return v
}

func (r *Registry) load(ctx context.Context, name string) (*packument, *policy.Package, error) {
	downloads := make(chan int64, 1)
	go func() { downloads <- r.weeklyDownloads(ctx, name) }()
	// The abbreviated install-v1 document lacks time and _npmUser.
	b, err := r.o.HTTP.Fetch(ctx, r.o.Registry+"/"+url.PathEscape(name), http.Header{"Accept": {"application/json"}})
	if err != nil {
		return nil, nil, err
	}
	p, err := parsePackument(b)
	if err != nil {
		return nil, nil, err
	}
	return p, p.policyPackage(name, <-downloads), nil
}

func (r *Registry) weeklyDownloads(ctx context.Context, name string) int64 {
	var resp struct {
		Downloads *int64 `json:"downloads"`
	}
	if err := r.o.HTTP.FetchJSON(ctx, r.o.Downloads+"/downloads/point/last-week/"+name, &resp); err != nil || resp.Downloads == nil {
		return policy.UnknownDownloads
	}
	return *resp.Downloads
}

func (r *Registry) servePackument(w http.ResponseWriter, req *http.Request, name string) {
	if body, _, _, ok := r.filtered(w, req, name); ok {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}
}

// filtered returns the packument with blocked versions removed, along with
// the upstream dist-tags. When it returns false it has already written the
// response.
func (r *Registry) filtered(w http.ResponseWriter, req *http.Request, name string) ([]byte, map[string]string, *policy.Assessment, bool) {
	p, pkg, err := r.load(req.Context(), name)
	if err != nil {
		proxy.WriteError(w, err)
		return nil, nil, nil, false
	}
	ctx := req.Context()
	a := r.o.Engine.Assess(ctx, pkg)
	if !proxy.Enforce(ctx, w, proxy.JSON, proxy.StageMetadata, proxy.Subject{Ecosystem: ecosystem.Npm, Name: name}, a.Package) {
		return nil, nil, nil, false
	}
	tarballBase := proxy.BaseURL(req, r.o.PublicURL) + "/" + string(ecosystem.Npm)
	body, ok, err := p.filter(a.Allowed, tarballBase, r.registryPath)
	if err != nil {
		proxy.WriteError(w, err)
		return nil, nil, nil, false
	}
	if !ok {
		latest := p.distTags["latest"]
		proxy.Enforce(ctx, w, proxy.JSON, proxy.StageMetadata, proxy.Subject{Ecosystem: ecosystem.Npm, Name: name, Version: latest}, a.Release(latest))
		return nil, nil, nil, false
	}
	return body, p.distTags, a, true
}

// serveManifest answers GET /<name>/<version-or-tag> from the filtered
// packument, so the manifest's tarball link also points at the proxy.
func (r *Registry) serveManifest(w http.ResponseWriter, req *http.Request, rt route) {
	body, upstreamTags, a, ok := r.filtered(w, req, rt.name)
	if !ok {
		return
	}
	var doc struct {
		DistTags map[string]string          `json:"dist-tags"`
		Versions map[string]json.RawMessage `json:"versions"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		proxy.WriteError(w, err)
		return
	}
	v := rt.spec
	if tagged, ok := doc.DistTags[v]; ok {
		v = tagged
	} else if tagged, ok := upstreamTags[v]; ok {
		// Filtering dropped the tag because its target is blocked, so the
		// 403 reports the target's verdict.
		v = tagged
	}
	m, found := doc.Versions[v]
	if !found {
		// Missing from the filtered document means blocked or unpublished,
		// and the verdict says which.
		proxy.Enforce(req.Context(), w, proxy.JSON, proxy.StageMetadata, proxy.Subject{Ecosystem: ecosystem.Npm, Name: rt.name, Version: v}, a.Release(v))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(m)
}

func (r *Registry) serveTarball(w http.ResponseWriter, req *http.Request, rt route) {
	ctx := req.Context()
	_, pkg, err := r.load(ctx, rt.name)
	if err != nil {
		proxy.WriteError(w, err)
		return
	}
	s := proxy.Subject{Ecosystem: ecosystem.Npm, Name: rt.name, Version: rt.version()}
	a := r.o.Engine.Assess(ctx, pkg)
	if !proxy.Enforce(ctx, w, proxy.JSON, proxy.StageArtifact, s, a.Release(s.Version)) {
		return
	}
	resp, err := r.o.HTTP.Open(ctx, r.o.Registry+req.URL.EscapedPath(), nil)
	if err != nil {
		proxy.WriteError(w, err)
		return
	}
	defer resp.Body.Close()
	proxy.ServeArtifact(ctx, w, s, resp)
}

func (r *Registry) passthrough(w http.ResponseWriter, req *http.Request) {
	resp, err := r.o.HTTP.Open(req.Context(), r.upstreamURL(req), forwarded(req, "Accept"))
	if err != nil {
		proxy.WriteError(w, err)
		return
	}
	defer resp.Body.Close()
	proxy.Relay(w, resp)
}

func (r *Registry) forwardPost(w http.ResponseWriter, req *http.Request) {
	resp, err := r.o.HTTP.Post(req.Context(), r.upstreamURL(req), forwarded(req, "Accept", "Content-Type", "Content-Encoding"), req.Body)
	if err != nil {
		proxy.WriteError(w, err)
		return
	}
	defer resp.Body.Close()
	proxy.Relay(w, resp)
}

func (r *Registry) upstreamURL(req *http.Request) string {
	u := r.o.Registry + req.URL.EscapedPath()
	if req.URL.RawQuery != "" {
		u += "?" + req.URL.RawQuery
	}
	return u
}

// forwarded copies only the named headers, so client credentials meant
// for the proxy never reach the public registry.
func forwarded(req *http.Request, names ...string) http.Header {
	h := http.Header{}
	for _, n := range names {
		if v := req.Header.Get(n); v != "" {
			h.Set(n, v)
		}
	}
	return h
}
