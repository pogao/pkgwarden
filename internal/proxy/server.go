package proxy

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/pogao/pkgwarden/internal/ecosystem"
	"github.com/pogao/pkgwarden/internal/policy"
)

// Registry is an ecosystem adapter. It serves the package manager's
// protocol relative to its mount point and can describe a package to the
// policy engine.
type Registry interface {
	http.Handler
	Ecosystem() ecosystem.Ecosystem
	Package(ctx context.Context, name string) (*policy.Package, error)
}

// packageVersioner is a Registry whose upstream does not list every version
// it serves, so the check endpoint describes the package together with the
// version it is asked about.
type packageVersioner interface {
	PackageVersion(ctx context.Context, name, version string) (*policy.Package, error)
}

// NewServer mounts each registry under /<ecosystem>/ and adds /healthz and
// the /api/v1/check endpoint.
func NewServer(engine *policy.Engine, regs ...Registry) http.Handler {
	mux := http.NewServeMux()
	byEco := make(map[ecosystem.Ecosystem]Registry, len(regs))
	for _, reg := range regs {
		prefix := "/" + string(reg.Ecosystem())
		mux.Handle(prefix+"/", http.StripPrefix(prefix, reg))
		byEco[reg.Ecosystem()] = reg
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /api/v1/check", func(w http.ResponseWriter, r *http.Request) {
		check(w, r, engine, byEco)
	})
	return mux
}

type checkResult struct {
	Ecosystem ecosystem.Ecosystem `json:"ecosystem"`
	Name      string              `json:"name"`
	Version   string              `json:"version,omitempty"`
	policy.Verdict
}

// check reports the verdict for ?ecosystem=&name=&version= without
// downloading anything. Without a version it reports package-wide findings.
func check(w http.ResponseWriter, r *http.Request, engine *policy.Engine, regs map[ecosystem.Ecosystem]Registry) {
	q := r.URL.Query()
	eco, err := ecosystem.Parse(q.Get("ecosystem"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	reg, ok := regs[eco]
	name := q.Get("name")
	if !ok || name == "" {
		http.Error(w, "ecosystem not enabled or name missing", http.StatusBadRequest)
		return
	}
	var pkg *policy.Package
	if pv, ok := reg.(packageVersioner); ok {
		pkg, err = pv.PackageVersion(r.Context(), name, q.Get("version"))
	} else {
		pkg, err = reg.Package(r.Context(), name)
	}
	if err != nil {
		WriteError(w, err)
		return
	}
	a := engine.Assess(r.Context(), pkg)
	res := checkResult{Ecosystem: eco, Name: pkg.Name, Version: q.Get("version"), Verdict: a.Package}
	if res.Version != "" {
		res.Verdict = a.Release(res.Version)
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(res)
}
