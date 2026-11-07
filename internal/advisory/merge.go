package advisory

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strings"
	"sync"

	"github.com/pogao/pkgwarden/internal/ecosystem"
)

type merged []Source

// Merge returns a Source that queries every source concurrently and folds
// advisories sharing an ID or alias into one entry. When some sources fail
// it still returns what the others found, alongside the joined errors.
func Merge(sources ...Source) Source { return merged(sources) }

func (m merged) Lookup(ctx context.Context, eco ecosystem.Ecosystem, name string) ([]Advisory, error) {
	results := make([][]Advisory, len(m))
	errs := make([]error, len(m))
	var wg sync.WaitGroup
	for i, src := range m {
		wg.Go(func() { results[i], errs[i] = src.Lookup(ctx, eco, name) })
	}
	wg.Wait()
	return dedupe(slices.Concat(results...)), errors.Join(errs...)
}

// dedupe groups advisories that share any identifier, transitively, so a
// GHSA entry, its PYSEC twin and their CVE collapse into one.
func dedupe(advs []Advisory) []Advisory {
	parent := make([]int, len(advs))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		if parent[i] != i {
			parent[i] = find(parent[i])
		}
		return parent[i]
	}
	owner := make(map[string]int)
	for i, a := range advs {
		for _, id := range append([]string{a.ID}, a.Aliases...) {
			if j, ok := owner[id]; ok {
				parent[find(i)] = find(j)
			} else {
				owner[id] = i
			}
		}
	}

	groups := make(map[int][]Advisory)
	var roots []int
	for i, a := range advs {
		r := find(i)
		if _, ok := groups[r]; !ok {
			roots = append(roots, r)
		}
		groups[r] = append(groups[r], a)
	}
	out := make([]Advisory, 0, len(roots))
	for _, r := range roots {
		out = append(out, combine(groups[r]))
	}
	return out
}

// combine folds duplicates into one advisory. The entry it keeps is the
// first malicious one, else the first; the others contribute their IDs,
// sources and affected releases. Severity is the highest any member reports,
// so blocking does not depend on which source answered first. It never
// mutates the inputs, which may be shared with a cache.
func combine(group []Advisory) Advisory {
	base := group[0]
	if i := slices.IndexFunc(group, func(a Advisory) bool { return a.Kind == Malicious }); i >= 0 {
		base = group[i]
	}
	out := base
	out.Aliases, out.Versions, out.Ranges = nil, nil, nil
	var sources []string
	affectsAll := false
	for _, a := range group {
		for _, id := range append([]string{a.ID}, a.Aliases...) {
			if id != out.ID && !slices.Contains(out.Aliases, id) {
				out.Aliases = append(out.Aliases, id)
			}
		}
		for _, s := range strings.Split(a.Source, "+") {
			if !slices.Contains(sources, s) {
				sources = append(sources, s)
			}
		}
		out.Summary = cmp.Or(out.Summary, a.Summary)
		out.Severity = max(out.Severity, a.Severity)
		out.URL = cmp.Or(out.URL, a.URL)
		if len(a.Versions) == 0 && len(a.Ranges) == 0 {
			affectsAll = true
		}
		for _, v := range a.Versions {
			if !slices.Contains(out.Versions, v) {
				out.Versions = append(out.Versions, v)
			}
		}
		for _, r := range a.Ranges {
			if !slices.Contains(out.Ranges, r) {
				out.Ranges = append(out.Ranges, r)
			}
		}
	}
	out.Source = strings.Join(sources, "+")
	// One member covering every release means the union does too.
	if affectsAll {
		out.Versions, out.Ranges = nil, nil
	}
	return out
}
