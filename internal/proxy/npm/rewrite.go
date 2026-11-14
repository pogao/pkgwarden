package npm

import "context"

// rewriteBytes bounds the packument bytes being parsed and filtered at
// once, since rewriting takes several times a document's size in memory.
// A larger document is rewritten alone.
const rewriteBytes = 64 << 20

// rewriteKey names a rewrite by everything its output depends on: the
// cached packument, which of its releases the policy allows, and where the
// tarball links point.
type rewriteKey struct {
	snap *snapshot
	// allowed has one byte for each of snap.pkg.Releases, 1 if allowed.
	allowed     string
	tarballBase string
}

// flight is a rewrite that concurrent requests share. Once every request
// waiting for it has gone, it stops waiting for rewriteBytes, but a rewrite
// that has started runs to the end.
type flight struct {
	done    chan struct{}
	res     *rewritten
	err     error
	waiters int
	cancel  context.CancelFunc
}

// rewrite returns the packument in snap rewritten for allowed and
// tarballBase. Concurrent requests for the same rewrite share one.
func (r *Registry) rewrite(ctx context.Context, snap *snapshot, allowed func(string) bool, tarballBase string) (*rewritten, error) {
	decisions := make([]byte, len(snap.pkg.Releases))
	for i, rel := range snap.pkg.Releases {
		if allowed(rel.Version) {
			decisions[i] = 1
		}
	}
	key := rewriteKey{snap: snap, allowed: string(decisions), tarballBase: tarballBase}

	r.mu.Lock()
	f := r.flights[key]
	if f == nil {
		fctx, cancel := context.WithCancel(context.Background())
		f = &flight{done: make(chan struct{}), cancel: cancel}
		r.flights[key] = f
		go func() {
			f.res, f.err = r.runRewrite(fctx, snap.raw, allowed, tarballBase)
			cancel()
			r.mu.Lock()
			if r.flights[key] == f {
				delete(r.flights, key)
			}
			r.mu.Unlock()
			close(f.done)
		}()
	}
	f.waiters++
	r.mu.Unlock()

	select {
	case <-f.done:
		return f.res, f.err
	case <-ctx.Done():
		r.mu.Lock()
		if f.waiters--; f.waiters == 0 {
			f.cancel()
			if r.flights[key] == f {
				delete(r.flights, key)
			}
		}
		r.mu.Unlock()
		return nil, ctx.Err()
	}
}

// runRewrite parses raw and filters it with packument.filter, waiting
// until the documents being rewritten fit in rewriteBytes.
func (r *Registry) runRewrite(ctx context.Context, raw []byte, allowed func(string) bool, tarballBase string) (*rewritten, error) {
	n := min(int64(len(raw)), rewriteBytes)
	if err := r.rewriting.Acquire(ctx, n); err != nil {
		return nil, err
	}
	defer r.rewriting.Release(n)
	p, err := parsePackument(raw)
	if err != nil {
		return nil, err
	}
	return p.filter(allowed, tarballBase, r.registryPath)
}
