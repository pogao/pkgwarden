package npm

import "context"

func (r *Registry) HoldRewrites() func() {
	r.rewriting.Acquire(context.Background(), rewriteBytes)
	return func() { r.rewriting.Release(rewriteBytes) }
}

func (r *Registry) RewriteWaiters() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, f := range r.flights {
		n += f.waiters
	}
	return n
}
