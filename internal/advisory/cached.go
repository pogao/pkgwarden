package advisory

import (
	"context"
	"log/slog"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/pogao/pkgwarden/internal/cache"
	"github.com/pogao/pkgwarden/internal/ecosystem"
	"github.com/pogao/pkgwarden/internal/telemetry"
)

const cachedMaxPackages = 10000

// lookupTimeout bounds the shared lookup, which no caller can cancel.
const lookupTimeout = 30 * time.Second

type cached struct {
	src     Source
	results *cache.TTL[pkgKey, []Advisory]
	flight  singleflight.Group
}

// Cached returns a Source that remembers src's successful answers for ttl,
// keyed by ecosystem and normalized name. Concurrent misses for one package
// share a single upstream lookup, which keeps running if the caller that
// started it gives up, so the callers still waiting are not failed by
// someone else's cancellation. Errors are not cached.
func Cached(src Source, ttl time.Duration) Source {
	return &cached{src: src, results: cache.New[pkgKey, []Advisory](ttl, cachedMaxPackages)}
}

func (c *cached) Lookup(ctx context.Context, eco ecosystem.Ecosystem, name string) ([]Advisory, error) {
	k := keyOf(eco, name)
	if advs, ok := c.results.Get(k); ok {
		telemetry.RecordCache("advisory", true)
		slog.DebugContext(ctx, "advisory cache hit", "ecosystem", string(eco), "package", name)
		return advs, nil
	}
	telemetry.RecordCache("advisory", false)
	ch := c.flight.DoChan(string(k.eco)+"\x00"+k.name, func() (any, error) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), lookupTimeout)
		defer cancel()
		advs, err := c.src.Lookup(ctx, eco, name)
		if err == nil {
			c.results.Set(k, advs)
		}
		return advs, err
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		advs, _ := r.Val.([]Advisory)
		return advs, r.Err
	}
}
