package advisory

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pogao/pkgwarden/internal/ecosystem"
	"github.com/pogao/pkgwarden/internal/telemetry/telemetrytest"
)

type countingSource struct {
	calls   atomic.Int32
	release chan struct{} // when non-nil, each lookup waits for it
	err     error
}

func (s *countingSource) Lookup(ctx context.Context, eco ecosystem.Ecosystem, name string) ([]Advisory, error) {
	s.calls.Add(1)
	if s.release != nil {
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.err != nil {
		return nil, s.err
	}
	return []Advisory{{ID: "ADV-" + name, Ecosystem: eco}}, nil
}

func TestCachedServesWithinTTL(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := &countingSource{}
		c := Cached(src, time.Minute)
		ctx := context.Background()

		first, err := c.Lookup(ctx, ecosystem.PyPI, "Foo_Bar")
		if err != nil || len(first) != 1 {
			t.Fatalf("Lookup = %v, %v", first, err)
		}
		// PyPI treats Foo_Bar and foo-bar as one package.
		if _, err := c.Lookup(ctx, ecosystem.PyPI, "foo-bar"); err != nil {
			t.Fatal(err)
		}
		if got := src.calls.Load(); got != 1 {
			t.Errorf("upstream calls = %d, want 1", got)
		}
		if _, err := c.Lookup(ctx, ecosystem.Npm, "foo-bar"); err != nil {
			t.Fatal(err)
		}
		if got := src.calls.Load(); got != 2 {
			t.Errorf("upstream calls after another ecosystem = %d, want 2", got)
		}

		time.Sleep(time.Minute + time.Second)
		if _, err := c.Lookup(ctx, ecosystem.PyPI, "foo-bar"); err != nil {
			t.Fatal(err)
		}
		if got := src.calls.Load(); got != 3 {
			t.Errorf("upstream calls after expiry = %d, want 3", got)
		}
	})
}

// npm names are case-sensitive: jQuery and jquery are different packages.
func TestCachedKeepsNpmCaseVariantsApart(t *testing.T) {
	for _, order := range [][]string{{"jQuery", "jquery"}, {"jquery", "jQuery"}} {
		c := Cached(&countingSource{}, time.Hour)
		for _, name := range order {
			advs, err := c.Lookup(context.Background(), ecosystem.Npm, name)
			if err != nil {
				t.Fatal(err)
			}
			if len(advs) != 1 || advs[0].ID != "ADV-"+name {
				t.Errorf("after %v: Lookup(%s) = %+v, want ADV-%s", order, name, advs, name)
			}
		}
	}
}

func TestCachedDoesNotCacheErrors(t *testing.T) {
	src := &countingSource{err: errors.New("unavailable")}
	c := Cached(src, time.Hour)
	for range 2 {
		if _, err := c.Lookup(context.Background(), ecosystem.Npm, "p"); !errors.Is(err, src.err) {
			t.Fatalf("err = %v, want %v", err, src.err)
		}
	}
	if got := src.calls.Load(); got != 2 {
		t.Errorf("upstream calls = %d, want 2", got)
	}
}

func TestCachedCollapsesConcurrentMisses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := &countingSource{release: make(chan struct{})}
		c := Cached(src, time.Hour)

		leaderCtx, cancelLeader := context.WithCancel(context.Background())
		var leaderErr error
		var wg sync.WaitGroup
		wg.Go(func() { _, leaderErr = c.Lookup(leaderCtx, ecosystem.Npm, "p") })
		synctest.Wait()

		results := make([][]Advisory, 5)
		for i := range results {
			wg.Go(func() {
				var err error
				if results[i], err = c.Lookup(context.Background(), ecosystem.Npm, "p"); err != nil {
					t.Error(err)
				}
			})
		}
		synctest.Wait()
		// The caller that started the lookup gives up; the others still get the answer.
		cancelLeader()
		synctest.Wait()
		close(src.release)
		wg.Wait()

		if !errors.Is(leaderErr, context.Canceled) {
			t.Errorf("leader err = %v, want context.Canceled", leaderErr)
		}
		if got := src.calls.Load(); got != 1 {
			t.Errorf("upstream calls = %d, want 1", got)
		}
		for i, r := range results {
			if len(r) != 1 || r[0].ID != "ADV-p" {
				t.Errorf("waiter %d got %+v", i, r)
			}
		}
	})
}

func TestCachedCountsHitsAndMisses(t *testing.T) {
	hit := map[string]string{"cache": "advisory", "result": "hit"}
	miss := map[string]string{"cache": "advisory", "result": "miss"}
	hits, misses := telemetrytest.Value(t, "pkgwarden_cache_requests_total", hit), telemetrytest.Value(t, "pkgwarden_cache_requests_total", miss)
	c := Cached(&countingSource{}, time.Minute)
	for range 3 {
		if _, err := c.Lookup(context.Background(), ecosystem.Npm, "left-pad"); err != nil {
			t.Fatal(err)
		}
	}
	if d := telemetrytest.Value(t, "pkgwarden_cache_requests_total", miss) - misses; d != 1 {
		t.Errorf("advisory misses grew by %v, want 1", d)
	}
	if d := telemetrytest.Value(t, "pkgwarden_cache_requests_total", hit) - hits; d != 2 {
		t.Errorf("advisory hits grew by %v, want 2", d)
	}
}
