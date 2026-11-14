package cache_test

import (
	"runtime"
	"testing"
	"testing/synctest"
	"time"
	"weak"

	"github.com/pogao/pkgwarden/internal/cache"
)

type payload [1 << 20]byte

func TestExpiredEntryIsReleasedWithoutFurtherUse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := cache.New[string, *payload](time.Minute, 512)
		v := new(payload)
		held := weak.Make(v)
		c.Set("doc", v)
		v = nil

		time.Sleep(time.Minute + time.Second)
		synctest.Wait()
		runtime.GC()

		if held.Value() != nil {
			t.Error("an expired entry is still in memory, with no Set or Get since it expired")
		}
		runtime.KeepAlive(c)
	})
}

func TestZeroTTLHoldsNothing(t *testing.T) {
	c := cache.New[string, *payload](0, 512)
	v := new(payload)
	held := weak.Make(v)
	c.Set("doc", v)
	v = nil
	runtime.GC()

	if held.Value() != nil {
		t.Error("a cache with no TTL kept the value in memory")
	}
	runtime.KeepAlive(c)
}

func byValue(_ int, w int64) int64 { return w }

func TestWeightsNeverSumPastTheBudget(t *testing.T) {
	const budget = 100
	c := cache.NewWeighted(time.Minute, budget, byValue)
	for i := range 200 {
		c.Set(i, int64(1+i%50))
	}

	var held int64
	for i := range 200 {
		if w, ok := c.Get(i); ok {
			held += w
		}
	}
	if held > budget || held == 0 {
		t.Errorf("live entries weigh %d, want between 1 and the budget of %d", held, budget)
	}
}

func TestReplacingAnEntryFreesItsWeight(t *testing.T) {
	c := cache.NewWeighted(time.Minute, 100, byValue)
	for range 10 {
		c.Set(1, 40)
	}
	c.Set(2, 40)

	if _, ok := c.Get(1); !ok {
		t.Error("replacing an entry ten times evicted it to make room for a second one that fits")
	}
}

func TestEntryHeavierThanHalfTheBudgetIsNotStored(t *testing.T) {
	c := cache.NewWeighted(time.Minute, 100, byValue)
	c.Set(1, 10)
	c.Set(2, 51)

	if _, ok := c.Get(2); ok {
		t.Error("stored an entry heavier than half the budget")
	}
	if _, ok := c.Get(1); !ok {
		t.Error("refusing a heavy entry evicted another one")
	}
}
