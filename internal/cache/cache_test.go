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
