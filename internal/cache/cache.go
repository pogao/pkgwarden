// Package cache provides a small in-memory cache with per-entry expiry.
package cache

import (
	"sync"
	"time"
)

type entry[V any] struct {
	value   V
	weight  int64
	expires time.Time
	timer   *time.Timer
}

// TTL is a map whose entries expire after a fixed duration and whose
// entries' weights never sum past a budget. It is safe for concurrent use.
type TTL[K comparable, V any] struct {
	mu     sync.Mutex
	ttl    time.Duration
	budget int64
	weight func(K, V) int64
	used   int64
	items  map[K]*entry[V]
}

// New returns a cache holding at most max entries for ttl each.
func New[K comparable, V any](ttl time.Duration, max int) *TTL[K, V] {
	return NewWeighted(ttl, int64(max), func(K, V) int64 { return 1 })
}

// NewWeighted returns a cache holding entries for ttl each, whose weights
// sum to at most budget. It never stores an entry that weighs more than
// half the budget, so one entry cannot empty the cache.
func NewWeighted[K comparable, V any](ttl time.Duration, budget int64, weight func(K, V) int64) *TTL[K, V] {
	return &TTL[K, V]{ttl: ttl, budget: budget, weight: weight, items: make(map[K]*entry[V])}
}

// Get returns the live value stored under key.
func (c *TTL[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[key]
	if !ok || time.Now().After(e.expires) {
		var zero V
		return zero, false
	}
	return e.value, true
}

// Set stores value under key, evicting arbitrary entries to stay within the
// budget. The entry is deleted when it expires.
func (c *TTL[K, V]) Set(key K, value V) {
	w := c.weight(key, value)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.delete(key)
	if c.ttl <= 0 || 2*w > c.budget {
		return
	}
	for k := range c.items {
		if c.used+w <= c.budget {
			break
		}
		c.delete(k)
	}
	e := &entry[V]{value: value, weight: w, expires: time.Now().Add(c.ttl)}
	e.timer = time.AfterFunc(c.ttl, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.items[key] == e {
			c.delete(key)
		}
	})
	c.items[key] = e
	c.used += w
}

func (c *TTL[K, V]) delete(key K) {
	if e, ok := c.items[key]; ok {
		e.timer.Stop()
		c.used -= e.weight
		delete(c.items, key)
	}
}
