// Package cache provides a small in-memory cache with per-entry expiry.
package cache

import (
	"sync"
	"time"
)

type entry[V any] struct {
	value   V
	expires time.Time
}

// TTL is a size-bounded map whose entries expire after a fixed duration.
// It is safe for concurrent use.
type TTL[K comparable, V any] struct {
	mu    sync.Mutex
	ttl   time.Duration
	max   int
	items map[K]entry[V]
}

// New returns a cache holding at most max entries for ttl each.
func New[K comparable, V any](ttl time.Duration, max int) *TTL[K, V] {
	return &TTL[K, V]{ttl: ttl, max: max, items: make(map[K]entry[V])}
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

// Set stores value under key, evicting expired entries first and an
// arbitrary entry if the cache is still full.
func (c *TTL[K, V]) Set(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.items[key]; !exists && len(c.items) >= c.max {
		now := time.Now()
		for k, e := range c.items {
			if now.After(e.expires) {
				delete(c.items, k)
			}
		}
		for k := range c.items {
			if len(c.items) < c.max {
				break
			}
			delete(c.items, k)
		}
	}
	c.items[key] = entry[V]{value: value, expires: time.Now().Add(c.ttl)}
}
