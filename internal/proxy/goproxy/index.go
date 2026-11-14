package goproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/pogao/pkgwarden/internal/policy"
	"github.com/pogao/pkgwarden/internal/proxy"
	"github.com/pogao/pkgwarden/internal/telemetry"
)

const (
	defaultIndex = "https://index.golang.org/index"
	// indexPageLimit is the most entries the index returns per request. A
	// shorter page is the head of the feed.
	indexPageLimit   = 2000
	indexPageBytes   = 4 << 20
	indexPageTimeout = 30 * time.Second
	// indexPoll stays under the minute after which index.golang.org closes
	// an idle connection, so that a poll does not race that close.
	indexPoll  = 30 * time.Second
	minSyncGap = time.Second
	indexWait  = 10 * time.Second
)

// Index is the set of module versions that proxy.golang.org first served
// inside the cooldown window, with the time it first served each one, read
// from the Go module index. Unlike the commit time in a version's .info, the
// author cannot backdate that time.
type Index struct {
	up       *proxy.Upstream
	url      string
	cooldown time.Duration
	kick     chan struct{}

	syncMu  sync.Mutex
	since   time.Time
	pruned  time.Time
	started time.Time
	pages   int

	mu             sync.Mutex
	seen           map[string]time.Time
	completeBefore time.Time
	failed         bool
	synced         chan struct{}
}

// NewIndex returns an Index over the feed at url, or index.golang.org when
// url is empty, that keeps versions first served within cooldown. It holds
// nothing until Sync or Run reads the feed.
func NewIndex(up *proxy.Upstream, url string, cooldown time.Duration) *Index {
	if url == "" {
		url = defaultIndex
	}
	return &Index{
		up: up, url: url, cooldown: cooldown,
		kick:   make(chan struct{}, 1),
		seen:   make(map[string]time.Time),
		synced: make(chan struct{}),
	}
}

// Sync reads the feed from where the last call stopped, or from one cooldown
// ago on the first call, to its head. A failed Sync keeps what it read, and
// the next call resumes after it.
func (ix *Index) Sync(ctx context.Context) error {
	ix.syncMu.Lock()
	defer ix.syncMu.Unlock()
	now := time.Now()
	if ix.since.IsZero() {
		ix.since, ix.started = now.Add(-ix.cooldown), now
	}
	completeBefore, err := ix.read(ctx)

	ix.mu.Lock()
	first := err == nil && ix.completeBefore.IsZero()
	if err == nil {
		ix.completeBefore = completeBefore
	}
	ix.failed = err != nil
	if now.Sub(ix.pruned) >= indexPoll {
		cutoff := now.Add(-ix.cooldown)
		for k, t := range ix.seen {
			if t.Before(cutoff) {
				delete(ix.seen, k)
			}
		}
		ix.pruned = now
	}
	n := len(ix.seen)
	close(ix.synced)
	ix.synced = make(chan struct{})
	ix.mu.Unlock()

	if err != nil {
		return err
	}
	telemetry.RecordGoIndexSync(n, completeBefore)
	if first {
		slog.Info("go index synced", "versions", n, "pages", ix.pages, "duration", time.Since(ix.started).Round(time.Millisecond).String())
	}
	return nil
}

func (ix *Index) read(ctx context.Context) (time.Time, error) {
	for {
		start := time.Now()
		page, err := ix.page(ctx)
		if err != nil && ctx.Err() == nil {
			// The server can close a kept-alive connection just as a
			// request reuses it.
			start = time.Now()
			page, err = ix.page(ctx)
		}
		if err != nil {
			return time.Time{}, err
		}
		ix.pages++
		ix.mu.Lock()
		for _, e := range page {
			k := e.Path + "@" + e.Version
			if t, ok := ix.seen[k]; !ok || e.Timestamp.Before(t) {
				ix.seen[k] = e.Timestamp
			}
		}
		ix.mu.Unlock()
		// The next page starts at the last timestamp, inclusive, so a full
		// page that ends where it began would be requested forever.
		if n := len(page); n > 0 && page[n-1].Timestamp.After(ix.since) {
			ix.since = page[n-1].Timestamp
		} else if n == indexPageLimit {
			return time.Time{}, fmt.Errorf("%s: a full page since %s did not advance", ix.url, ix.since.Format(time.RFC3339Nano))
		}
		if len(page) < indexPageLimit {
			return start, nil
		}
	}
}

type indexEntry struct {
	Path      string
	Version   string
	Timestamp time.Time
}

func (ix *Index) page(ctx context.Context) ([]indexEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, indexPageTimeout)
	defer cancel()
	url := fmt.Sprintf("%s?since=%s&limit=%d", ix.url, ix.since.UTC().Format(time.RFC3339Nano), indexPageLimit)
	resp, err := ix.up.Open(ctx, url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &proxy.StatusError{URL: url, Status: resp.StatusCode}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, indexPageBytes+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	if len(b) > indexPageBytes {
		return nil, fmt.Errorf("GET %s: page larger than %d bytes", url, indexPageBytes)
	}
	var page []indexEntry
	dec := json.NewDecoder(bytes.NewReader(b))
	for dec.More() {
		var e indexEntry
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("decode %s: %w", url, err)
		}
		page = append(page, e)
	}
	return page, nil
}

// Run syncs now and then every 30 seconds until ctx is done, sooner when a
// load is waiting for the index, but never within a second of the last Sync.
// It logs a failed Sync and retries at the next poll.
func (ix *Index) Run(ctx context.Context) {
	for {
		if err := ix.Sync(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.ErrorContext(ctx, "go index sync failed", "err", err)
			telemetry.RecordGoIndexFailure()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(minSyncGap):
		}
		select {
		case <-ctx.Done():
			return
		case <-ix.kick:
		case <-time.After(indexPoll - minSyncGap):
		}
	}
}

// proxy.golang.org adds a version to the index when it first serves it, so
// a .info fetch can be what puts the version there.
func (ix *Index) firstSeen(ctx context.Context, mod string, rels []policy.Release, fetched time.Time) {
	if !ix.await(ctx, fetched) {
		slog.DebugContext(ctx, "go index behind, judging by commit time", "module", mod)
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	for i, r := range rels {
		if t, ok := ix.seen[mod+"@"+r.Version]; ok {
			rels[i].FirstSeen = t
		}
	}
}

// await does not wait before the first Sync reaches the head or after a
// failed Sync, so that a slow or down index never stalls an install.
func (ix *Index) await(ctx context.Context, fetched time.Time) bool {
	ctx, cancel := context.WithTimeout(ctx, indexWait)
	defer cancel()
	for {
		ix.mu.Lock()
		completeBefore, failed, synced := ix.completeBefore, ix.failed, ix.synced
		ix.mu.Unlock()
		switch {
		case completeBefore.After(fetched):
			return true
		case completeBefore.IsZero() || failed:
			return false
		}
		select {
		case ix.kick <- struct{}{}:
		default:
		}
		select {
		case <-synced:
		case <-ctx.Done():
			return false
		}
	}
}
