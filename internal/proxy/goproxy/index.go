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
	// A load waits for the feed to pass its fetch time plus indexClockSkew,
	// so that it still finds the version its own fetch put in the feed when
	// pkgwarden's clock runs up to that much behind the index's. Waiting
	// longer is the safe side of a clock error.
	indexClockSkew = time.Second
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

	mu   sync.Mutex
	seen map[string]time.Time
	// newest is the latest Timestamp read from the feed. The feed grows in
	// Timestamp order, so seen holds every version first served up to it.
	newest time.Time
	state  indexState
	synced chan struct{}
}

type indexState int

const (
	// indexStarting means no Sync has read to the head of the feed yet.
	indexStarting indexState = iota
	indexReady
	// indexFailed means the last Sync failed after an earlier one succeeded.
	indexFailed
	// indexStopped means Run returned, so no Sync follows.
	indexStopped
)

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
	err := ix.read(ctx)

	ix.mu.Lock()
	first := err == nil && ix.state == indexStarting
	switch {
	case ix.state == indexStopped:
	case err == nil:
		ix.state = indexReady
	case ix.state == indexReady:
		ix.state = indexFailed
	}
	if now.Sub(ix.pruned) >= indexPoll {
		cutoff := now.Add(-ix.cooldown)
		for k, t := range ix.seen {
			if t.Before(cutoff) {
				delete(ix.seen, k)
			}
		}
		ix.pruned = now
	}
	n, newest := len(ix.seen), ix.newest
	close(ix.synced)
	ix.synced = make(chan struct{})
	ix.mu.Unlock()

	if err != nil {
		return err
	}
	telemetry.RecordGoIndexSync(n, newest)
	if first {
		slog.Info("go index synced", "versions", n, "pages", ix.pages, "duration", time.Since(ix.started).Round(time.Millisecond).String())
	}
	return nil
}

func (ix *Index) read(ctx context.Context) error {
	for {
		page, err := ix.page(ctx)
		if err != nil && ctx.Err() == nil {
			// The server can close a kept-alive connection just as a
			// request reuses it.
			page, err = ix.page(ctx)
		}
		if err != nil {
			return err
		}
		ix.pages++
		ix.mu.Lock()
		for _, e := range page {
			k := e.Path + "@" + e.Version
			if t, ok := ix.seen[k]; !ok || e.Timestamp.Before(t) {
				ix.seen[k] = e.Timestamp
			}
			if e.Timestamp.After(ix.newest) {
				ix.newest = e.Timestamp
			}
		}
		ix.mu.Unlock()
		// The next page starts at the last timestamp, inclusive, so a full
		// page that ends where it began would be requested forever.
		if n := len(page); n > 0 && page[n-1].Timestamp.After(ix.since) {
			ix.since = page[n-1].Timestamp
		} else if n == indexPageLimit {
			return fmt.Errorf("%s: a full page since %s did not advance", ix.url, ix.since.Format(time.RFC3339Nano))
		}
		if len(page) < indexPageLimit {
			return nil
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
	// A read that finds nothing new repeats its since, and the index lets
	// shared caches answer a repeated URL for 5 minutes with what it held
	// then. The nonce sends every request to the index itself.
	url := fmt.Sprintf("%s?since=%s&limit=%d&nonce=%d", ix.url, ix.since.UTC().Format(time.RFC3339Nano), indexPageLimit, time.Now().UnixNano())
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
// It logs a failed Sync and retries at the next poll. Once it returns, loads
// no longer wait for the index.
func (ix *Index) Run(ctx context.Context) {
	defer ix.stop()
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

func (ix *Index) stop() {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	ix.state = indexStopped
	close(ix.synced)
	ix.synced = make(chan struct{})
}

// proxy.golang.org adds a version to the index when it first serves it, so
// a .info fetch can be what puts the version there.
func (ix *Index) firstSeen(ctx context.Context, mod string, rels []policy.Release, fetched time.Time) {
	covered, state := ix.await(ctx, fetched)
	ix.mu.Lock()
	for i, r := range rels {
		if t, ok := ix.seen[mod+"@"+r.Version]; ok {
			rels[i].FirstSeen = t
		}
	}
	newest := ix.newest
	ix.mu.Unlock()
	switch {
	case covered:
	case state == indexStarting:
		slog.DebugContext(ctx, "go index behind, judging by commit time", "module", mod)
	default:
		slog.WarnContext(ctx, "go index behind, judging by commit time", "module", mod, "index_newest", newest)
		telemetry.RecordGoIndexFallback()
	}
}

// await reports whether the feed has been read past fetched, so that seen
// holds any version that a fetch ended by then made proxy.golang.org serve
// first, and otherwise the state that ended the wait. It waits at most
// indexWait, and not at all before the first Sync reaches the head, after a
// failed Sync, or once Run returned, so that a slow or down index never
// stalls an install for long.
func (ix *Index) await(ctx context.Context, fetched time.Time) (bool, indexState) {
	ctx, cancel := context.WithTimeout(ctx, indexWait)
	defer cancel()
	for {
		ix.mu.Lock()
		state, newest, synced := ix.state, ix.newest, ix.synced
		ix.mu.Unlock()
		switch {
		case state == indexStarting:
			return false, state
		case !newest.Before(fetched.Add(indexClockSkew)):
			return true, state
		case state != indexReady:
			return false, state
		}
		select {
		case ix.kick <- struct{}{}:
		default:
		}
		select {
		case <-synced:
		case <-ctx.Done():
			return false, state
		}
	}
}
