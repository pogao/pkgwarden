package goproxy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pogao/pkgwarden/internal/proxy"
	"github.com/pogao/pkgwarden/internal/proxy/goproxy"
	"github.com/pogao/pkgwarden/internal/telemetry/telemetrytest"
)

type indexLine struct {
	Path      string
	Version   string
	Timestamp time.Time
}

type fakeIndex struct {
	mu       sync.Mutex
	entries  []indexLine
	onFetch  map[string]bool
	status   int
	cut      int
	requests int
}

func newFakeIndex() *fakeIndex {
	return &fakeIndex{onFetch: map[string]bool{}, status: http.StatusOK}
}

func (f *fakeIndex) add(path, version string, ts time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, indexLine{path, version, ts})
	slices.SortStableFunc(f.entries, func(a, b indexLine) int { return a.Timestamp.Compare(b.Timestamp) })
}

func (f *fakeIndex) addOnFetch(path, version string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onFetch[path+"@"+version] = true
}

func (f *fakeIndex) served(path, version string) {
	f.mu.Lock()
	first := f.onFetch[path+"@"+version]
	delete(f.onFetch, path+"@"+version)
	f.mu.Unlock()
	if first {
		f.add(path, version, time.Now())
	}
}

func (f *fakeIndex) setStatus(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = status
}

// cutNext makes the next response end with an unexpected EOF.
func (f *fakeIndex) cutNext() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cut++
}

func (f *fakeIndex) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

func (f *fakeIndex) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	if r.Header.Get("User-Agent") != "pkgwarden-test" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if f.status != http.StatusOK {
		w.WriteHeader(f.status)
		return
	}
	if f.cut > 0 {
		f.cut--
		w.Header().Set("Content-Length", "1000")
		w.Write([]byte("{"))
		// Flushed, the cut comes after the response began, which the
		// transport never retries on its own.
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}
	since, err := time.Parse(time.RFC3339Nano, r.URL.Query().Get("since"))
	limit, lerr := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || lerr != nil || limit <= 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	enc := json.NewEncoder(w)
	for _, e := range f.entries {
		if limit == 0 {
			break
		}
		if !e.Timestamp.Before(since) {
			enc.Encode(e)
			limit--
		}
	}
}

func newIndexEnv(t *testing.T, feed *fakeIndex) env {
	t.Helper()
	e := setupEnv(t, nil, feed)
	if err := e.index.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		e.index.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return e
}

func TestGoIndexCooldownCountsFromFirstSeen(t *testing.T) {
	feed := newFakeIndex()
	dayAgo := time.Now().Add(-24 * time.Hour).UTC()
	feed.add(fooBar, "v1.0.0", dayAgo)
	feed.add("example.com/other", "v1.0.0", dayAgo.Add(time.Minute))
	e := newIndexEnv(t, feed)

	if status, body := get(t, e.proxy.URL+"/go/example.com/!foo/bar/@v/list"); status != http.StatusOK || body != "v0.9.0\nv1.0.0-RC.1\n" {
		t.Errorf("list: status %d body %q, want v1.0.0 hidden", status, body)
	}
	if status, body := get(t, e.proxy.URL+"/go/example.com/!foo/bar/@latest"); status != http.StatusOK || body != infoJSON("v0.9.0", ancient) {
		t.Errorf("@latest: status %d body %s, want the .info of v0.9.0", status, body)
	}
	status, body := get(t, e.proxy.URL+"/go/example.com/!foo/bar/@v/v1.0.0.zip")
	assertBlocked(t, status, body, "go/example.com/Foo/bar@v1.0.0", "cooldown", "first seen upstream", dayAgo.Format(time.RFC3339))
	if d, rules := checkAPI(t, e, fooBar, "v1.0.0"); d != "block" || !slices.Equal(rules, []string{"cooldown"}) {
		t.Errorf("check: %s %v, want block [cooldown]", d, rules)
	}
	p := "example.com/!foo/bar/@v/v1.0.0-!r!c.1.zip"
	if status, body := get(t, e.proxy.URL+"/go/"+p); status != http.StatusOK || body != string(zipBytes(p)) {
		t.Errorf("v1.0.0-RC.1.zip: status %d body %q, want 200", status, body)
	}
}

func TestGoIndexSeesTheFirstFetchThroughPkgwarden(t *testing.T) {
	t.Run("list", func(t *testing.T) {
		feed := newFakeIndex()
		feed.addOnFetch(fooBar, "v1.0.0")
		e := newIndexEnv(t, feed)
		if status, body := get(t, e.proxy.URL+"/go/example.com/!foo/bar/@v/list"); status != http.StatusOK || body != "v0.9.0\nv1.0.0-RC.1\n" {
			t.Errorf("first list: status %d body %q, want v1.0.0 hidden", status, body)
		}
	})
	t.Run("zip", func(t *testing.T) {
		feed := newFakeIndex()
		feed.addOnFetch(fooBar, "v1.0.0")
		e := newIndexEnv(t, feed)
		status, body := get(t, e.proxy.URL+"/go/example.com/!foo/bar/@v/v1.0.0.zip")
		assertBlocked(t, status, body, "go/example.com/Foo/bar@v1.0.0", "cooldown", "first seen upstream")
	})
	t.Run("@latest of an untagged module", func(t *testing.T) {
		const mod = "example.com/pseudo/old"
		feed := newFakeIndex()
		feed.addOnFetch(mod, pseudoV)
		e := newIndexEnv(t, feed)
		status, body := get(t, e.proxy.URL+"/go/"+mod+"/@latest")
		assertBlocked(t, status, body, "go/"+mod+"@"+pseudoV, "cooldown", "first seen upstream")

		before := feed.count()
		status, body = get(t, e.proxy.URL+"/go/"+mod+"/@latest")
		assertBlocked(t, status, body, "first seen upstream")
		if n := feed.count() - before; n != 0 {
			t.Errorf("repeating @latest sent %d index requests, want 0: the version was fetched before the last sync", n)
		}
	})
}

func TestGoIndexBehindJudgesByCommitTime(t *testing.T) {
	const zip = "example.com/!foo/bar/@v/v1.0.0.zip"
	served := func(t *testing.T, e env) {
		t.Helper()
		start := time.Now()
		if status, body := get(t, e.proxy.URL+"/go/"+zip); status != http.StatusOK || body != string(zipBytes(zip)) {
			t.Errorf("status %d body %q, want 200 by commit time", status, body)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("request took %v waiting for the index", d)
		}
	}

	t.Run("not synced yet", func(t *testing.T) {
		feed := newFakeIndex()
		feed.add(fooBar, "v1.0.0", time.Now().Add(-24*time.Hour))
		served(t, setupEnv(t, nil, feed))
	})
	t.Run("failing after a sync", func(t *testing.T) {
		feed := newFakeIndex()
		feed.addOnFetch(fooBar, "v1.0.0")
		e := setupEnv(t, nil, feed)
		if err := e.index.Sync(context.Background()); err != nil {
			t.Fatal(err)
		}
		feed.setStatus(http.StatusInternalServerError)
		if err := e.index.Sync(context.Background()); err == nil {
			t.Fatal("Sync succeeded against a failing index")
		}
		served(t, e)
	})
}

func TestGoIndexSyncReadsEveryPage(t *testing.T) {
	feed := newFakeIndex()
	start := time.Now()
	for i := range 2500 {
		feed.add(fmt.Sprintf("example.com/noise%d", i), "v1.0.0", start.Add(-6*24*time.Hour+time.Duration(i)*time.Minute))
	}
	seen := start.Add(-24 * time.Hour)
	feed.add(fooBar, "v1.0.0", seen)
	e := setupEnv(t, nil, feed)

	// Fetching the .info before the Sync means the later zip has no newer
	// fetch to wait for, since no Run loop is there to sync again.
	const zip = "example.com/!foo/bar/@v/v1.0.0.zip"
	if status, _ := get(t, e.proxy.URL+"/go/"+zip); status != http.StatusOK {
		t.Fatalf("zip before any sync: status %d, want 200 by commit time", status)
	}
	if err := e.index.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := feed.count(); n != 2 {
		t.Errorf("Sync sent %d requests for 2501 entries, want 2 pages", n)
	}
	if n := telemetrytest.Value(t, "pkgwarden_go_index_versions", nil); n != 2501 {
		t.Errorf("pkgwarden_go_index_versions = %v, want 2501", n)
	}
	if ts := telemetrytest.Value(t, "pkgwarden_go_index_last_success_timestamp_seconds", nil); ts < float64(start.Unix()) {
		t.Errorf("pkgwarden_go_index_last_success_timestamp_seconds = %v, want at least %d", ts, start.Unix())
	}
	status, body := get(t, e.proxy.URL+"/go/"+zip)
	assertBlocked(t, status, body, "first seen upstream", seen.UTC().Format(time.RFC3339))
}

func TestGoIndexSyncRetriesACutResponse(t *testing.T) {
	feed := newFakeIndex()
	e := setupEnv(t, nil, feed)
	if err := e.index.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	feed.add(fooBar, "v1.0.0", time.Now())
	feed.cutNext()
	before := feed.count()
	if err := e.index.Sync(context.Background()); err != nil {
		t.Fatalf("Sync after one cut response: %v", err)
	}
	if n := feed.count() - before; n != 2 {
		t.Errorf("Sync sent %d requests, want the cut one and one retry", n)
	}
	if n := telemetrytest.Value(t, "pkgwarden_go_index_versions", nil); n != 1 {
		t.Errorf("pkgwarden_go_index_versions = %v, want 1", n)
	}

	feed.cutNext()
	feed.cutNext()
	if err := e.index.Sync(context.Background()); err == nil {
		t.Error("Sync succeeded after two cut responses in a row")
	}
}

// handlerTransport serves requests from a handler in memory, so that a
// synctest bubble sees no network.
type handlerTransport struct{ http.Handler }

func (h handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Result(), nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type stalledBody struct{ ctx context.Context }

func (b stalledBody) Read([]byte) (int, error) {
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

func (stalledBody) Close() error { return nil }

func TestGoIndexSyncFailsOnAStalledPage(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stalled := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: stalledBody{r.Context()}, Request: r}, nil
		})
		up := proxy.NewUpstream(&http.Client{Transport: stalled}, "pkgwarden-test", time.Minute, 64<<20)
		ix := goproxy.NewIndex(up, "https://index.example/index", cooldown)
		start := time.Now()
		if err := ix.Sync(context.Background()); err == nil {
			t.Fatal("Sync succeeded on a page that never arrived")
		}
		if d := time.Since(start); d > time.Minute {
			t.Errorf("Sync gave up after %v, want within a minute", d)
		}
	})
}

func TestGoIndexRunRetriesAndLogsTheFirstSync(t *testing.T) {
	failures := telemetrytest.Value(t, "pkgwarden_go_index_sync_failures_total", nil)
	logs := telemetrytest.CaptureLogs(t)
	synctest.Test(t, func(t *testing.T) {
		feed := newFakeIndex()
		feed.add(fooBar, "v1.0.0", time.Now().Add(-time.Hour))
		feed.setStatus(http.StatusServiceUnavailable)
		up := proxy.NewUpstream(&http.Client{Transport: handlerTransport{feed}}, "pkgwarden-test", time.Minute, 64<<20)
		ix := goproxy.NewIndex(up, "https://index.example/index", cooldown)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			ix.Run(ctx)
			close(done)
		}()
		defer func() {
			cancel()
			<-done
		}()

		synctest.Wait()
		if d := telemetrytest.Value(t, "pkgwarden_go_index_sync_failures_total", nil) - failures; d != 1 {
			t.Errorf("pkgwarden_go_index_sync_failures_total grew by %v after one failed sync, want 1", d)
		}
		if n := len(logs.Messages(t, "go index sync failed")); n != 1 {
			t.Errorf("%d sync failure log lines, want 1", n)
		}

		feed.setStatus(http.StatusOK)
		time.Sleep(30*time.Second - time.Nanosecond)
		synctest.Wait()
		if n := feed.count(); n != 2 {
			t.Fatalf("%d index requests before the next poll, want 2: one failed and its retry", n)
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		synced := logs.Messages(t, "go index synced")
		if len(synced) != 1 || synced[0]["versions"] != 1.0 || synced[0]["pages"] != 1.0 || synced[0]["duration"] != "30s" {
			t.Fatalf("go index synced lines %v, want one with 1 version, 1 page and the 30s since the first attempt", synced)
		}

		time.Sleep(30 * time.Second)
		synctest.Wait()
		if n := feed.count(); n != 4 {
			t.Errorf("%d index requests after another poll interval, want 4", n)
		}
		if n := len(logs.Messages(t, "go index synced")); n != 1 {
			t.Errorf("%d go index synced lines after a later sync, want 1", n)
		}
	})
}
