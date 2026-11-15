package goproxy_test

import (
	"bytes"
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
	// traffic is when the next version that other clients fetched enters
	// the feed, one every 100ms once set, so that the feed's time passes.
	traffic  time.Time
	trafficN int
	// visible, when set, hides the entries after visible(now), as the real
	// feed does for a while after it records them.
	visible func(now time.Time) time.Time
	// cache, when set, answers a URL it answered before with the same
	// bytes, as the shared caches in front of index.golang.org do.
	cache map[string][]byte
}

func newFakeIndex() *fakeIndex {
	return &fakeIndex{onFetch: map[string]bool{}, status: http.StatusOK}
}

func (f *fakeIndex) add(path, version string, ts time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.insert(path, version, ts)
}

func (f *fakeIndex) insert(path, version string, ts time.Time) {
	f.entries = append(f.entries, indexLine{path, version, ts})
	slices.SortStableFunc(f.entries, func(a, b indexLine) int { return a.Timestamp.Compare(b.Timestamp) })
}

func (f *fakeIndex) startTraffic() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.traffic = time.Now()
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
	now := time.Now()
	for ; !f.traffic.IsZero() && !f.traffic.After(now); f.traffic = f.traffic.Add(100 * time.Millisecond) {
		f.trafficN++
		f.insert("example.com/traffic", fmt.Sprintf("v0.0.%d", f.trafficN), f.traffic)
	}
	if b, ok := f.cache[r.URL.RequestURI()]; ok {
		w.Write(b)
		return
	}
	since, err := time.Parse(time.RFC3339Nano, r.URL.Query().Get("since"))
	limit, lerr := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || lerr != nil || limit <= 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range f.entries {
		if limit == 0 || f.visible != nil && e.Timestamp.After(f.visible(now)) {
			break
		}
		if !e.Timestamp.Before(since) {
			enc.Encode(e)
			limit--
		}
	}
	if f.cache != nil {
		f.cache[r.URL.RequestURI()] = buf.Bytes()
	}
	w.Write(buf.Bytes())
}

// newIndexEnv returns an env whose feed has other clients' traffic and
// whose Index has synced once and runs until stopIndex or the test ends.
func newIndexEnv(t *testing.T, feed *fakeIndex) env {
	t.Helper()
	feed.startTraffic()
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
	e.stopIndex = func() {
		cancel()
		<-done
	}
	t.Cleanup(e.stopIndex)
	return e
}

const behindMsg = "go index behind, judging by commit time"

// assertFallbacks checks that the loads judged by commit time while the
// index was in force were warned about, naming mods in order, and counted.
func assertFallbacks(t *testing.T, logs *telemetrytest.Logs, before float64, mods ...string) {
	t.Helper()
	var warned []string
	for _, l := range logs.Messages(t, behindMsg) {
		if l["level"] == "WARN" {
			m, _ := l["module"].(string)
			warned = append(warned, m)
		}
	}
	if !slices.Equal(warned, mods) {
		t.Errorf("%s warnings name %q, want %q", behindMsg, warned, mods)
	}
	if d := telemetrytest.Value(t, "pkgwarden_go_index_fallbacks_total", nil) - before; d != float64(len(mods)) {
		t.Errorf("pkgwarden_go_index_fallbacks_total grew by %v, want %d", d, len(mods))
	}
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

func TestGoIndexWaitsForTheFeedToReadPastTheFetch(t *testing.T) {
	tests := []struct {
		name    string
		visible func(now time.Time) time.Time
		cache   bool
	}{
		{"lagging feed", func(now time.Time) time.Time { return now.Add(-3 * time.Second) }, false},
		{"feed published in batches behind a cache", func(now time.Time) time.Time { return now.Truncate(4 * time.Second) }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := telemetrytest.CaptureLogs(t)
			fallbacks := telemetrytest.Value(t, "pkgwarden_go_index_fallbacks_total", nil)
			feed := newFakeIndex()
			feed.visible = tt.visible
			if tt.cache {
				feed.cache = map[string][]byte{}
			}
			feed.addOnFetch(fooBar, "v1.0.0")
			e := newIndexEnv(t, feed)

			// Fetch midway between two of the reads that come once a
			// second, not in step with them.
			time.Sleep(500 * time.Millisecond)
			status, body := get(t, e.proxy.URL+"/go/example.com/!foo/bar/@v/v1.0.0.zip")
			assertBlocked(t, status, body, "go/example.com/Foo/bar@v1.0.0", "cooldown", "first seen upstream")
			assertFallbacks(t, logs, fallbacks)
		})
	}
}

func TestGoIndexBehindJudgesByCommitTime(t *testing.T) {
	const zip = "example.com/!foo/bar/@v/v1.0.0.zip"
	served := func(t *testing.T, e env) time.Duration {
		t.Helper()
		start := time.Now()
		if status, body := get(t, e.proxy.URL+"/go/"+zip); status != http.StatusOK || body != string(zipBytes(zip)) {
			t.Errorf("status %d body %q, want 200 by commit time", status, body)
		}
		return time.Since(start)
	}

	t.Run("not synced yet", func(t *testing.T) {
		logs := telemetrytest.CaptureLogs(t)
		fallbacks := telemetrytest.Value(t, "pkgwarden_go_index_fallbacks_total", nil)
		feed := newFakeIndex()
		feed.add(fooBar, "v1.0.0", time.Now().Add(-24*time.Hour))
		if d := served(t, setupEnv(t, nil, feed)); d > 2*time.Second {
			t.Errorf("request took %v waiting for the index", d)
		}
		if n := len(logs.Messages(t, behindMsg)); n != 1 {
			t.Errorf("%d %s lines, want 1 at debug", n, behindMsg)
		}
		assertFallbacks(t, logs, fallbacks)
	})
	t.Run("failing after a sync", func(t *testing.T) {
		logs := telemetrytest.CaptureLogs(t)
		fallbacks := telemetrytest.Value(t, "pkgwarden_go_index_fallbacks_total", nil)
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
		if d := served(t, e); d > 2*time.Second {
			t.Errorf("request took %v waiting for the index", d)
		}
		assertFallbacks(t, logs, fallbacks, fooBar)
	})
	t.Run("feed stuck before the fetch", func(t *testing.T) {
		logs := telemetrytest.CaptureLogs(t)
		fallbacks := telemetrytest.Value(t, "pkgwarden_go_index_fallbacks_total", nil)
		feed := newFakeIndex()
		stuck := time.Now()
		feed.visible = func(time.Time) time.Time { return stuck }
		feed.addOnFetch(fooBar, "v1.0.0")
		e := newIndexEnv(t, feed)
		if d := served(t, e); d < 10*time.Second || d > 12*time.Second {
			t.Errorf("request took %v, want the 10s the index gets to catch up", d)
		}
		assertFallbacks(t, logs, fallbacks, fooBar)
	})
}

func TestGoIndexBehindWarnsOnlyWhenACommitTimeJudges(t *testing.T) {
	const logrus = "github.com/sirupsen/logrus"
	dayAgo := time.Now().Add(-24 * time.Hour).UTC()
	tests := []struct {
		name     string
		mod, zip string
		entries  []string
		stuck    bool
		warned   []string
	}{
		{"every release has a first-seen time", logrus, "v1.9.3", []string{"v1.0.3", "v1.9.3"}, false, nil},
		{"every release has a first-seen time, feed stuck", logrus, "v1.9.3", []string{"v1.0.3", "v1.9.3"}, true, nil},
		{"one release lacks a first-seen time", logrus, "v1.9.3", []string{"v1.9.3"}, false, []string{logrus}},
		{"releases with no publish time need none", "example.com/gap", "v1.0.0", []string{"v1.0.0"}, false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := telemetrytest.CaptureLogs(t)
			fallbacks := telemetrytest.Value(t, "pkgwarden_go_index_fallbacks_total", nil)
			feed := newFakeIndex()
			for _, v := range tt.entries {
				feed.add(tt.mod, v, dayAgo)
			}
			var e env
			if tt.stuck {
				stuck := time.Now()
				feed.visible = func(time.Time) time.Time { return stuck }
				e = newIndexEnv(t, feed)
			} else {
				e = setupEnv(t, nil, feed)
				if err := e.index.Sync(context.Background()); err != nil {
					t.Fatal(err)
				}
				feed.setStatus(http.StatusInternalServerError)
				if err := e.index.Sync(context.Background()); err == nil {
					t.Fatal("Sync succeeded against a failing index")
				}
			}
			status, body := get(t, e.proxy.URL+"/go/"+tt.mod+"/@v/"+tt.zip+".zip")
			assertBlocked(t, status, body, tt.mod+"@"+tt.zip, "first seen upstream", dayAgo.Format(time.RFC3339))
			assertFallbacks(t, logs, fallbacks, tt.warned...)
		})
	}
}

func TestGoIndexStopEndsEveryWait(t *testing.T) {
	logs := telemetrytest.CaptureLogs(t)
	fallbacks := telemetrytest.Value(t, "pkgwarden_go_index_fallbacks_total", nil)
	feed := newFakeIndex()
	stuck := time.Now()
	feed.visible = func(time.Time) time.Time { return stuck }
	e := newIndexEnv(t, feed)

	const zip = "example.com/!foo/bar/@v/v1.0.0.zip"
	status := make(chan int, 1)
	go func() {
		resp, err := http.Get(e.proxy.URL + "/go/" + zip)
		if err != nil {
			status <- 0
			return
		}
		resp.Body.Close()
		status <- resp.StatusCode
	}()
	for deadline := time.Now().Add(5 * time.Second); e.infoHits.Load() < 5; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d .info fetches after 5s, want the 5 listed versions", e.infoHits.Load())
		}
	}
	time.Sleep(200 * time.Millisecond)

	stopped := time.Now()
	e.stopIndex()
	if s := <-status; s != http.StatusOK {
		t.Errorf("zip waiting at stop: status %d, want 200 by commit time", s)
	}
	if d := time.Since(stopped); d > 2*time.Second {
		t.Errorf("zip waiting at stop returned %v after it, want at once", d)
	}

	start := time.Now()
	p := "example.com/prerelease/@v/v0.1.0-alpha.1.zip"
	if status, body := get(t, e.proxy.URL+"/go/"+p); status != http.StatusOK || body != string(zipBytes(p)) {
		t.Errorf("zip after stop: status %d body %q, want 200 by commit time", status, body)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("zip after stop took %v, want no wait", d)
	}
	assertFallbacks(t, logs, fallbacks, fooBar, "example.com/prerelease")
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

	// With the .info fetched before the Sync, and a version another client
	// fetched after it in the feed, the Sync reads past that fetch, so the
	// later zip needs no Run loop to sync again.
	const zip = "example.com/!foo/bar/@v/v1.0.0.zip"
	if status, _ := get(t, e.proxy.URL+"/go/"+zip); status != http.StatusOK {
		t.Fatalf("zip before any sync: status %d, want 200 by commit time", status)
	}
	later := time.Now().Add(2 * time.Second)
	feed.add("example.com/later", "v1.0.0", later)
	if err := e.index.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := feed.count(); n != 2 {
		t.Errorf("Sync sent %d requests for 2502 entries, want 2 pages", n)
	}
	if n := telemetrytest.Value(t, "pkgwarden_go_index_versions", nil); n != 2502 {
		t.Errorf("pkgwarden_go_index_versions = %v, want 2502", n)
	}
	if ts := telemetrytest.Value(t, "pkgwarden_go_index_newest_entry_timestamp_seconds", nil); ts != float64(later.Unix()) {
		t.Errorf("pkgwarden_go_index_newest_entry_timestamp_seconds = %v, want %d, the newest entry", ts, later.Unix())
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
