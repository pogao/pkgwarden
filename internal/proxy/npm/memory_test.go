package npm_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pogao/pkgwarden/internal/advisory"
	"github.com/pogao/pkgwarden/internal/ecosystem"
	"github.com/pogao/pkgwarden/internal/policy"
	"github.com/pogao/pkgwarden/internal/proxy"
	"github.com/pogao/pkgwarden/internal/proxy/npm"
)

// largePackument has n old releases whose manifests each carry pad bytes
// of readme. renovate's 75 MB packument has 5957 releases, about 12.6 KB
// each.
func largePackument(t *testing.T, registry string, n, pad int) []byte {
	t.Helper()
	versions := map[string]any{}
	times := map[string]string{"created": old.Format(npmTime)}
	for i := range n {
		v := fmt.Sprintf("1.%d.0", i)
		versions[v] = map[string]any{
			"name":    "big",
			"version": v,
			"readme":  strings.Repeat("x", pad),
			"dist":    map[string]string{"tarball": registry + "/big/-/big-" + v + ".tgz", "integrity": "sha512-x"},
		}
		times[v] = old.Format(npmTime)
	}
	b, err := json.Marshal(map[string]any{"name": "big", "dist-tags": map[string]string{"latest": "1.0.0"}, "versions": versions, "time": times})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// One P and no collection keep a rewrite's second large JSON encode on the
// sync.Pool buffer its first one grew. A collection empties the pool, and an
// item put on one P is hidden from the others. A rewrite that misses the
// buffer allocates about 100 MB more.
func bytesAllocated(f func()) uint64 {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// skipAllocationBudgetUnderRace ends the test before its byte comparison
// when the race detector is on. The detector's own allocations move one
// packument rewrite by about 100 MB from run to run, more than these
// budgets allow. The requests and their checks have already run.
func skipAllocationBudgetUnderRace(t *testing.T) {
	t.Helper()
	if raceEnabled {
		t.Skip("allocation budgets are checked without -race")
	}
}

// bigProxy returns a proxy whose upstream serves a largePackument of 2000
// releases with pad bytes each as package big, and that packument.
func bigProxy(t *testing.T, pad int) (*httptest.Server, []byte) {
	t.Helper()
	srv, _, doc := releasesProxy(t, 2000, pad, fakeSource(nil))
	return srv, doc
}

// releasesProxy is bigProxy for a package of n releases, with heuristics
// on and advisories from src. It also returns the npm registry.
func releasesProxy(t *testing.T, n, pad int, src fakeSource) (*httptest.Server, *npm.Registry, []byte) {
	t.Helper()
	var doc []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/big":
			w.Write(doc)
		case strings.HasSuffix(r.URL.Path, ".tgz"):
			w.Write(tarballBytes(r.URL.Path))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(upstream.Close)
	doc = largePackument(t, upstream.URL, n, pad)
	engine := policy.New(policy.Config{Cooldown: week, Heuristics: policy.HeuristicsConfig{
		Enabled: true, NewPackageAge: week, LowWeeklyDownloads: 100, WarnScore: 30, BlockScore: 70,
	}}, src)
	reg := npm.New(npm.Options{
		Registry:  upstream.URL,
		Downloads: upstream.URL,
		Engine:    engine,
		HTTP:      proxy.NewUpstream(http.DefaultClient, "pkgwarden-test", time.Minute, 64<<20),
	})
	srv := httptest.NewServer(proxy.NewServer(engine, reg))
	t.Cleanup(srv.Close)
	return srv, reg, doc
}

// together serves srv's handler at a new URL where each of the first n
// requests waits until all n have arrived. Without it, a request whose
// connection opens late on a loaded machine can reach the proxy after the
// shared rewrite has ended, and then does a rewrite of its own.
func together(t *testing.T, srv *httptest.Server, n int) string {
	t.Helper()
	var arrived sync.WaitGroup
	arrived.Add(n)
	burst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived.Done()
		arrived.Wait()
		srv.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(burst.Close)
	return burst.URL
}

func TestConcurrentTarballRequestsDoNotMultiplyPackumentMemory(t *testing.T) {
	srv, doc := bigProxy(t, 8<<10)
	tarball := srv.URL + "/npm/big/-/big-1.7.0.tgz"
	if resp, body := get(t, tarball); resp.StatusCode != http.StatusOK {
		t.Fatalf("first tarball request: status %d body %s", resp.StatusCode, body)
	}

	const n = 16
	allocated := bytesAllocated(func() {
		var wg sync.WaitGroup
		for range n {
			wg.Go(func() {
				resp, err := http.Get(tarball)
				if err != nil {
					t.Error(err)
					return
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Errorf("status %d, want 200", resp.StatusCode)
				}
			})
		}
		wg.Wait()
	})

	t.Logf("%d concurrent tarball requests allocated %d bytes in all, for a %d-byte packument", n, allocated, len(doc))
	skipAllocationBudgetUnderRace(t)
	if allocated > uint64(len(doc)) {
		t.Errorf("%d concurrent tarball requests for a cached packument allocated %d bytes, more than the %d-byte packument itself", n, allocated, len(doc))
	}
}

// send GETs url with the given Host header, copies the body to w, and
// returns the status.
func send(url, host string, w io.Writer) (int, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, err = io.Copy(w, resp.Body)
	return resp.StatusCode, err
}

var hostsUsed atomic.Int32

// unusedHost returns a Host header that no earlier request sent, so no kept
// rewrite answers a request that sends it.
func unusedHost() string { return fmt.Sprintf("host%d.example", hostsUsed.Add(1)) }

func TestConcurrentPackumentRequestsShareOneRewrite(t *testing.T) {
	srv, _ := bigProxy(t, 8<<10)
	packument := srv.URL + "/npm/big"
	if code, err := send(packument, "", io.Discard); err != nil || code != http.StatusOK {
		t.Fatalf("first packument request: status %d, error %v", code, err)
	}
	one := bytesAllocated(func() { send(packument, unusedHost(), io.Discard) })

	const n = 16
	burst, host := together(t, srv, n)+"/npm/big", unusedHost()
	sums := make([][]byte, n)
	allocated := bytesAllocated(func() {
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() {
				h := sha256.New()
				if code, err := send(burst, host, h); err != nil || code != http.StatusOK {
					t.Errorf("status %d, error %v, want 200", code, err)
				}
				sums[i] = h.Sum(nil)
			})
		}
		wg.Wait()
	})

	later := sha256.New()
	send(packument, host, later)
	for i, sum := range sums {
		if !bytes.Equal(sum, later.Sum(nil)) {
			t.Errorf("concurrent response %d differs from a later request's", i)
		}
	}
	t.Logf("one packument request allocated %d bytes, %d concurrent ones %d", one, n, allocated)
	skipAllocationBudgetUnderRace(t)
	if allocated > 4*one {
		t.Errorf("%d concurrent requests for one packument allocated %d bytes, more than 4 times the %d bytes of one request", n, allocated, one)
	}
}

func TestRepeatPackumentRequestsDoNotRewriteThePackument(t *testing.T) {
	srv, doc := bigProxy(t, 8<<10)
	packument := srv.URL + "/npm/big"
	first := sha256.New()
	if code, err := send(packument, "", first); err != nil || code != http.StatusOK {
		t.Fatalf("first packument request: status %d, error %v", code, err)
	}
	for i := range 5 {
		h := sha256.New()
		var code int
		var err error
		allocated := bytesAllocated(func() { code, err = send(packument, "", h) })
		if err != nil || code != http.StatusOK {
			t.Fatalf("repeat request %d: status %d, error %v", i, code, err)
		}
		if !bytes.Equal(h.Sum(nil), first.Sum(nil)) {
			t.Errorf("repeat response %d differs from the first", i)
		}
		t.Logf("repeat request %d allocated %d bytes, for a %d-byte packument", i, allocated, len(doc))
		if !raceEnabled && allocated > uint64(len(doc))/16 {
			t.Errorf("repeat request %d for a cached packument allocated %d bytes, more than a sixteenth of the %d-byte packument", i, allocated, len(doc))
		}
	}
}

func TestConcurrentManifestRequestsDoNotEachParseThePackument(t *testing.T) {
	srv, doc := bigProxy(t, 8<<10)
	manifest := srv.URL + "/npm/big/1.7.0"
	if code, err := send(manifest, "", io.Discard); err != nil || code != http.StatusOK {
		t.Fatalf("first manifest request: status %d, error %v", code, err)
	}
	one := bytesAllocated(func() { send(manifest, unusedHost(), io.Discard) })

	const n = 16
	burst, host := together(t, srv, n)+"/npm/big/1.7.0", unusedHost()
	allocated := bytesAllocated(func() {
		var wg sync.WaitGroup
		for range n {
			wg.Go(func() {
				if code, err := send(burst, host, io.Discard); err != nil || code != http.StatusOK {
					t.Errorf("status %d, error %v, want 200", code, err)
				}
			})
		}
		wg.Wait()
	})

	t.Logf("one manifest request allocated %d bytes, %d concurrent ones %d, for a %d-byte packument", one, n, allocated, len(doc))
	skipAllocationBudgetUnderRace(t)
	if extra := (allocated - min(allocated, one)) / (n - 1); extra > uint64(len(doc))/4 {
		t.Errorf("each of %d concurrent manifest requests beyond the first allocated %d bytes, more than a quarter of the %d-byte packument", n, extra, len(doc))
	}
}

func TestConcurrentPackumentRequestsKeepTheirOwnTarballLinks(t *testing.T) {
	srv, _ := bigProxy(t, 1<<10)
	packument := srv.URL + "/npm/big"
	hosts := []string{"a.example", "b.example"}
	var wg sync.WaitGroup
	for i := range 16 {
		host, other := hosts[i%2], hosts[(i+1)%2]
		wg.Go(func() {
			var body bytes.Buffer
			if code, err := send(packument, host, &body); err != nil || code != http.StatusOK {
				t.Errorf("status %d, error %v, want 200", code, err)
				return
			}
			if !bytes.Contains(body.Bytes(), []byte(`"tarball":"http://`+host+`/npm/big/-/big-1.0.0.tgz"`)) ||
				bytes.Contains(body.Bytes(), []byte(other)) {
				t.Errorf("a packument requested from %s does not link its tarballs there", host)
			}
		})
	}
	wg.Wait()
}

// everyRelease is an advisory that warns about every release of big.
var everyRelease = fakeSource{"big": {{ID: "GHSA-0000-0000-0000", Source: "osv", Kind: advisory.Vulnerability,
	Ecosystem: ecosystem.Npm, Ranges: []advisory.Range{{Introduced: "0"}}}}}

func heapAlloc() uint64 {
	var m runtime.MemStats
	// The second collection empties the sync.Pool victim caches the first
	// one filled.
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// heldWhileWaiting returns the heap that each of n concurrent packument
// requests holds while it waits for the shared rewrite, for a package with
// the given number of releases.
func heldWhileWaiting(t *testing.T, releases, n int) uint64 {
	srv, reg, _ := releasesProxy(t, releases, 0, everyRelease)
	packument := srv.URL + "/npm/big"
	if code, err := send(packument, "", io.Discard); err != nil || code != http.StatusOK {
		t.Fatalf("first packument request: status %d, error %v", code, err)
	}
	host := unusedHost()
	release := reg.HoldRewrites()
	before := heapAlloc()
	var wg sync.WaitGroup
	var failed atomic.Int32
	for range n {
		wg.Go(func() {
			if code, err := send(packument, host, io.Discard); err != nil || code != http.StatusOK {
				failed.Add(1)
				t.Errorf("status %d, error %v, want 200", code, err)
			}
		})
	}
	deadline := time.Now().Add(30 * time.Second)
	for reg.RewriteWaiters() < n && failed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	waiting := reg.RewriteWaiters()
	after := heapAlloc()
	release()
	wg.Wait()
	if waiting < n {
		t.Fatalf("%d of %d requests reached the rewrite", waiting, n)
	}
	return (after - min(after, before)) / uint64(n)
}

func TestRequestsWaitingForARewriteHoldMemoryIndependentOfReleaseCount(t *testing.T) {
	// macOS queues at most 128 connections that the server has not yet
	// accepted, and resets the rest.
	const n = 100
	few := heldWhileWaiting(t, 40, n)
	many := heldWhileWaiting(t, 20000, n)
	t.Logf("each of %d requests waiting for a rewrite held %d bytes for 40 releases, %d bytes for 20000", n, few, many)
	if extra := many - min(many, few); extra > 8<<10 {
		t.Errorf("each request waiting for a rewrite of a 20000-release package held %d bytes more than for 40 releases, want at most 8 KiB", extra)
	}
}

func TestTarballRequestAllocationIndependentOfReleaseCount(t *testing.T) {
	allocated := func(releases int) uint64 {
		srv, _, _ := releasesProxy(t, releases, 0, everyRelease)
		tarball := srv.URL + "/npm/big/-/big-1.7.0.tgz"
		if code, err := send(tarball, "", io.Discard); err != nil || code != http.StatusOK {
			t.Fatalf("first tarball request: status %d, error %v", code, err)
		}
		return bytesAllocated(func() { send(tarball, "", io.Discard) })
	}
	few, many := allocated(40), allocated(20000)
	t.Logf("one tarball request allocated %d bytes for 40 releases, %d bytes for 20000", few, many)
	skipAllocationBudgetUnderRace(t)
	if extra := many - min(many, few); extra > 64<<10 {
		t.Errorf("a tarball request for a 20000-release package allocated %d bytes more than for 40 releases, want at most 64 KiB", extra)
	}
}
