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
	"strings"
	"sync"
	"testing"
	"time"

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

func bytesAllocated(f func()) uint64 {
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

// bigProxy returns the URL of a proxy whose upstream serves a
// largePackument of 2000 releases with pad bytes each as package big, and
// that packument.
func bigProxy(t *testing.T, pad int) (string, []byte) {
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
	doc = largePackument(t, upstream.URL, 2000, pad)
	engine := policy.New(policy.Config{Cooldown: week}, fakeSource(nil))
	reg := npm.New(npm.Options{
		Registry:  upstream.URL,
		Downloads: upstream.URL,
		Engine:    engine,
		HTTP:      proxy.NewUpstream(http.DefaultClient, "pkgwarden-test", time.Minute, 64<<20),
	})
	srv := httptest.NewServer(proxy.NewServer(engine, reg))
	t.Cleanup(srv.Close)
	return srv.URL, doc
}

func TestConcurrentTarballRequestsDoNotMultiplyPackumentMemory(t *testing.T) {
	proxyURL, doc := bigProxy(t, 8<<10)
	tarball := proxyURL + "/npm/big/-/big-1.7.0.tgz"
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

func TestConcurrentPackumentRequestsShareOneRewrite(t *testing.T) {
	proxyURL, _ := bigProxy(t, 8<<10)
	packument := proxyURL + "/npm/big"
	if code, err := send(packument, "", io.Discard); err != nil || code != http.StatusOK {
		t.Fatalf("first packument request: status %d, error %v", code, err)
	}
	lone := sha256.New()
	one := bytesAllocated(func() { send(packument, "", lone) })

	const n = 16
	sums := make([][]byte, n)
	allocated := bytesAllocated(func() {
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() {
				h := sha256.New()
				if code, err := send(packument, "", h); err != nil || code != http.StatusOK {
					t.Errorf("status %d, error %v, want 200", code, err)
				}
				sums[i] = h.Sum(nil)
			})
		}
		wg.Wait()
	})

	for i, sum := range sums {
		if !bytes.Equal(sum, lone.Sum(nil)) {
			t.Errorf("concurrent response %d differs from a lone request's", i)
		}
	}
	t.Logf("one packument request allocated %d bytes, %d concurrent ones %d", one, n, allocated)
	skipAllocationBudgetUnderRace(t)
	if allocated > 4*one {
		t.Errorf("%d concurrent requests for one packument allocated %d bytes, more than 4 times the %d bytes of one request", n, allocated, one)
	}
}

func TestConcurrentManifestRequestsDoNotEachParseThePackument(t *testing.T) {
	proxyURL, doc := bigProxy(t, 8<<10)
	manifest := proxyURL + "/npm/big/1.7.0"
	if code, err := send(manifest, "", io.Discard); err != nil || code != http.StatusOK {
		t.Fatalf("first manifest request: status %d, error %v", code, err)
	}
	one := bytesAllocated(func() { send(manifest, "", io.Discard) })

	const n = 16
	allocated := bytesAllocated(func() {
		var wg sync.WaitGroup
		for range n {
			wg.Go(func() {
				if code, err := send(manifest, "", io.Discard); err != nil || code != http.StatusOK {
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
	proxyURL, _ := bigProxy(t, 1<<10)
	packument := proxyURL + "/npm/big"
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
