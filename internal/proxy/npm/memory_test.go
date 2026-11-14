package npm_test

import (
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

func TestConcurrentTarballRequestsDoNotMultiplyPackumentMemory(t *testing.T) {
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
	doc = largePackument(t, upstream.URL, 2000, 8<<10)
	engine := policy.New(policy.Config{Cooldown: week}, fakeSource(nil))
	reg := npm.New(npm.Options{
		Registry:  upstream.URL,
		Downloads: upstream.URL,
		Engine:    engine,
		HTTP:      proxy.NewUpstream(http.DefaultClient, "pkgwarden-test", time.Minute, 64<<20),
	})
	srv := httptest.NewServer(proxy.NewServer(engine, reg))
	t.Cleanup(srv.Close)
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
	if allocated > uint64(len(doc)) {
		t.Errorf("%d concurrent tarball requests for a cached packument allocated %d bytes, more than the %d-byte packument itself", n, allocated, len(doc))
	}
}
