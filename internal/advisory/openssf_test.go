package advisory

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pogao/pkgwarden/internal/ecosystem"
	"github.com/pogao/pkgwarden/internal/telemetry/telemetrytest"
)

// archive is a fake codeload endpoint whose tarball the test can swap.
type archive struct {
	mu       sync.Mutex
	body     []byte
	status   int
	requests int
}

func (a *archive) set(status int, body []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status, a.body = status, body
}

func (a *archive) RoundTrip(r *http.Request) (*http.Response, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.requests++
	if r.Header.Get("User-Agent") != "pkgwarden" {
		return &http.Response{StatusCode: http.StatusForbidden, Body: http.NoBody, Request: r}, nil
	}
	return &http.Response{StatusCode: a.status, Body: io.NopCloser(bytes.NewReader(a.body)), Request: r}, nil
}

func (a *archive) source() *OpenSSF {
	return NewOpenSSF(&http.Client{Transport: a}, "https://codeload.example/tar.gz/main")
}

func (a *archive) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.requests
}

func tarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "malicious-packages-main/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: "malicious-packages-main/" + name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func datasetFiles(t *testing.T) map[string]string {
	return map[string]string{
		"README.md": "# malicious packages",
		"osv/malicious/crates.io/rustdecimal/MAL-2022-1.json": string(fixture(t, "openssf_MAL-2022-1.json")),
		"osv/malicious/pypi/evil-pkg/MAL-2024-2.json": `{"id":"MAL-2024-2","summary":"Malicious code in Evil_Pkg (PyPI)",
			"affected":[{"package":{"name":"Evil_Pkg","ecosystem":"PyPI"},"versions":["1.0.0","1.0.1"]}]}`,
		"osv/withdrawn/npm/gone/MAL-2024-3.json": `{"id":"MAL-2024-3","withdrawn":"2024-02-01T00:00:00Z",
			"affected":[{"package":{"name":"gone","ecosystem":"npm"}}]}`,
		"osv/unmergable/npm/limbo/MAL-2024-5.json": `{"id":"MAL-2024-5",
			"affected":[{"package":{"name":"limbo","ecosystem":"npm"}}]}`,
		"osv/malicious/maven/x/MAL-2024-4.json": `{"id":"MAL-2024-4",
			"affected":[{"package":{"name":"org.example:x","ecosystem":"Maven"}}]}`,
	}
}

func TestOpenSSFLookupBeforeLoad(t *testing.T) {
	a := &archive{}
	if _, err := a.source().Lookup(context.Background(), ecosystem.Npm, "x"); err == nil {
		t.Error("Lookup before the first refresh succeeded, want an error")
	}
}

func TestOpenSSFRefresh(t *testing.T) {
	a := &archive{}
	a.set(http.StatusOK, tarball(t, datasetFiles(t)))
	src := a.source()
	ctx := context.Background()
	start := time.Now().Unix()
	if err := src.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if n := telemetrytest.Value(t, "pkgwarden_openssf_packages", nil); n != 2 {
		t.Errorf("pkgwarden_openssf_packages = %v, want 2 (rustdecimal and evil-pkg)", n)
	}
	if ts := telemetrytest.Value(t, "pkgwarden_openssf_last_success_timestamp_seconds", nil); ts < float64(start) {
		t.Errorf("pkgwarden_openssf_last_success_timestamp_seconds = %v, want at least %d", ts, start)
	}

	advs, err := src.Lookup(ctx, ecosystem.Cargo, "rustdecimal")
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 {
		t.Fatalf("got %d advisories, want 1", len(advs))
	}
	mal := advs[0]
	if mal.ID != "MAL-2022-1" || mal.Source != "openssf" || mal.Kind != Malicious ||
		mal.Summary != "Malicious code in rustdecimal (crates.io)" || mal.URL != "https://osv.dev/vulnerability/MAL-2022-1" {
		t.Errorf("unexpected advisory %+v", mal)
	}
	checkAffects(t, mal, []string{"0.0.1", "1.23.1"}, nil)

	advs, err = src.Lookup(ctx, ecosystem.PyPI, "evil.pkg")
	if err != nil || len(advs) != 1 {
		t.Fatalf("Lookup(evil.pkg) = %+v, %v; want the Evil_Pkg report", advs, err)
	}
	checkAffects(t, advs[0], []string{"1.0.0", "1.0.1"}, []string{"0.9", "1.0.2"})

	for _, q := range []struct {
		eco  ecosystem.Ecosystem
		name string
	}{{ecosystem.Npm, "gone"}, {ecosystem.Npm, "limbo"}, {ecosystem.Npm, "unknown"}, {ecosystem.Cargo, "rust_decimal"}} {
		if advs, err := src.Lookup(ctx, q.eco, q.name); err != nil || advs != nil {
			t.Errorf("Lookup(%s, %s) = %+v, %v; want nil, nil", q.eco, q.name, advs, err)
		}
	}
}

func TestOpenSSFFailedRefreshKeepsIndex(t *testing.T) {
	a := &archive{}
	good := tarball(t, datasetFiles(t))
	a.set(http.StatusOK, good)
	src := a.source()
	ctx := context.Background()
	if err := src.Refresh(ctx); err != nil {
		t.Fatal(err)
	}

	broken := datasetFiles(t)
	broken["osv/malicious/npm/new/MAL-2024-9.json"] = `{"id":"MAL-2024-9","affected":[{"package":{"name":"new","ecosystem":"npm"}}]}`
	broken["osv/malicious/npm/bad/MAL-2024-10.json"] = `{"id":`
	failures := map[string]struct {
		status int
		body   []byte
	}{
		"truncated archive": {http.StatusOK, good[:len(good)/2]},
		"invalid entry":     {http.StatusOK, tarball(t, broken)},
		"server error":      {http.StatusBadGateway, []byte("bad gateway")},
	}
	for name, f := range failures {
		a.set(f.status, f.body)
		if err := src.Refresh(ctx); err == nil {
			t.Errorf("%s: Refresh succeeded, want an error", name)
		}
		if advs, err := src.Lookup(ctx, ecosystem.Cargo, "rustdecimal"); err != nil || len(advs) != 1 {
			t.Errorf("%s: previous index lost: %+v, %v", name, advs, err)
		}
		if advs, _ := src.Lookup(ctx, ecosystem.Npm, "new"); advs != nil {
			t.Errorf("%s: partial index swapped in: %+v", name, advs)
		}
	}
}

func TestOpenSSFRun(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := &archive{}
		a.set(http.StatusOK, tarball(t, datasetFiles(t)))
		src := a.source()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			src.Run(ctx, time.Hour)
			close(done)
		}()

		synctest.Wait()
		if advs, err := src.Lookup(ctx, ecosystem.Cargo, "rustdecimal"); err != nil || len(advs) != 1 {
			t.Fatalf("after start: %+v, %v; want the dataset loaded immediately", advs, err)
		}

		next := datasetFiles(t)
		next["osv/malicious/npm/fresh/MAL-2024-11.json"] = `{"id":"MAL-2024-11","affected":[{"package":{"name":"fresh","ecosystem":"npm"}}]}`
		a.set(http.StatusOK, tarball(t, next))
		time.Sleep(time.Hour)
		synctest.Wait()
		if advs, err := src.Lookup(ctx, ecosystem.Npm, "fresh"); err != nil || len(advs) != 1 {
			t.Errorf("after one interval: %+v, %v; want the refreshed dataset", advs, err)
		}

		cancel()
		<-done
	})
}

func TestOpenSSFRunRetriesWithBackoff(t *testing.T) {
	failuresBefore := telemetrytest.Value(t, "pkgwarden_openssf_refresh_failures_total", nil)
	synctest.Test(t, func(t *testing.T) {
		a := &archive{}
		a.set(http.StatusBadGateway, []byte("bad gateway"))
		src := a.source()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			src.Run(ctx, time.Hour)
			close(done)
		}()
		defer func() {
			cancel()
			<-done
		}()
		synctest.Wait()
		if n := a.count(); n != 1 {
			t.Fatalf("%d downloads at start, want 1", n)
		}
		if d := telemetrytest.Value(t, "pkgwarden_openssf_refresh_failures_total", nil) - failuresBefore; d != 1 {
			t.Errorf("pkgwarden_openssf_refresh_failures_total grew by %v after one failed refresh, want 1", d)
		}

		// next waits gap and checks that exactly one more download happened
		// at its end and none before.
		next := func(gap time.Duration) {
			t.Helper()
			n := a.count()
			time.Sleep(gap - time.Second)
			synctest.Wait()
			if got := a.count(); got != n {
				t.Fatalf("download %d came before the %v wait was over", got, gap)
			}
			time.Sleep(time.Second)
			synctest.Wait()
			if got := a.count(); got != n+1 {
				t.Fatalf("%d downloads after waiting %v, want %d", got, gap, n+1)
			}
		}
		for _, gap := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute,
			8 * time.Minute, 16 * time.Minute, 32 * time.Minute, time.Hour, time.Hour} {
			next(gap)
		}
		if _, err := src.Lookup(ctx, ecosystem.Cargo, "rustdecimal"); err == nil {
			t.Fatal("Lookup succeeded before any download did")
		}

		a.set(http.StatusOK, tarball(t, datasetFiles(t)))
		next(time.Hour)
		if advs, err := src.Lookup(ctx, ecosystem.Cargo, "rustdecimal"); err != nil || len(advs) != 1 {
			t.Fatalf("after a successful retry: %+v, %v; want the dataset loaded", advs, err)
		}
		next(time.Hour)

		a.set(http.StatusBadGateway, []byte("bad gateway"))
		next(time.Hour)
		next(30 * time.Second)
	})
}
