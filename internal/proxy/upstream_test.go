package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pogao/pkgwarden/internal/telemetry"
	"github.com/pogao/pkgwarden/internal/telemetry/telemetrytest"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func okResponse(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
}

func TestFetchCountsCacheHitsAndLogsThem(t *testing.T) {
	const url = "https://registry.example/left-pad"
	hit := map[string]string{"cache": "metadata", "result": "hit"}
	miss := map[string]string{"cache": "metadata", "result": "miss"}
	hits, misses := telemetrytest.Value(t, "pkgwarden_cache_requests_total", hit), telemetrytest.Value(t, "pkgwarden_cache_requests_total", miss)
	logs := telemetrytest.CaptureLogs(t)
	u := NewUpstream(&http.Client{Transport: roundTripFunc(okResponse)}, "pkgwarden-test", time.Minute, 64<<20)

	for _, id := range []string{"first", "second"} {
		if _, err := u.Fetch(telemetry.WithRequestID(context.Background(), id), url, nil); err != nil {
			t.Fatal(err)
		}
	}

	if d := telemetrytest.Value(t, "pkgwarden_cache_requests_total", miss) - misses; d != 1 {
		t.Errorf("metadata misses grew by %v, want 1", d)
	}
	if d := telemetrytest.Value(t, "pkgwarden_cache_requests_total", hit) - hits; d != 1 {
		t.Errorf("metadata hits grew by %v, want 1", d)
	}
	lines := logs.Messages(t, "metadata cache hit")
	if len(lines) != 1 || lines[0]["url"] != url || lines[0]["request_id"] != "second" {
		t.Errorf("cache hit lines %v, want one for %s from request second", lines, url)
	}
}

func TestFetchLogsJoinedInFlightFetch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		calls := 0
		u := NewUpstream(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			<-release
			return okResponse(r)
		})}, "pkgwarden-test", time.Minute, 64<<20)
		logs := telemetrytest.CaptureLogs(t)

		var wg sync.WaitGroup
		for _, id := range []string{"a", "b"} {
			wg.Go(func() {
				if _, err := u.Fetch(telemetry.WithRequestID(context.Background(), id), "https://registry.example/left-pad", nil); err != nil {
					t.Error(err)
				}
			})
		}
		synctest.Wait()
		close(release)
		wg.Wait()

		if calls != 1 {
			t.Errorf("%d upstream calls, want 1 shared", calls)
		}
		if lines := logs.Messages(t, "joined in-flight fetch"); len(lines) != 1 {
			t.Errorf("joined lines %v, want exactly one", lines)
		}
	})
}

func TestFetchSurvivesCancelOfTheRequestThatStartedIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		u := NewUpstream(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			select {
			case <-release:
				return okResponse(r)
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		})}, "pkgwarden-test", time.Minute, 64<<20)
		const url = "https://registry.example/left-pad"

		leaderCtx, cancel := context.WithCancel(context.Background())
		leaderErr := make(chan error, 1)
		go func() {
			_, err := u.Fetch(leaderCtx, url, nil)
			leaderErr <- err
		}()
		synctest.Wait()
		var body []byte
		var err error
		done := make(chan struct{})
		go func() {
			body, err = u.Fetch(context.Background(), url, nil)
			close(done)
		}()
		synctest.Wait()
		cancel()
		synctest.Wait()
		select {
		case err := <-leaderErr:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("cancelled caller got %v, want context.Canceled", err)
			}
		default:
			t.Error("cancelled caller still waiting on the shared fetch")
		}
		close(release)
		<-done

		if err != nil || string(body) != `{}` {
			t.Errorf("joined fetch got %q, %v; want the body", body, err)
		}
	})
}

func TestFetchGivesUpOnAHungUpstream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		u := NewUpstream(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			return nil, r.Context().Err()
		})}, "pkgwarden-test", time.Minute, 64<<20)

		start := time.Now()
		_, err := u.Fetch(context.Background(), "https://registry.example/left-pad", nil)

		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != fetchTimeout {
			t.Errorf("hung fetch returned %v after %v, want a deadline error after %v", err, time.Since(start), fetchTimeout)
		}
	})
}

func TestFetchParsedSharesOneParseAndCachesIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		calls, parses := 0, 0
		u := NewUpstream(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			<-release
			return okResponse(r)
		})}, "pkgwarden-test", time.Minute, 64<<20)
		parse := func(b []byte) (string, int64, error) {
			parses++
			return "parsed " + string(b), int64(len(b)), nil
		}
		const url = "https://registry.example/left-pad"
		fetch := func() {
			if v, err := FetchParsed(context.Background(), u, url, nil, parse); err != nil || v != "parsed {}" {
				t.Errorf("FetchParsed = %q, %v; want the parsed body", v, err)
			}
		}

		var wg sync.WaitGroup
		for range 4 {
			wg.Go(fetch)
		}
		synctest.Wait()
		close(release)
		wg.Wait()
		fetch()

		if calls != 1 || parses != 1 {
			t.Errorf("%d upstream calls and %d parses for five fetches, want one of each", calls, parses)
		}
		if b, err := u.Fetch(context.Background(), url, nil); err != nil || string(b) != `{}` {
			t.Errorf("Fetch after FetchParsed = %q, %v; want the body", b, err)
		}
	})
}

func TestDocumentOverHalfTheCacheBudgetIsNotCached(t *testing.T) {
	bodies := map[string]string{"/small": `{}`, "/large": strings.Repeat("x", 600)}
	calls := map[string]int{}
	u := NewUpstream(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls[r.URL.Path]++
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(bodies[r.URL.Path]))}, nil
	})}, "pkgwarden-test", time.Minute, 1000)

	for _, path := range []string{"/small", "/large", "/small", "/large"} {
		if b, err := u.Fetch(context.Background(), "https://registry.example"+path, nil); err != nil || string(b) != bodies[path] {
			t.Fatalf("Fetch %s = %d bytes, %v", path, len(b), err)
		}
	}

	if calls["/small"] != 1 || calls["/large"] != 2 {
		t.Errorf("upstream calls %v, want the small document cached and the large one fetched each time", calls)
	}
}

func TestKeptValuesShareTheMetadataBudget(t *testing.T) {
	calls := 0
	u := NewUpstream(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return okResponse(r)
	})}, "pkgwarden-test", time.Minute, 1000)
	const url = "https://registry.example/left-pad"
	fetch := func() {
		if _, err := u.Fetch(context.Background(), url, nil); err != nil {
			t.Fatal(err)
		}
	}

	fetch()
	if _, ok := u.Kept(" " + url); ok {
		t.Error("Kept returned a fetched document")
	}
	u.Keep(" "+url, "derived", 100)
	fetch()
	if v, ok := u.Kept(" " + url); !ok || v != "derived" {
		t.Errorf("Kept = %v, %v; want the kept value", v, ok)
	}
	if calls != 1 {
		t.Errorf("%d upstream calls, want the document and the kept value cached side by side", calls)
	}
	u.Keep("huge", "derived", 600)
	if _, ok := u.Kept("huge"); ok {
		t.Error("kept a value weighing over half the metadata budget")
	}
}
