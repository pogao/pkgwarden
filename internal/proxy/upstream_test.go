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
	u := NewUpstream(&http.Client{Transport: roundTripFunc(okResponse)}, "pkgwarden-test", time.Minute)

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
		})}, "pkgwarden-test", time.Minute)
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
		})}, "pkgwarden-test", time.Minute)
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
		})}, "pkgwarden-test", time.Minute)

		start := time.Now()
		_, err := u.Fetch(context.Background(), "https://registry.example/left-pad", nil)

		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != fetchTimeout {
			t.Errorf("hung fetch returned %v after %v, want a deadline error after %v", err, time.Since(start), fetchTimeout)
		}
	})
}
