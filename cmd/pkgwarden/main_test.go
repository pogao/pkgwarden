package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pogao/pkgwarden/internal/telemetry/telemetrytest"
)

func get(h http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec
}

func TestMetricsRoute(t *testing.T) {
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/npm/left-pad" {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		http.NotFound(w, r)
	})
	isMetrics := func(rec *httptest.ResponseRecorder) bool {
		return rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "pkgwarden_build_info{")
	}

	t.Run("main listener serves /metrics by default", func(t *testing.T) {
		main, metrics := handlers(app, false, 0)
		if metrics != nil {
			t.Error("got a metrics listener handler without -metrics-listen")
		}
		if rec := get(main, "/metrics"); !isMetrics(rec) {
			t.Errorf("GET /metrics: status %d, body without pkgwarden_build_info", rec.Code)
		}
		if rec := get(main, "/npm/left-pad"); rec.Code != http.StatusTeapot {
			t.Errorf("GET /npm/left-pad: status %d, want the app's 418", rec.Code)
		}
	})

	t.Run("-metrics-listen moves /metrics off the main listener", func(t *testing.T) {
		main, metrics := handlers(app, true, 0)
		if rec := get(main, "/metrics"); rec.Code != http.StatusNotFound {
			t.Errorf("main GET /metrics: status %d, want 404", rec.Code)
		}
		if rec := get(main, "/npm/left-pad"); rec.Code != http.StatusTeapot {
			t.Errorf("main GET /npm/left-pad: status %d, want the app's 418", rec.Code)
		}
		if metrics == nil {
			t.Fatal("no metrics listener handler")
		}
		if rec := get(metrics, "/metrics"); !isMetrics(rec) {
			t.Errorf("metrics GET /metrics: status %d, body without pkgwarden_build_info", rec.Code)
		}
		if rec := get(metrics, "/npm/left-pad"); rec.Code != http.StatusNotFound {
			t.Errorf("metrics GET /npm/left-pad: status %d, want 404", rec.Code)
		}
	})
}

const (
	inFlightMetric = "pkgwarden_http_requests_in_flight"
	refusedMetric  = "pkgwarden_http_requests_refused_total"
)

// holdRequests starts n requests for /npm/slow on the main handler built
// with maxInFlight, and returns once the app holds all of them. release
// lets them finish and returns their status codes.
func holdRequests(t *testing.T, maxInFlight, n int) (main http.Handler, release func() []int) {
	t.Helper()
	started := make(chan struct{})
	hold := make(chan struct{})
	app := http.NewServeMux()
	app.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok\n"))
	})
	app.HandleFunc("GET /npm/{name}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("name") == "slow" {
			started <- struct{}{}
			<-hold
		}
		w.Write([]byte("ok\n"))
	})
	main, _ = handlers(app, false, maxInFlight)

	var done []chan int
	for range n {
		d := make(chan int, 1)
		done = append(done, d)
		go func() { d <- get(main, "/npm/slow").Code }()
		select {
		case <-started:
		case code := <-d:
			t.Fatalf("GET /npm/slow: status %d before the app held it", code)
		}
	}
	unhold := sync.OnceFunc(func() { close(hold) })
	t.Cleanup(unhold)
	return main, func() []int {
		unhold()
		codes := make([]int, n)
		for i, d := range done {
			codes[i] = <-d
		}
		return codes
	}
}

func TestMaxInFlightLimit(t *testing.T) {
	t.Run("refuses requests past the limit", func(t *testing.T) {
		code503 := map[string]string{"ecosystem": "npm", "method": "GET", "code": "503"}
		inFlight := telemetrytest.Value(t, inFlightMetric, nil)
		refused := telemetrytest.Value(t, refusedMetric, nil)
		finished503 := telemetrytest.Value(t, "pkgwarden_http_requests_total", code503)
		main, release := holdRequests(t, 2, 2)

		rec := get(main, "/npm/left-pad")
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("GET /npm/left-pad at the limit: status %d, want 503", rec.Code)
		}
		if got := rec.Header().Get("Retry-After"); got != "1" {
			t.Errorf("Retry-After = %q, want 1", got)
		}
		if got := rec.Header().Get("Connection"); got != "close" {
			t.Errorf("Connection = %q, want close", got)
		}
		if rec.Header().Get("X-Request-Id") == "" {
			t.Error("the 503 has no X-Request-Id")
		}
		if rec := get(main, "/healthz"); rec.Code != http.StatusOK {
			t.Errorf("GET /healthz at the limit: status %d, want 200", rec.Code)
		}
		if rec := get(main, "/metrics"); rec.Code != http.StatusOK {
			t.Errorf("GET /metrics at the limit: status %d, want 200", rec.Code)
		}
		if got := telemetrytest.Value(t, inFlightMetric, nil) - inFlight; got != 2 {
			t.Errorf("%s rose by %v, want 2", inFlightMetric, got)
		}
		if got := telemetrytest.Value(t, refusedMetric, nil) - refused; got != 1 {
			t.Errorf("%s rose by %v, want 1", refusedMetric, got)
		}
		if got := telemetrytest.Value(t, "pkgwarden_http_requests_total", code503) - finished503; got != 1 {
			t.Errorf("pkgwarden_http_requests_total{code=\"503\"} rose by %v, want 1", got)
		}

		for _, code := range release() {
			if code != http.StatusOK {
				t.Errorf("held GET /npm/slow: status %d, want 200", code)
			}
		}
		if rec := get(main, "/npm/left-pad"); rec.Code != http.StatusOK {
			t.Errorf("GET /npm/left-pad after the held requests finished: status %d, want 200", rec.Code)
		}
		if got := telemetrytest.Value(t, inFlightMetric, nil); got != inFlight {
			t.Errorf("%s = %v after every request finished, want %v", inFlightMetric, got, inFlight)
		}
	})

	t.Run("0 counts requests without a limit", func(t *testing.T) {
		inFlight := telemetrytest.Value(t, inFlightMetric, nil)
		refused := telemetrytest.Value(t, refusedMetric, nil)
		_, release := holdRequests(t, 0, 3)

		if got := telemetrytest.Value(t, inFlightMetric, nil) - inFlight; got != 3 {
			t.Errorf("%s rose by %v, want 3", inFlightMetric, got)
		}
		for _, code := range release() {
			if code != http.StatusOK {
				t.Errorf("held GET /npm/slow: status %d, want 200", code)
			}
		}
		if got := telemetrytest.Value(t, refusedMetric, nil) - refused; got != 0 {
			t.Errorf("%s rose by %v, want 0", refusedMetric, got)
		}
	})
}

func TestUpstreamBurstPastStreamLimitKeepsEveryConnection(t *testing.T) {
	const streams, burst = 4, 100
	var opened, closed atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		io.WriteString(w, "tarball")
	}))
	srv.EnableHTTP2 = true
	srv.Config.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: streams}
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		switch s {
		case http.StateNew:
			opened.Add(1)
		case http.StateClosed:
			closed.Add(1)
		}
	}
	srv.StartTLS()
	defer srv.Close()
	telemetrytest.CaptureLogs(t)
	client := upstreamClient(srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone())
	get := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.ProtoMajor != 2 {
			return fmt.Errorf("got %s, want HTTP/2", resp.Proto)
		}
		_, err = io.Copy(io.Discard, resp.Body)
		return err
	}

	if err := get(); err != nil {
		t.Fatalf("warm-up request: %v", err)
	}
	errs := make([]error, burst)
	var wg sync.WaitGroup
	for i := range burst {
		wg.Go(func() { errs[i] = get() })
	}
	wg.Wait()

	if err := errors.Join(errs...); err != nil {
		t.Errorf("burst of %d requests: %v", burst, err)
	}
	if got, want := opened.Load(), int64(burst/streams); got > want {
		t.Errorf("opened %d connections for %d concurrent requests at %d streams each, want at most %d", got, burst, streams, want)
	}
	if got := closed.Load(); got != 0 {
		t.Errorf("closed %d connections during the burst, want 0", got)
	}
}
