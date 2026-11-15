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

func TestMetricsRoute(t *testing.T) {
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/npm/left-pad" {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		http.NotFound(w, r)
	})
	get := func(h http.Handler, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec
	}
	isMetrics := func(rec *httptest.ResponseRecorder) bool {
		return rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "pkgwarden_build_info{")
	}

	t.Run("main listener serves /metrics by default", func(t *testing.T) {
		main, metrics := handlers(app, false)
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
		main, metrics := handlers(app, true)
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
	client := upstreamClient(srv.Client().Transport.(*http.Transport).TLSClientConfig)
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
