package connpool_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pogao/pkgwarden/internal/connpool"
)

const streams = 4

type server struct {
	*httptest.Server
	opened, closed atomic.Int64
}

func serve(t *testing.T, h2 bool, h http.Handler) *server {
	t.Helper()
	s := &server{Server: httptest.NewUnstartedServer(h)}
	s.EnableHTTP2 = h2
	s.Config.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: streams}
	s.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		switch st {
		case http.StateNew:
			s.opened.Add(1)
		case http.StateClosed:
			s.closed.Add(1)
		}
	}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func respondAfter(d time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(d)
		io.WriteString(w, "tarball")
	})
}

func base(s *httptest.Server) *http.Transport {
	return &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   s.Client().Transport.(*http.Transport).TLSClientConfig,
	}
}

func get(ctx context.Context, rt http.RoundTripper, url string) (proto int, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	return resp.ProtoMajor, err
}

func burst(n int, f func() error) []error {
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { errs[i] = f() })
	}
	wg.Wait()
	return errs
}

func getHTTP2(rt http.RoundTripper, url string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	proto, err := get(ctx, rt, url)
	if err == nil && proto != 2 {
		err = errors.New("response over HTTP/1, want HTTP/2")
	}
	return err
}

func TestColdBurstOpensOnlyTheConnectionsItNeeds(t *testing.T) {
	s := serve(t, true, respondAfter(20*time.Millisecond))
	p := connpool.New(base(s.Server))

	const n = 100
	if err := errors.Join(burst(n, func() error { return getHTTP2(p, s.URL) })...); err != nil {
		t.Fatalf("cold burst of %d requests: %v", n, err)
	}
	if got := s.opened.Load(); got > n/streams {
		t.Errorf("opened %d connections for %d concurrent requests at %d streams each, want at most %d", got, n, streams, n/streams)
	}
	if got := s.closed.Load(); got != 0 {
		t.Errorf("closed %d connections during the burst, want 0", got)
	}
}

func TestPlainHTTPGoesThroughBase(t *testing.T) {
	s := httptest.NewServer(respondAfter(5 * time.Millisecond))
	defer s.Close()
	p := connpool.New(&http.Transport{ForceAttemptHTTP2: true})

	if err := errors.Join(burst(20, func() error { _, err := get(context.Background(), p, s.URL); return err })...); err != nil {
		t.Fatalf("20 concurrent plain http requests: %v", err)
	}
}

func TestHTTP1OverTLSFallsBackToBase(t *testing.T) {
	s := serve(t, false, respondAfter(5*time.Millisecond))
	p := connpool.New(base(s.Server))
	getHTTP1 := func() error {
		proto, err := get(context.Background(), p, s.URL)
		if err == nil && proto != 1 {
			err = errors.New("response over HTTP/2, want HTTP/1")
		}
		return err
	}

	if err := errors.Join(burst(20, getHTTP1)...); err != nil {
		t.Fatalf("20 concurrent requests to an HTTP/1 server: %v", err)
	}
	opened := s.opened.Load()
	for range 5 {
		if err := getHTTP1(); err != nil {
			t.Fatalf("request after the burst: %v", err)
		}
	}
	if got := s.opened.Load() - opened; got != 0 {
		t.Errorf("5 requests after the burst opened %d connections, want 0 because base keeps its idle ones", got)
	}
}

func TestCancelWhileWaitingLeaksNoStream(t *testing.T) {
	arrived, gate := make(chan struct{}), make(chan struct{})
	var first atomic.Bool
	s := serve(t, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if first.CompareAndSwap(false, true) {
			close(arrived)
			select {
			case <-gate:
			case <-r.Context().Done():
			}
		} else {
			time.Sleep(20 * time.Millisecond)
		}
		io.WriteString(w, "ok")
	}))
	p := connpool.New(base(s.Server))
	probe := make(chan error, 1)
	go func() { probe <- getHTTP2(p, s.URL) }()
	<-arrived

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	for _, err := range burst(50, func() error { _, err := get(ctx, p, s.URL); return err }) {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("request queued behind the first connection's first response got %v, want its deadline", err)
		}
	}
	close(gate)
	if err := <-probe; err != nil {
		t.Fatalf("first request: %v", err)
	}
	if err := errors.Join(burst(streams, func() error { return getHTTP2(p, s.URL) })...); err != nil {
		t.Fatalf("%d concurrent requests after the cancellations: %v", streams, err)
	}
	if got := s.opened.Load(); got != 1 {
		t.Errorf("opened %d connections, want 1, whose %d streams no cancelled request kept", got, streams)
	}
}

func TestDialErrorReachesEveryWaiter(t *testing.T) {
	s := serve(t, true, respondAfter(0))
	p := connpool.New(base(s.Server))
	s.Close()

	for _, err := range burst(50, func() error { return getHTTP2(p, s.URL) }) {
		if err == nil || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("request to a closed server got %v, want the dial error", err)
		}
	}
}

func TestIdleConnectionsCloseAndRedial(t *testing.T) {
	s := serve(t, true, respondAfter(5*time.Millisecond))
	tr := base(s.Server)
	tr.IdleConnTimeout = 100 * time.Millisecond
	p := connpool.New(tr)

	if err := errors.Join(burst(40, func() error { return getHTTP2(p, s.URL) })...); err != nil {
		t.Fatalf("burst of 40 requests: %v", err)
	}
	for deadline := time.Now().Add(5 * time.Second); s.closed.Load() < s.opened.Load(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d connections still open 5 s after the 100 ms idle timeout", s.opened.Load()-s.closed.Load(), s.opened.Load())
		}
	}
	opened := s.opened.Load()
	if err := getHTTP2(p, s.URL); err != nil {
		t.Fatalf("request after every connection idled out: %v", err)
	}
	if got := s.opened.Load() - opened; got != 1 {
		t.Errorf("request after every connection idled out opened %d connections, want 1", got)
	}
}

// With keep-alives off, net/http's HTTP/2 server sends GOAWAY each time a
// connection goes idle.
func TestServerGOAWAYRaceIsResent(t *testing.T) {
	s := serve(t, true, respondAfter(0))
	s.Config.SetKeepAlivesEnabled(false)
	p := connpool.New(base(s.Server))

	err := errors.Join(burst(4, func() error {
		for range 200 {
			if err := getHTTP2(p, s.URL); err != nil {
				return err
			}
		}
		return nil
	})...)
	if err != nil {
		t.Errorf("800 requests to a server that closes each idle connection: %v", err)
	}
}
