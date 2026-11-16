package connpool_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
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
		TLSClientConfig:   s.Client().Transport.(*http.Transport).TLSClientConfig.Clone(),
	}
}

// h2Server speaks just enough HTTP/2 to let a test send frames that
// net/http's own server sends only under races: a refused stream, or GOAWAY
// before a connection's first response.
type h2Server struct {
	*httptest.Server
	opened atomic.Int64
}

type h2Conn struct {
	n  int64 // 1 for the server's first connection
	mu sync.Mutex
	c  net.Conn
}

const (
	frameData     = 0x0
	frameHeaders  = 0x1
	frameRST      = 0x3
	frameSettings = 0x4
	framePing     = 0x6
	frameGoAway   = 0x7
	flagAck       = 0x1
	flagEndStream = 0x1
	flagEndHeader = 0x4
	refusedStream = 0x7
)

func (c *h2Conn) frame(typ, flags byte, stream uint32, payload []byte) {
	hdr := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), typ, flags}
	hdr = binary.BigEndian.AppendUint32(hdr, stream)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.c.Write(append(hdr, payload...))
}

// respond answers stream with :status 200 (HPACK static index 8) and no body.
func (c *h2Conn) respond(stream uint32) {
	c.frame(frameHeaders, flagEndStream|flagEndHeader, stream, []byte{0x88})
}

func serveH2(t *testing.T, onRequest func(c *h2Conn, stream uint32)) *h2Server {
	t.Helper()
	s := &h2Server{Server: httptest.NewUnstartedServer(http.NotFoundHandler())}
	s.TLS = &tls.Config{NextProtos: []string{"h2"}}
	s.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){
		"h2": func(_ *http.Server, tc *tls.Conn, _ http.Handler) {
			c := &h2Conn{n: s.opened.Add(1), c: tc}
			if _, err := io.ReadFull(tc, make([]byte, len("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))); err != nil {
				return
			}
			c.frame(frameSettings, 0, 0, binary.BigEndian.AppendUint32([]byte{0, 0x3}, streams))
			hdr := make([]byte, 9)
			for {
				if _, err := io.ReadFull(tc, hdr); err != nil {
					return
				}
				payload := make([]byte, int(hdr[0])<<16|int(hdr[1])<<8|int(hdr[2]))
				if _, err := io.ReadFull(tc, payload); err != nil {
					return
				}
				stream := binary.BigEndian.Uint32(hdr[5:]) &^ (1 << 31)
				switch typ, flags := hdr[3], hdr[4]; {
				case typ == frameSettings && flags&flagAck == 0:
					c.frame(frameSettings, flagAck, 0, nil)
				case typ == framePing && flags&flagAck == 0:
					c.frame(framePing, flagAck, 0, payload)
				case typ == frameHeaders:
					go onRequest(c, stream)
				}
			}
		},
	}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
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
		for range 50 {
			if err := getHTTP2(p, s.URL); err != nil {
				return err
			}
		}
		return nil
	})...)
	if err != nil {
		t.Errorf("200 requests to a server that closes each idle connection: %v", err)
	}
}

func TestStreamPastGOAWAYIsResentOnANewConnection(t *testing.T) {
	var requests atomic.Int64
	s := serveH2(t, func(c *h2Conn, stream uint32) {
		requests.Add(1)
		if c.n == 1 && stream > 1 {
			c.frame(frameGoAway, 0, 0, binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 1), 0))
			return
		}
		c.respond(stream)
	})
	p := connpool.New(base(s.Server))

	for i := range 2 {
		if err := getHTTP2(p, s.URL); err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
	}
	if got := requests.Load(); got != 3 {
		t.Errorf("server saw %d requests, want 3: the first, the second past GOAWAY, and its resend", got)
	}
	if got := s.opened.Load(); got != 2 {
		t.Errorf("opened %d connections, want 2", got)
	}
}

func TestRefusedStreamIsResent(t *testing.T) {
	var requests atomic.Int64
	s := serveH2(t, func(c *h2Conn, stream uint32) {
		if requests.Add(1) == 1 {
			c.frame(frameRST, 0, stream, binary.BigEndian.AppendUint32(nil, refusedStream))
			return
		}
		c.respond(stream)
	})
	p := connpool.New(base(s.Server))

	if err := getHTTP2(p, s.URL); err != nil {
		t.Fatalf("request whose first stream the server refused: %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Errorf("server saw %d requests, want 2, the refused one and its resend", got)
	}
}

func TestGOAWAYBeforeFirstResponseKeepsTheDialPlan(t *testing.T) {
	arrived := make(chan struct{})
	s := serveH2(t, func(c *h2Conn, stream uint32) {
		if c.n == 1 {
			close(arrived)
			c.frame(frameGoAway, 0, 0, binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, stream), 0))
			time.Sleep(100 * time.Millisecond)
			c.frame(frameHeaders, flagEndHeader, stream, []byte{0x88})
			time.Sleep(50 * time.Millisecond)
			c.frame(frameData, flagEndStream, stream, []byte("ok"))
			return
		}
		time.Sleep(20 * time.Millisecond)
		c.respond(stream)
	})
	p := connpool.New(base(s.Server))
	first := make(chan error, 1)
	go func() { first <- getHTTP2(p, s.URL) }()
	<-arrived

	const n = 100
	if err := errors.Join(burst(n, func() error { return getHTTP2(p, s.URL) })...); err != nil {
		t.Fatalf("burst of %d requests queued behind a connection that went away: %v", n, err)
	}
	if err := <-first; err != nil {
		t.Fatalf("first request, answered after GOAWAY: %v", err)
	}
	if got, want := s.opened.Load(), int64(1+(n+streams-1)/streams+1); got > want {
		t.Errorf("opened %d connections, want at most %d: the one that went away, then %d requests at %d streams each, plus one probing", got, want, n, streams)
	}
}
