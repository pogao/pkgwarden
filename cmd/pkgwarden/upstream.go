package main

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/pogao/pkgwarden/internal/telemetry"
)

// Past an HTTP/2 connection's stream limit, net/http dials a new connection
// for each extra request and usually closes it unused (#55). Its own remedy,
// StrictMaxConcurrentRequests, hangs requests on Go 1.27. Every upstream
// advertises at least 100 streams.
const maxUpstreamStreams = 100

func newUpstreamTransport(tlsConfig *tls.Config) http.RoundTripper {
	return &hostLimiter{
		base: telemetry.Transport(&http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSClientConfig:       tlsConfig,
			ForceAttemptHTTP2:     true,
			MaxIdleConnsPerHost:   32,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
		}),
		slots: map[string]chan struct{}{},
	}
}

type hostLimiter struct {
	base  http.RoundTripper
	mu    sync.Mutex
	slots map[string]chan struct{}
}

func (l *hostLimiter) RoundTrip(req *http.Request) (*http.Response, error) {
	l.mu.Lock()
	slots, ok := l.slots[req.URL.Host]
	if !ok {
		slots = make(chan struct{}, maxUpstreamStreams)
		l.slots[req.URL.Host] = slots
	}
	l.mu.Unlock()
	select {
	case slots <- struct{}{}:
	case <-req.Context().Done():
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, req.Context().Err()
	}
	resp, err := l.base.RoundTrip(req)
	if err != nil {
		<-slots
		return resp, err
	}
	resp.Body = &slotBody{ReadCloser: resp.Body, slots: slots}
	return resp, nil
}

// slotBody closes itself when a read fails, before it gives its slot back,
// because net/http can return io.EOF from an HTTP/2 body while it still
// counts the stream against the connection's limit. Close waits until it
// does not.
type slotBody struct {
	io.ReadCloser
	slots   chan struct{}
	release sync.Once
	readErr error
}

func (b *slotBody) Read(p []byte) (int, error) {
	if b.readErr != nil {
		return 0, b.readErr
	}
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.readErr = err
		b.Close()
	}
	return n, err
}

func (b *slotBody) Close() error {
	err := b.ReadCloser.Close()
	b.release.Do(func() { <-b.slots })
	return err
}
