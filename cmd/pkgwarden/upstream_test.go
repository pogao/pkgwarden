package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pogao/pkgwarden/internal/telemetry/telemetrytest"
)

func TestUpstreamStaysOnOneHTTP2Connection(t *testing.T) {
	telemetrytest.CaptureLogs(t)
	// The fewest concurrent streams any upstream registry advertises.
	const serverStreams = 100
	var conns atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Millisecond)
		io.WriteString(w, "tarball")
	}))
	srv.EnableHTTP2 = true
	srv.Config.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: serverStreams}
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	client := &http.Client{Transport: newUpstreamTransport(&tls.Config{RootCAs: roots})}

	get := func() error {
		resp, err := client.Get(srv.URL)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		switch {
		case err != nil:
			return err
		case resp.ProtoMajor != 2:
			return fmt.Errorf("got %s, want HTTP/2", resp.Proto)
		case string(body) != "tarball":
			return fmt.Errorf("body %q", body)
		}
		return nil
	}
	if err := get(); err != nil {
		t.Fatal(err)
	}

	const clients, perClient = 4 * serverStreams, 5
	var (
		mu       sync.Mutex
		failures int
		firstErr error
		wg       sync.WaitGroup
	)
	for range clients {
		wg.Go(func() {
			for range perClient {
				if err := get(); err != nil {
					mu.Lock()
					failures++
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
				}
			}
		})
	}
	wg.Wait()
	if failures > 0 {
		t.Errorf("%d of %d requests failed, first: %v", failures, clients*perClient, firstErr)
	}
	if n := conns.Load(); n != 1 {
		t.Errorf("%d clients against a %d-stream server opened %d connections, want 1", clients, serverStreams, n)
	}
}
