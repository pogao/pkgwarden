package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
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

func TestUpstreamGivesSlotsBack(t *testing.T) {
	telemetrytest.CaptureLogs(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fail" {
			panic(http.ErrAbortHandler)
		}
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	exceedSlots := func(t *testing.T, path string, finish func(*http.Response, error) error) {
		client := &http.Client{Transport: newUpstreamTransport(nil)}
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		get := func(path string) (*http.Response, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
			if err != nil {
				return nil, err
			}
			return client.Do(req)
		}
		for i := range maxUpstreamStreams + 1 {
			if err := finish(get(path)); err != nil {
				t.Fatalf("GET %s #%d: %v", path, i+1, err)
			}
		}
		resp, err := get("/ok")
		if err != nil {
			t.Fatalf("GET /ok after %d of GET %s: %v", maxUpstreamStreams+1, path, err)
		}
		resp.Body.Close()
	}

	t.Run("failed round trip", func(t *testing.T) {
		exceedSlots(t, "/fail", func(resp *http.Response, err error) error {
			if err == nil {
				resp.Body.Close()
				return errors.New("succeeded")
			}
			return nil
		})
	})
	t.Run("body read to its end and never closed", func(t *testing.T) {
		exceedSlots(t, "/ok", func(resp *http.Response, err error) error {
			if err != nil {
				return err
			}
			_, err = io.ReadAll(resp.Body)
			return err
		})
	})
	t.Run("body closed unread", func(t *testing.T) {
		exceedSlots(t, "/ok", func(resp *http.Response, err error) error {
			if err != nil {
				return err
			}
			return resp.Body.Close()
		})
	})
}

func TestUpstreamQueuedRequestGivesUpWithItsContext(t *testing.T) {
	telemetrytest.CaptureLogs(t)
	release := make(chan struct{})
	var holding sync.WaitGroup
	holding.Add(maxUpstreamStreams)
	var queuedArrived atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hold":
			holding.Done()
			<-release
		case "/queued":
			queuedArrived.Store(true)
		}
	}))
	defer srv.Close()
	client := &http.Client{Transport: newUpstreamTransport(nil)}
	get := func(ctx context.Context, path string) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}

	var held sync.WaitGroup
	for range maxUpstreamStreams {
		held.Go(func() {
			if err := get(t.Context(), "/hold"); err != nil {
				t.Errorf("GET /hold: %v", err)
			}
		})
	}
	holding.Wait()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	queued := make(chan error, 1)
	go func() { queued <- get(ctx, "/queued") }()
	select {
	case err := <-queued:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("GET /queued with every slot held: %v, want %v", err, context.DeadlineExceeded)
		}
	case <-time.After(5 * time.Second):
		t.Error("GET /queued kept waiting for a slot after its context ended")
	}
	close(release)
	held.Wait()
	if queuedArrived.Load() {
		t.Error("GET /queued reached the server while every slot was held")
	}
}
