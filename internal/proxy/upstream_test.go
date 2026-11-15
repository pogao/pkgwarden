package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pogao/pkgwarden/internal/proxy/proxytest"
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

func relayServer(t *testing.T, writeTimeout time.Duration, upstream http.Handler) *httptest.Server {
	t.Helper()
	old := relayWriteTimeout
	relayWriteTimeout = writeTimeout
	t.Cleanup(func() { relayWriteTimeout = old })
	telemetrytest.CaptureLogs(t)
	up := httptest.NewServer(upstream)
	t.Cleanup(up.Close)
	srv := httptest.NewServer(telemetry.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := up.Client().Get(up.URL + r.URL.Path)
		if err != nil {
			WriteError(w, err)
			return
		}
		defer resp.Body.Close()
		Relay(w, r, resp)
	})))
	t.Cleanup(srv.Close)
	return srv
}

func dial(t *testing.T, srv *httptest.Server) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func send(t *testing.T, conn net.Conn, method, path string) {
	t.Helper()
	if _, err := fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: pkgwarden.test\r\n\r\n", method, path); err != nil {
		t.Fatal(err)
	}
}

func TestRelayDropsAClientThatStopsReading(t *testing.T) {
	file := proxytest.NewFile()
	file.Size = 64 << 20
	conn := dial(t, relayServer(t, 500*time.Millisecond, file))

	start := time.Now()
	send(t, conn, http.MethodGet, "/file")
	n := file.Written(t)

	if d := time.Since(start); d > relayWriteTimeout+3*time.Second {
		t.Errorf("the upstream transfer ended %v after the client stopped reading, want about %v", d, relayWriteTimeout)
	}
	if n == file.Size {
		t.Errorf("upstream sent all %d bytes to a client that read none, want the transfer cut short", n)
	}
}

func TestRelayKeepsAClientThatReadsSlowly(t *testing.T) {
	file := proxytest.NewFile()
	srv := relayServer(t, 500*time.Millisecond, file)

	start := time.Now()
	resp, err := srv.Client().Get(srv.URL + "/file")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got int64
	for {
		n, err := io.CopyN(io.Discard, resp.Body, 256<<10)
		got += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read %d of %d bytes in %v, then: %v", got, file.Size, time.Since(start), err)
		}
		time.Sleep(relayWriteTimeout / 5)
	}

	if got != int64(file.Size) {
		t.Errorf("read %d of %d bytes", got, file.Size)
	}
	if n := file.Written(t); n != file.Size {
		t.Errorf("upstream sent %d of %d bytes", n, file.Size)
	}
}

func TestRelayLeavesTheNextResponseOnTheConnectionAlone(t *testing.T) {
	srv := relayServer(t, 200*time.Millisecond, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "relayed")
	}))
	conn := dial(t, srv)
	br := bufio.NewReader(conn)

	send(t, conn, http.MethodGet, "/file")
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if body, err := io.ReadAll(resp.Body); err != nil || string(body) != "relayed" {
		t.Fatalf("GET = %q, %v; want %q", body, err, "relayed")
	}
	time.Sleep(2 * relayWriteTimeout)
	send(t, conn, http.MethodHead, "/file")
	resp, err = http.ReadResponse(br, &http.Request{Method: http.MethodHead})
	if err != nil {
		t.Fatalf("HEAD %v after a GET on the same connection: %v", 2*relayWriteTimeout, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HEAD %v after a GET on the same connection: status %d, want 200", 2*relayWriteTimeout, resp.StatusCode)
	}
}
