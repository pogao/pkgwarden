// Package proxy holds the pieces shared by every ecosystem adapter: upstream
// HTTP access, policy enforcement responses, and the top-level server.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/pogao/pkgwarden/internal/cache"
	"github.com/pogao/pkgwarden/internal/telemetry"
)

// ErrNotFound reports that the upstream registry has no such resource.
var ErrNotFound = errors.New("not found upstream")

// StatusError is an unexpected upstream HTTP status.
type StatusError struct {
	URL    string
	Status int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("GET %s: unexpected status %d", e.URL, e.Status)
}

const maxMetadataBytes = 128 << 20

// fetchTimeout bounds a shared metadata fetch, body included.
const fetchTimeout = 2 * time.Minute

// DownloadsTimeout bounds a download-count lookup, which only feeds
// heuristics and must not stall an install when the stats API is slow. A
// lookup that runs out of time counts as policy.UnknownDownloads.
const DownloadsTimeout = 5 * time.Second

// Upstream fetches from upstream registries. Metadata fetched through Fetch
// is cached briefly and concurrent identical requests share one round trip.
// Artifacts go through Open and are never cached, and neither are POSTs.
type Upstream struct {
	client    *http.Client
	userAgent string
	meta      *cache.TTL[string, []byte]
	group     singleflight.Group
}

// NewUpstream returns an Upstream that caches metadata for metaTTL.
func NewUpstream(client *http.Client, userAgent string, metaTTL time.Duration) *Upstream {
	return &Upstream{client: client, userAgent: userAgent, meta: cache.New[string, []byte](metaTTL, 512)}
}

// Fetch returns the body of a metadata document. A 404 or 410 yields ErrNotFound.
func (u *Upstream) Fetch(ctx context.Context, url string, header http.Header) ([]byte, error) {
	key := header.Get("Accept") + " " + url
	if b, ok := u.meta.Get(key); ok {
		telemetry.RecordCache("metadata", true)
		slog.DebugContext(ctx, "metadata cache hit", "url", url)
		return b, nil
	}
	telemetry.RecordCache("metadata", false)
	fetched := false
	ch := u.group.DoChan(key, func() (any, error) {
		fetched = true
		// The fetch is shared, so it must outlive the request that started
		// it. WithoutCancel keeps that request's ID for the upstream log line.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout)
		defer cancel()
		resp, err := u.Open(ctx, url, header)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
			return nil, fmt.Errorf("GET %s: %w", url, ErrNotFound)
		case resp.StatusCode != http.StatusOK:
			return nil, &StatusError{URL: url, Status: resp.StatusCode}
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes))
		if err != nil {
			return nil, fmt.Errorf("GET %s: %w", url, err)
		}
		u.meta.Set(key, b)
		return b, nil
	})
	var res singleflight.Result
	select {
	case res = <-ch:
	case <-ctx.Done():
		return nil, fmt.Errorf("GET %s: %w", url, ctx.Err())
	}
	if !fetched {
		// The upstream line for this fetch carries the request ID of the
		// request that started it.
		slog.DebugContext(ctx, "joined in-flight fetch", "url", url)
	}
	if res.Err != nil {
		return nil, res.Err
	}
	return res.Val.([]byte), nil
}

// FetchJSON fetches a metadata document and decodes it into v.
func (u *Upstream) FetchJSON(ctx context.Context, url string, v any) error {
	b, err := u.Fetch(ctx, url, http.Header{"Accept": {"application/json"}})
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("decode %s: %w", url, err)
	}
	return nil
}

// Open issues an uncached GET and returns the response whatever its status.
// The caller closes the body.
func (u *Upstream) Open(ctx context.Context, url string, header http.Header) (*http.Response, error) {
	return u.send(ctx, http.MethodGet, url, header, nil)
}

// Post sends body in a POST and returns the response whatever its status.
// The caller closes the body.
func (u *Upstream) Post(ctx context.Context, url string, header http.Header, body io.Reader) (*http.Response, error) {
	return u.send(ctx, http.MethodPost, url, header, body)
}

func (u *Upstream) send(ctx context.Context, method, url string, header http.Header, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	for k, vs := range header {
		req.Header[k] = vs
	}
	req.Header.Set("User-Agent", u.userAgent)
	return u.client.Do(req)
}

var relayHeaders = []string{
	"Content-Type", "Content-Length", "Content-Encoding", "Content-Range", "Accept-Ranges",
	"ETag", "Last-Modified", "Cache-Control", "Repr-Digest", "Digest",
}

// Relay copies an upstream response to w, without the body when req is a
// HEAD request.
func Relay(w http.ResponseWriter, req *http.Request, resp *http.Response) {
	relay(w, req, resp)
}

// ServeArtifact relays an upstream response carrying a release's file and,
// when upstream answered 200 or 206 to a request that is not a HEAD, counts
// the file and the bytes copied in the artifact metrics.
func ServeArtifact(w http.ResponseWriter, req *http.Request, s Subject, resp *http.Response) {
	n, err := relay(w, req, resp)
	if req.Method == http.MethodHead || resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return
	}
	telemetry.RecordArtifact(string(s.Ecosystem), n)
	if err != nil {
		slog.WarnContext(req.Context(), "artifact relay interrupted", "ecosystem", string(s.Ecosystem), "package", s.Name,
			"version", s.Version, "bytes", n, "err", err)
	}
}

func relay(w http.ResponseWriter, req *http.Request, resp *http.Response) (int64, error) {
	for _, h := range relayHeaders {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	// net/http discards a HEAD response body, so copying it would download
	// the whole file for nothing. The caller closes the unread body, which
	// ends the upstream transfer.
	if req.Method == http.MethodHead {
		return 0, nil
	}
	return io.Copy(w, resp.Body)
}

// WriteError maps an upstream failure to a response.
func WriteError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
}
