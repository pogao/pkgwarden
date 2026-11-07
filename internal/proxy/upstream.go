// Package proxy holds the pieces shared by every ecosystem adapter: upstream
// HTTP access, policy enforcement responses, and the top-level server.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/pogao/pkgwarden/internal/cache"
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
		return b, nil
	}
	v, err, _ := u.group.Do(key, func() (any, error) {
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
	if err != nil {
		return nil, err
	}
	return v.([]byte), nil
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

// Relay copies an upstream response to w.
func Relay(w http.ResponseWriter, resp *http.Response) {
	for _, h := range relayHeaders {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// WriteError maps an upstream failure to a response.
func WriteError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
}
