package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pogao/pkgwarden/internal/ecosystem"
)

// Middleware gives every request an ID, returns it in the X-Request-Id
// header, and puts it in the request context so that log lines about the
// request carry it. After next returns it logs one "request" line and
// records the request in the http_requests metrics. Requests for /metrics
// and /healthz log at debug, so scrapes and probes do not flood the log.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := requestID(r.Header.Get(requestIDHeader))
		w.Header().Set(requestIDHeader, id)
		ctx, release := untilClientLeaves(r.Context())
		defer release()
		ctx = WithRequestID(ctx, id)
		rec := &recorder{ResponseWriter: w, clientCtx: r.Context()}
		next.ServeHTTP(rec, r.WithContext(ctx))

		d := time.Since(start)
		rec.note(http.StatusOK)
		status := rec.status
		eco := routeEcosystem(r.URL.Path)
		httpRequests.WithLabelValues(eco, methodLabel(r.Method), strconv.Itoa(status)).Inc()
		httpDuration.WithLabelValues(eco).Observe(d.Seconds())

		level := slog.LevelInfo
		if r.URL.Path == "/metrics" || r.URL.Path == "/healthz" {
			level = slog.LevelDebug
		}
		attrs := []slog.Attr{
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", status),
			slog.Int64("bytes", rec.bytes),
			millis(d),
			slog.String("ecosystem", eco),
		}
		if decision := w.Header().Get("X-Pkgwarden-Decision"); decision != "" {
			attrs = append(attrs, slog.String("decision", decision))
		}
		attrs = append(attrs, slog.String("user_agent", r.UserAgent()), slog.String("remote_addr", r.RemoteAddr))
		slog.Default().LogAttrs(ctx, level, "request", attrs...)
	})
}

const statusClientClosedRequest = 499

var errClientLeft = fmt.Errorf("client closed the request: %w", context.Canceled)

// untilClientLeaves returns a context with the values of client that ends
// with the cause errClientLeft when client ends. A context derived from
// client would end with the cause net/http gives, a bare context.Canceled.
// release frees the context.
func untilClientLeaves(client context.Context) (ctx context.Context, release func()) {
	ctx, cancel := context.WithCancelCause(context.WithoutCancel(client))
	stop := context.AfterFunc(client, func() { cancel(errClientLeft) })
	return ctx, func() {
		stop()
		cancel(nil)
	}
}

// recorder notes the status and size of a response.
type recorder struct {
	http.ResponseWriter
	clientCtx context.Context
	status    int
	bytes     int64
}

func (r *recorder) note(code int) {
	if r.status != 0 {
		return
	}
	if r.clientCtx.Err() != nil {
		code = statusClientClosedRequest
	}
	r.status = code
}

func (r *recorder) WriteHeader(code int) {
	r.note(code)
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	r.note(http.StatusOK)
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// routeEcosystem labels a request path by the adapter it reaches.
func routeEcosystem(path string) string {
	seg, _, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	for _, e := range ecosystem.All() {
		if seg == string(e) {
			return seg
		}
	}
	if seg == "api" {
		return "api"
	}
	return "other"
}

// methodLabel bounds the method label, which a client controls.
func methodLabel(m string) string {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions, http.MethodConnect, http.MethodTrace:
		return m
	}
	return "other"
}

func millis(d time.Duration) slog.Attr {
	return slog.Float64("duration_ms", float64(d.Microseconds())/1000)
}

// Transport wraps base, or http.DefaultTransport when base is nil, so that
// every outbound request logs one "upstream" line with the request ID from
// its context and is recorded in the upstream_requests metrics. A request
// that got no response counts as code "canceled" when its context ended
// because the inbound client left, and as "error" otherwise. It logs no
// header values, because some carry credentials, and sends nothing extra
// upstream.
func Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return transport{base}
}

type transport struct{ base http.RoundTripper }

func (t transport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := t.base.RoundTrip(req)
	d := time.Since(start)

	host := req.URL.Host
	attrs := []slog.Attr{
		slog.String("method", req.Method),
		slog.String("host", host),
		slog.String("path", req.URL.Path),
	}
	code := "error"
	if err != nil {
		if errors.Is(context.Cause(req.Context()), errClientLeft) {
			code = "canceled"
		}
		attrs = append(attrs, slog.String("err", err.Error()))
	} else {
		code = strconv.Itoa(resp.StatusCode)
		attrs = append(attrs, slog.Int("status", resp.StatusCode))
		if resp.ContentLength >= 0 {
			attrs = append(attrs, slog.Int64("content_length", resp.ContentLength))
		}
	}
	attrs = append(attrs, millis(d))
	upstreamRequests.WithLabelValues(host, code).Inc()
	upstreamDuration.WithLabelValues(host).Observe(d.Seconds())
	slog.Default().LogAttrs(req.Context(), slog.LevelInfo, "upstream", attrs...)
	return resp, err
}
