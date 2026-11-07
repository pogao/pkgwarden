package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
)

// RequestIDHeader carries the request ID in to the proxy, when a load
// balancer or client sets it, and back out on every response.
const RequestIDHeader = "X-Request-Id"

type requestIDKey struct{}

// WithRequestID returns a context carrying id.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestID returns the request ID ctx carries, or "".
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// requestID keeps an inbound ID that is safe to echo into headers and logs,
// and otherwise makes a new one.
func requestID(inbound string) string {
	if validRequestID(inbound) {
		return inbound
	}
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func validRequestID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range []byte(s) {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// NewLogHandler wraps h so that every record logged with a context that
// carries a request ID gets a request_id attribute ahead of its own.
func NewLogHandler(h slog.Handler) slog.Handler { return logHandler{h} }

type logHandler struct{ slog.Handler }

func (h logHandler) Handle(ctx context.Context, r slog.Record) error {
	id := RequestID(ctx)
	if id == "" {
		return h.Handler.Handle(ctx, r)
	}
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	out.AddAttrs(slog.String("request_id", id))
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(a)
		return true
	})
	return h.Handler.Handle(ctx, out)
}

func (h logHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return logHandler{h.Handler.WithAttrs(attrs)}
}

func (h logHandler) WithGroup(name string) slog.Handler {
	return logHandler{h.Handler.WithGroup(name)}
}
