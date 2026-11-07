// Package telemetrytest reads pkgwarden's metrics and logs the way an
// operator does, from the /metrics handler and the JSON log, for tests.
package telemetrytest

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"

	"github.com/pogao/pkgwarden/internal/telemetry"
)

// Value scrapes telemetry.Handler and returns the value of the counter or
// gauge series name with exactly labels, or 0 when the series is absent.
// Metrics are process-wide, so tests compare values before and after.
func Value(t testing.TB, name string, labels map[string]string) float64 {
	t.Helper()
	rec := httptest.NewRecorder()
	telemetry.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(rec.Body)
	if err != nil {
		t.Fatalf("parse /metrics: %v", err)
	}
	mf, ok := families[name]
	if !ok {
		return 0
	}
	for _, m := range mf.GetMetric() {
		if len(m.GetLabel()) != len(labels) {
			continue
		}
		match := true
		for _, l := range m.GetLabel() {
			if v, ok := labels[l.GetName()]; !ok || v != l.GetValue() {
				match = false
			}
		}
		if !match {
			continue
		}
		switch {
		case m.Counter != nil:
			return m.GetCounter().GetValue()
		case m.Gauge != nil:
			return m.GetGauge().GetValue()
		}
	}
	return 0
}

// Logs holds what the default logger wrote while it was captured.
type Logs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// CaptureLogs points the default logger at a debug-level JSON handler
// wrapped in telemetry.NewLogHandler, as cmd/pkgwarden sets it up, until
// the test ends.
func CaptureLogs(t testing.TB) *Logs {
	t.Helper()
	l := &Logs{}
	prev := slog.Default()
	slog.SetDefault(slog.New(telemetry.NewLogHandler(slog.NewJSONHandler(l, &slog.HandlerOptions{Level: slog.LevelDebug}))))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return l
}

func (l *Logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

// Raw returns everything written so far.
func (l *Logs) Raw() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// Lines decodes every line written so far.
func (l *Logs) Lines(t testing.TB) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range bytes.Lines([]byte(l.Raw())) {
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// Messages returns the lines whose msg is msg.
func (l *Logs) Messages(t testing.TB, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, m := range l.Lines(t) {
		if m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}
