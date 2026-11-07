// Package telemetry exports pkgwarden's Prometheus metrics and ties log
// lines to the inbound request that caused them through a request ID.
//
// Metrics are process-wide, so the collectors live in one package-level
// registry instead of being threaded through every adapter. The recording
// functions take plain strings so that this package imports nothing else
// from pkgwarden but the ecosystem list.
package telemetry

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var registry = prometheus.NewRegistry()

var (
	metric = promauto.With(registry)

	// Artifact downloads stream whole files, so latency buckets reach a minute.
	latencyBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60}

	httpRequests = metric.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pkgwarden", Name: "http_requests_total",
		Help: "Inbound requests processed, by ecosystem, method and status code.",
	}, []string{"ecosystem", "method", "code"})
	httpDuration = metric.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "pkgwarden", Name: "http_request_duration_seconds",
		Help: "Inbound request latency, by ecosystem.", Buckets: latencyBuckets,
	}, []string{"ecosystem"})
	decisions = metric.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pkgwarden", Name: "decisions_total",
		Help: "Policy decisions applied, by ecosystem, stage (metadata or artifact) and decision (allow, warn or block).",
	}, []string{"ecosystem", "stage", "decision"})
	findings = metric.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pkgwarden", Name: "findings_total",
		Help: "Rules behind warn and block decisions, each rule counted once per decision.",
	}, []string{"ecosystem", "stage", "rule", "decision"})
	artifactsServed = metric.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pkgwarden", Name: "artifacts_served_total",
		Help: "Package files relayed to clients, by ecosystem.",
	}, []string{"ecosystem"})
	artifactBytes = metric.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pkgwarden", Name: "artifact_bytes_total",
		Help: "Bytes of package files relayed to clients, by ecosystem.",
	}, []string{"ecosystem"})
	upstreamRequests = metric.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pkgwarden", Name: "upstream_requests_total",
		Help: `Outbound requests, by host and status code ("error" when no response arrived).`,
	}, []string{"host", "code"})
	upstreamDuration = metric.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "pkgwarden", Name: "upstream_request_duration_seconds",
		Help: "Outbound latency until the response headers arrive, by host.", Buckets: latencyBuckets,
	}, []string{"host"})
)

func init() {
	registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
}

// Handler serves every metric in the Prometheus exposition format.
func Handler() http.Handler {
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
}

// RecordDecision counts one policy decision and, once each, the distinct
// rules behind it.
func RecordDecision(ecosystem, stage, decision string, rules []string) {
	decisions.WithLabelValues(ecosystem, stage, decision).Inc()
	for _, r := range rules {
		findings.WithLabelValues(ecosystem, stage, r, decision).Inc()
	}
}

// RecordArtifact counts a package file of n bytes relayed to a client.
func RecordArtifact(ecosystem string, n int64) {
	artifactsServed.WithLabelValues(ecosystem).Inc()
	artifactBytes.WithLabelValues(ecosystem).Add(float64(n))
}
