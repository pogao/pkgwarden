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
