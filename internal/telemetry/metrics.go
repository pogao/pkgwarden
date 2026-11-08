// Package telemetry exports pkgwarden's Prometheus metrics and ties log
// lines to the inbound request that caused them through a request ID.
//
// Metrics are process-wide, so the collectors live in one package-level
// registry instead of being threaded through every adapter. The recording
// functions take plain strings so that this package imports nothing else
// from pkgwarden but the ecosystem list.
package telemetry

import (
	"cmp"
	"net/http"
	"runtime"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var registry = prometheus.NewRegistry()

// version overrides the module version in build_info. Builds without VCS
// information, such as the container image, set it with
// -ldflags "-X github.com/pogao/pkgwarden/internal/telemetry.version=v1.2.3".
var version string

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
	cacheRequests = metric.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pkgwarden", Name: "cache_requests_total",
		Help: "Cache lookups, by cache (metadata or advisory) and result (hit or miss).",
	}, []string{"cache", "result"})
	openSSFLastSuccess = metric.NewGauge(prometheus.GaugeOpts{
		Namespace: "pkgwarden", Name: "openssf_last_success_timestamp_seconds",
		Help: "Unix time of the last successful OpenSSF dataset load; 0 until the first.",
	})
	openSSFPackages = metric.NewGauge(prometheus.GaugeOpts{
		Namespace: "pkgwarden", Name: "openssf_packages",
		Help: "Packages in the loaded OpenSSF malicious-packages index.",
	})
	openSSFFailures = metric.NewCounter(prometheus.CounterOpts{
		Namespace: "pkgwarden", Name: "openssf_refresh_failures_total",
		Help: "Failed OpenSSF dataset refreshes.",
	})
	policyInfo = metric.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "pkgwarden", Name: "policy_info",
		Help: "The policy in effect, as labels on a constant 1.",
	}, []string{"cooldown", "block_severity", "fail_open", "heuristics", "heuristics_warn", "heuristics_block"})
	buildInfo = metric.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "pkgwarden", Name: "build_info",
		Help: "The running build, as labels on a constant 1.",
	}, []string{"version", "go_version"})
)

func init() {
	registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	v := version
	if bi, ok := debug.ReadBuildInfo(); ok && v == "" {
		v = bi.Main.Version
	}
	buildInfo.WithLabelValues(cmp.Or(v, "unknown"), runtime.Version()).Set(1)
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

// RecordCache counts a lookup in the named cache.
func RecordCache(cache string, hit bool) {
	result := "miss"
	if hit {
		result = "hit"
	}
	cacheRequests.WithLabelValues(cache, result).Inc()
}

// RecordOpenSSFLoad records a successful OpenSSF dataset load.
func RecordOpenSSFLoad(packages int, at time.Time) {
	openSSFPackages.Set(float64(packages))
	openSSFLastSuccess.Set(float64(at.Unix()))
}

// RecordOpenSSFFailure counts a failed OpenSSF dataset refresh.
func RecordOpenSSFFailure() { openSSFFailures.Inc() }

// Policy describes the policy in effect for the policy_info metric.
type Policy struct {
	Cooldown        time.Duration
	BlockSeverity   string
	FailOpen        bool
	Heuristics      bool
	HeuristicsWarn  int
	HeuristicsBlock int
}

// SetPolicy publishes p as the policy in effect.
func SetPolicy(p Policy) {
	policyInfo.Reset()
	policyInfo.WithLabelValues(p.Cooldown.String(), p.BlockSeverity, strconv.FormatBool(p.FailOpen),
		strconv.FormatBool(p.Heuristics), strconv.Itoa(p.HeuristicsWarn), strconv.Itoa(p.HeuristicsBlock)).Set(1)
}
