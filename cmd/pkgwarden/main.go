// Command pkgwarden is a package proxy for npm, PyPI, RubyGems, Go modules
// and Cargo that refuses releases that are too new, known to be malicious or
// vulnerable, or that look suspicious.
package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pogao/pkgwarden/internal/advisory"
	"github.com/pogao/pkgwarden/internal/policy"
	"github.com/pogao/pkgwarden/internal/proxy"
	"github.com/pogao/pkgwarden/internal/proxy/cargo"
	"github.com/pogao/pkgwarden/internal/proxy/goproxy"
	"github.com/pogao/pkgwarden/internal/proxy/npm"
	"github.com/pogao/pkgwarden/internal/proxy/pypi"
	"github.com/pogao/pkgwarden/internal/proxy/rubygems"
	"github.com/pogao/pkgwarden/internal/telemetry"
)

func main() {
	cfg, err := parseConfig(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pkgwarden:", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// Restoring default signal handling lets a second signal kill a slow drain.
	context.AfterFunc(ctx, stop)
	if err := run(ctx, cfg); err != nil {
		slog.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg *config) error {
	slog.SetDefault(slog.New(telemetry.NewLogHandler(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.logLevel}))))

	client := &http.Client{Transport: telemetry.Transport(&http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	})}

	sources := []advisory.Source{advisory.NewOSV(client, cfg.osvURL)}
	if cfg.ghsaToken != "" {
		sources = append(sources, advisory.NewGHSA(client, "", cfg.ghsaToken))
	}
	if cfg.openSSF {
		feed := advisory.NewOpenSSF(client, "")
		go feed.Run(ctx, cfg.openSSFRefresh)
		sources = append(sources, feed)
	}
	telemetry.SetAdvisorySources(map[string]bool{"osv": true, "ghsa": cfg.ghsaToken != "", "openssf": cfg.openSSF})
	engine := policy.New(cfg.policy, advisory.Cached(advisory.Merge(sources...), cfg.advisoryTTL))

	up := proxy.NewUpstream(client, "pkgwarden (+https://github.com/pogao/pkgwarden)", cfg.metadataTTL)
	app := proxy.NewServer(engine,
		npm.New(npm.Options{PublicURL: cfg.publicURL, Engine: engine, HTTP: up}),
		pypi.New(pypi.Options{PublicURL: cfg.publicURL, Engine: engine, HTTP: up}),
		rubygems.New(rubygems.Options{PublicURL: cfg.publicURL, Engine: engine, HTTP: up}),
		goproxy.New(goproxy.Options{Engine: engine, HTTP: up}),
		cargo.New(cargo.Options{PublicURL: cfg.publicURL, Engine: engine, HTTP: up}),
	)
	telemetry.SetPolicy(telemetry.Policy{
		Cooldown:        cfg.policy.Cooldown,
		BlockSeverity:   cmp.Or(strings.ToLower(cfg.policy.BlockSeverity.String()), "none"),
		FailOpen:        cfg.policy.FailOpen,
		Heuristics:      cfg.policy.Heuristics.Enabled,
		HeuristicsWarn:  cfg.policy.Heuristics.WarnScore,
		HeuristicsBlock: cfg.policy.Heuristics.BlockScore,
	})

	mainHandler, metricsHandler := handlers(app, cfg.metricsListen != "")
	type listener struct {
		addr    string
		handler http.Handler
	}
	listeners := []listener{{cfg.listen, mainHandler}}
	if metricsHandler != nil {
		listeners = append(listeners, listener{cfg.metricsListen, metricsHandler})
	}
	var servers []*http.Server
	var addrs []string
	errc := make(chan error, len(listeners))
	for _, l := range listeners {
		ln, err := net.Listen("tcp", l.addr)
		if err != nil {
			for _, srv := range servers {
				srv.Close()
			}
			return err
		}
		srv := &http.Server{
			Handler:           l.handler,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       2 * time.Minute,
		}
		servers = append(servers, srv)
		addrs = append(addrs, ln.Addr().String())
		go func() { errc <- srv.Serve(ln) }()
	}
	slog.Info("listening", "addr", addrs[0], "metrics_addr", addrs[len(addrs)-1], "cooldown", cfg.policy.Cooldown.String(),
		"ghsa", cfg.ghsaToken != "", "openssf", cfg.openSSF, "heuristics", cfg.policy.Heuristics.Enabled)

	var err error
	select {
	case err = <-errc:
	case <-ctx.Done():
		slog.Info("shutting down", "signal", context.Cause(ctx))
	}
	for _, srv := range servers {
		if serr := srv.Shutdown(context.Background()); err == nil {
			err = serr
		}
	}
	return err
}

// handlers wraps app for the main listener. With separateMetrics it also
// returns the handler for the metrics listener, and the main listener
// leaves /metrics to app, which has no such route. Without it the main
// listener serves /metrics itself and the second handler is nil.
func handlers(app http.Handler, separateMetrics bool) (main, metrics http.Handler) {
	metricsMux := http.NewServeMux()
	metricsMux.Handle("GET /metrics", telemetry.Handler())
	if separateMetrics {
		return telemetry.Middleware(app), telemetry.Middleware(metricsMux)
	}
	return telemetry.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" {
			metricsMux.ServeHTTP(w, r)
			return
		}
		app.ServeHTTP(w, r)
	})), nil
}
