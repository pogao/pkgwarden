// Command pkgwarden is a package proxy for npm, PyPI, RubyGems, Go modules
// and Cargo that refuses releases that are too new, known to be malicious or
// vulnerable, or that look suspicious.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
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
	defer stop()
	if err := run(ctx, cfg); err != nil {
		slog.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg *config) error {
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.logLevel)); err != nil {
		return fmt.Errorf("-log-level: %w", err)
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	client := &http.Client{Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}}

	sources := []advisory.Source{advisory.NewOSV(client, cfg.osvURL)}
	if cfg.ghsaToken != "" {
		sources = append(sources, advisory.NewGHSA(client, "", cfg.ghsaToken))
	}
	if cfg.openSSF {
		feed := advisory.NewOpenSSF(client, "")
		go feed.Run(ctx, cfg.openSSFRefresh)
		sources = append(sources, feed)
	}
	engine := policy.New(cfg.policy, advisory.Cached(advisory.Merge(sources...), cfg.advisoryTTL))

	up := proxy.NewUpstream(client, "pkgwarden (+https://github.com/pogao/pkgwarden)", cfg.metadataTTL)
	handler := proxy.NewServer(engine,
		npm.New(npm.Options{PublicURL: cfg.publicURL, Engine: engine, HTTP: up}),
		pypi.New(pypi.Options{PublicURL: cfg.publicURL, Engine: engine, HTTP: up}),
		rubygems.New(rubygems.Options{PublicURL: cfg.publicURL, Engine: engine, HTTP: up}),
		goproxy.New(goproxy.Options{Engine: engine, HTTP: up}),
		cargo.New(cargo.Options{PublicURL: cfg.publicURL, Engine: engine, HTTP: up}),
	)

	ln, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	slog.Info("listening", "addr", ln.Addr().String(), "cooldown", cfg.policy.Cooldown.String(),
		"ghsa", cfg.ghsaToken != "", "openssf", cfg.openSSF, "heuristics", cfg.policy.Heuristics.Enabled)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
