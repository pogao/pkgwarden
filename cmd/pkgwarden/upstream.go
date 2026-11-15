package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/pogao/pkgwarden/internal/telemetry"
)

func newUpstreamTransport(tlsConfig *tls.Config) http.RoundTripper {
	return telemetry.Transport(&http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	})
}
