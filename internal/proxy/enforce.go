package proxy

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/pogao/pkgwarden/internal/policy"
)

// Format is the body format a package manager expects in error responses.
type Format int

const (
	Text Format = iota
	// JSON writes {"error": "..."}, which npm prints verbatim.
	JSON
)

// Enforce applies a verdict to a response before anything is written.
// It returns false after writing a 403 when the verdict blocks. A warning
// is passed on in the X-Pkgwarden-Warning header. subject names what is
// being served, such as "npm/left-pad@1.3.0", for logs and messages.
func Enforce(w http.ResponseWriter, f Format, subject string, v policy.Verdict) bool {
	w.Header().Set("X-Pkgwarden-Decision", v.Decision.String())
	switch v.Decision {
	case policy.Allow:
		return true
	case policy.Warn:
		w.Header().Set("X-Pkgwarden-Warning", reasons(v))
		slog.Warn("serving with warnings", "subject", subject, "reasons", reasons(v))
		return true
	}
	slog.Info("blocked", "subject", subject, "reasons", reasons(v))
	msg := "pkgwarden blocked " + subject + ": " + reasons(v)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if f == JSON {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": msg})
		return false
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(msg + "\n"))
	return false
}

func reasons(v policy.Verdict) string {
	var parts []string
	for _, f := range v.Findings {
		if f.Decision >= v.Decision {
			parts = append(parts, string(f.Rule)+": "+f.Reason)
		}
	}
	return strings.Join(parts, "; ")
}

// BaseURL returns the externally visible URL of the proxy, without a
// trailing slash. A configured public URL wins over request headers.
func BaseURL(r *http.Request, public string) string {
	if public != "" {
		return strings.TrimSuffix(public, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p == "http" || p == "https" {
		scheme = p
	}
	return scheme + "://" + r.Host
}
