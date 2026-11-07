package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsRoute(t *testing.T) {
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/npm/left-pad" {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		http.NotFound(w, r)
	})
	get := func(h http.Handler, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec
	}
	isMetrics := func(rec *httptest.ResponseRecorder) bool {
		return rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "pkgwarden_build_info{")
	}

	t.Run("main listener serves /metrics by default", func(t *testing.T) {
		main, metrics := handlers(app, false)
		if metrics != nil {
			t.Error("got a metrics listener handler without -metrics-listen")
		}
		if rec := get(main, "/metrics"); !isMetrics(rec) {
			t.Errorf("GET /metrics: status %d, body without pkgwarden_build_info", rec.Code)
		}
		if rec := get(main, "/npm/left-pad"); rec.Code != http.StatusTeapot {
			t.Errorf("GET /npm/left-pad: status %d, want the app's 418", rec.Code)
		}
	})

	t.Run("-metrics-listen moves /metrics off the main listener", func(t *testing.T) {
		main, metrics := handlers(app, true)
		if rec := get(main, "/metrics"); rec.Code != http.StatusNotFound {
			t.Errorf("main GET /metrics: status %d, want 404", rec.Code)
		}
		if rec := get(main, "/npm/left-pad"); rec.Code != http.StatusTeapot {
			t.Errorf("main GET /npm/left-pad: status %d, want the app's 418", rec.Code)
		}
		if metrics == nil {
			t.Fatal("no metrics listener handler")
		}
		if rec := get(metrics, "/metrics"); !isMetrics(rec) {
			t.Errorf("metrics GET /metrics: status %d, body without pkgwarden_build_info", rec.Code)
		}
		if rec := get(metrics, "/npm/left-pad"); rec.Code != http.StatusNotFound {
			t.Errorf("metrics GET /npm/left-pad: status %d, want 404", rec.Code)
		}
	})
}
