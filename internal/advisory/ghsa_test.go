package advisory

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/pogao/pkgwarden/internal/ecosystem"
)

func ghsaServer(t *testing.T, token string, handle func(w http.ResponseWriter, r *http.Request)) *GHSA {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/advisories" {
			http.NotFound(w, r)
			return
		}
		for h, want := range map[string]string{
			"User-Agent":           "pkgwarden",
			"Accept":               "application/vnd.github+json",
			"X-GitHub-Api-Version": "2022-11-28",
		} {
			if got := r.Header.Get(h); got != want {
				t.Errorf("%s = %q, want %q", h, got, want)
			}
		}
		_, sent := r.Header["Authorization"]
		if token == "" && sent {
			t.Errorf("Authorization sent without a token")
		}
		if token != "" && r.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("Authorization = %q, want bearer token", r.Header.Get("Authorization"))
		}
		handle(w, r)
	}))
	t.Cleanup(srv.Close)
	return NewGHSA(srv.Client(), srv.URL, token)
}

func TestGHSALookupNpm(t *testing.T) {
	src := ghsaServer(t, "secret", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("ecosystem") != "npm" || q.Get("affects") != "event-stream" || q.Get("per_page") != "100" {
			t.Errorf("query = %v", q)
		}
		w.Write(fixture(t, "ghsa_event-stream.json"))
	})
	advs, err := src.Lookup(context.Background(), ecosystem.Npm, "event-stream")
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 {
		t.Fatalf("got %d advisories, want 1", len(advs))
	}
	a := advs[0]
	if a.ID != "GHSA-mh6f-8j2x-4483" || a.Source != "ghsa" || a.Severity != SeverityCritical || a.Kind != Vulnerability ||
		a.URL != "https://github.com/advisories/GHSA-mh6f-8j2x-4483" || len(a.Aliases) != 0 {
		t.Errorf("unexpected advisory %+v", a)
	}
	// "= 3.3.6" names one release; the flatmap-stream ">= 0" entry must not apply.
	checkAffects(t, a, []string{"3.3.6"}, []string{"3.3.5", "3.3.7", "4.0.0"})
}

func TestGHSALookupPyPIWithoutToken(t *testing.T) {
	src := ghsaServer(t, "", func(w http.ResponseWriter, r *http.Request) {
		if q := r.URL.Query(); q.Get("ecosystem") != "pip" || q.Get("affects") != "jinja2" {
			t.Errorf("query = %v", q)
		}
		w.Write(fixture(t, "ghsa_jinja2.json"))
	})
	advs, err := src.Lookup(context.Background(), ecosystem.PyPI, "jinja2")
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 3 {
		t.Fatalf("got %d advisories, want 3", len(advs))
	}
	// The fixture spells this package "Jinja2"; names match after normalization.
	a := byID(t, advs, "GHSA-h75v-3vvj-5mfj")
	if a.Severity != SeverityMedium || !slices.Equal(a.Aliases, []string{"CVE-2024-34064"}) {
		t.Errorf("unexpected advisory %+v", a)
	}
	checkAffects(t, a, []string{"2.0", "3.1.3"}, []string{"3.1.4", "3.2.0"})
	checkAffects(t, byID(t, advs, "GHSA-gmj6-6f8f-6699"), []string{"3.0.0", "3.1.4"}, []string{"2.11.3", "3.1.5"})
}

func TestGHSAVulnerableVersionRange(t *testing.T) {
	tests := []struct {
		rng            string
		affected, safe []string
	}{
		{"= 2.0.0", []string{"2.0.0"}, []string{"1.9.9", "2.0.1"}},
		{"< 1.4.2", []string{"0.0.1", "1.4.1"}, []string{"1.4.2"}},
		{"<= 1.4.2", []string{"1.4.2"}, []string{"1.4.3"}},
		{">= 1.0.0, < 1.4.2", []string{"1.0.0", "1.4.1"}, []string{"0.9.9", "1.4.2"}},
		// The exclusive lower bound over-blocks 1.0.0 itself, by design.
		{"> 1.0.0, <= 2.0.0", []string{"1.0.0", "1.5.0", "2.0.0"}, []string{"0.9.0", "2.0.1"}},
		{">= 0", []string{"0.0.1", "9.9.9"}, nil},
		{"~> 1.0", []string{"0.0.1", "9.9.9"}, nil},
		{"", []string{"0.0.1", "9.9.9"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.rng, func(t *testing.T) {
			src := ghsaServer(t, "", func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, `[{"ghsa_id":"GHSA-1111-2222-3333","severity":"moderate","withdrawn_at":null,
					"vulnerabilities":[{"package":{"ecosystem":"rust","name":"some_crate"},"vulnerable_version_range":%q}]}]`, tt.rng)
			})
			advs, err := src.Lookup(context.Background(), ecosystem.Cargo, "some-crate")
			if err != nil {
				t.Fatal(err)
			}
			if len(advs) != 1 {
				t.Fatalf("got %d advisories, want 1", len(advs))
			}
			if advs[0].Severity != SeverityMedium {
				t.Errorf("severity = %v, want MEDIUM", advs[0].Severity)
			}
			checkAffects(t, advs[0], tt.affected, tt.safe)
		})
	}
}

func TestGHSAKindsAndWithdrawn(t *testing.T) {
	src := ghsaServer(t, "", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[
		{"ghsa_id":"GHSA-mal0-0000-0000","type":"malware","severity":"critical","cve_id":null,"withdrawn_at":null,
		 "vulnerabilities":[{"package":{"ecosystem":"rubygems","name":"evil"},"vulnerable_version_range":">= 0"}]},
		{"ghsa_id":"GHSA-wdrn-0000-0000","type":"reviewed","severity":"high","withdrawn_at":"2023-01-01T00:00:00Z",
		 "vulnerabilities":[{"package":{"ecosystem":"rubygems","name":"evil"},"vulnerable_version_range":">= 0"}]},
		{"ghsa_id":"GHSA-othr-0000-0000","type":"reviewed","severity":"high","withdrawn_at":null,
		 "vulnerabilities":[{"package":{"ecosystem":"rubygems","name":"unrelated"},"vulnerable_version_range":">= 0"}]}
		]`))
	})
	advs, err := src.Lookup(context.Background(), ecosystem.RubyGems, "evil")
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 || advs[0].ID != "GHSA-mal0-0000-0000" || advs[0].Kind != Malicious {
		t.Errorf("got %+v, want only the malicious advisory", advs)
	}
}

func TestGHSAPagination(t *testing.T) {
	var srvURL string
	src := ghsaServer(t, "tok", func(w http.ResponseWriter, r *http.Request) {
		entry := `[{"ghsa_id":"%s","withdrawn_at":null,"vulnerabilities":[{"package":{"ecosystem":"go","name":"example.com/m"},"vulnerable_version_range":"< 1.0.0"}]}]`
		if r.URL.Query().Get("after") == "" {
			w.Header().Set("Link", fmt.Sprintf(`<%s/advisories?after=abc&per_page=100>; rel="next"`, srvURL))
			fmt.Fprintf(w, entry, "GHSA-page-0001-0000")
			return
		}
		fmt.Fprintf(w, entry, "GHSA-page-0002-0000")
	})
	srvURL = src.base
	advs, err := src.Lookup(context.Background(), ecosystem.Go, "example.com/m")
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 2 || advs[0].ID != "GHSA-page-0001-0000" || advs[1].ID != "GHSA-page-0002-0000" {
		t.Errorf("got %+v, want both pages", advs)
	}
	checkAffects(t, advs[0], []string{"v0.9.0"}, []string{"v1.0.0"})
}

func TestGHSAPaginationRefusesForeignHost(t *testing.T) {
	var leaked atomic.Bool
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Store(true)
		w.Write([]byte(`[]`))
	}))
	defer foreign.Close()
	src := ghsaServer(t, "tok", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", fmt.Sprintf(`<%s/advisories?after=abc>; rel="next"`, foreign.URL))
		w.Write([]byte(`[]`))
	})
	if _, err := src.Lookup(context.Background(), ecosystem.Npm, "x"); err == nil {
		t.Error("Lookup followed a pagination link to another host, want an error")
	}
	if leaked.Load() {
		t.Error("request carrying the token reached another host")
	}
}
