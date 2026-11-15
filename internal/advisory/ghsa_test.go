package advisory

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pogao/pkgwarden/internal/ecosystem"
)

func ghsaServer(t *testing.T, token string, handle func(w http.ResponseWriter, r *http.Request)) *GHSA {
	t.Helper()
	return ghsaServerWithNpm(t, token, nil, handle)
}

// ghsaServerWithNpm is ghsaServer with a fake registry.npmjs.org, which
// answers a request for a name in npm with its status and fails the test
// for any other name or for a name asked twice.
func ghsaServerWithNpm(t *testing.T, token string, npm map[string]int, handle func(w http.ResponseWriter, r *http.Request)) *GHSA {
	t.Helper()
	var mu sync.Mutex
	asked := map[string]bool{}
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("registry request %s carries the GitHub token", r.URL.Path)
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		mu.Lock()
		if asked[name] {
			t.Errorf("registry asked for %s more than once", name)
		}
		asked[name] = true
		mu.Unlock()
		status, ok := npm[name]
		if !ok {
			t.Errorf("unexpected registry request %s %s", r.Method, r.URL.Path)
			status = http.StatusNotFound
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(registry.Close)
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
	to, _ := url.Parse(registry.URL)
	client := srv.Client()
	client.Transport = npmRoute{to: to, next: client.Transport}
	return NewGHSA(client, srv.URL, token)
}

// npmRoute sends requests for registry.npmjs.org to the fake registry at to.
type npmRoute struct {
	to   *url.URL
	next http.RoundTripper
}

func (n npmRoute) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host == "registry.npmjs.org" {
		r = r.Clone(r.Context())
		r.URL.Scheme, r.URL.Host = n.to.Scheme, n.to.Host
	}
	return n.next.RoundTrip(r)
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

func TestGHSAMatchesNpmNamesExactly(t *testing.T) {
	src := ghsaServerWithNpm(t, "", map[string]int{"jquery": http.StatusOK}, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"ghsa_id":"GHSA-case-0000-0000","type":"reviewed","severity":"high","withdrawn_at":null,
		 "vulnerabilities":[{"package":{"ecosystem":"npm","name":"jQuery"},"vulnerable_version_range":"= 1.0.0"},
		 {"package":{"ecosystem":"npm","name":"jquery"},"vulnerable_version_range":"= 3.4.1"}]},
		{"ghsa_id":"GHSA-case-1111-1111","type":"reviewed","severity":"high","withdrawn_at":null,
		 "vulnerabilities":[{"package":{"ecosystem":"npm","name":"jquery"},"vulnerable_version_range":"< 3.5.0"}]}]`))
	})
	advs, err := src.Lookup(context.Background(), ecosystem.Npm, "jQuery")
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 {
		t.Fatalf("got %+v, want only GHSA-case-0000-0000", advs)
	}
	checkAffects(t, byID(t, advs, "GHSA-case-0000-0000"), []string{"1.0.0"}, []string{"3.4.1"})
}

func TestGHSAMatchesMisfiledNpmName(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusGone} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			npm := map[string]int{"Openclaw": status}
			src := ghsaServerWithNpm(t, "secret", npm, func(w http.ResponseWriter, r *http.Request) {
				w.Write(fixture(t, "ghsa_openclaw.json"))
			})
			advs, err := src.Lookup(context.Background(), ecosystem.Npm, "openclaw")
			if err != nil {
				t.Fatal(err)
			}
			if len(advs) != 2 {
				t.Fatalf("got %d advisories, want 2 (GHSA-vm29-7mq3-9jrg is withdrawn)", len(advs))
			}
			checkAffects(t, byID(t, advs, "GHSA-2j8v-hwgc-x698"), []string{"2026.5.12", "2026.5.16"}, []string{"2026.5.17"})
			checkAffects(t, byID(t, advs, "GHSA-3x84-qq85-fj65"), []string{"2026.6.5"}, []string{"2026.6.6"})
		})
	}
}

func TestGHSAMisfiledNpmNameMatchesWhenRegistryFails(t *testing.T) {
	npm := map[string]int{"Openclaw": http.StatusServiceUnavailable}
	src := ghsaServerWithNpm(t, "", npm, func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixture(t, "ghsa_openclaw.json"))
	})
	advs, err := src.Lookup(context.Background(), ecosystem.Npm, "openclaw")
	if err == nil {
		t.Error("Lookup succeeded although the registry could not say whether Openclaw exists, want an error")
	}
	checkAffects(t, byID(t, advs, "GHSA-2j8v-hwgc-x698"), []string{"2026.5.12"}, []string{"2026.5.17"})
	byID(t, advs, "GHSA-3x84-qq85-fj65")
}

func TestGHSAMisfiledNpmNamesAcrossPages(t *testing.T) {
	npm := map[string]int{"Openclaw": http.StatusServiceUnavailable, "OPENCLAW": http.StatusGone}
	var srvURL string
	src := ghsaServerWithNpm(t, "", npm, func(w http.ResponseWriter, r *http.Request) {
		entry := `{"ghsa_id":"%s","withdrawn_at":null,"vulnerabilities":[{"package":{"ecosystem":"npm","name":"%s"},"vulnerable_version_range":"< 1.0.0"}]}`
		switch r.URL.Query().Get("after") {
		case "":
			w.Header().Set("Link", fmt.Sprintf(`<%s/advisories?after=2&per_page=100>; rel="next"`, srvURL))
			fmt.Fprintf(w, "["+entry+"]", "GHSA-page-0001-0000", "Openclaw")
		case "2":
			w.Header().Set("Link", fmt.Sprintf(`<%s/advisories?after=3&per_page=100>; rel="next"`, srvURL))
			fmt.Fprintf(w, "["+entry+","+entry+"]", "GHSA-page-0002-0000", "Openclaw", "GHSA-page-0002-1111", "OPENCLAW")
		default:
			fmt.Fprintf(w, "["+entry+"]", "GHSA-page-0003-0000", "openclaw")
		}
	})
	srvURL = src.base
	advs, err := src.Lookup(context.Background(), ecosystem.Npm, "openclaw")
	if err == nil {
		t.Error("Lookup succeeded although the registry failed on page 1, want an error")
	}
	for _, id := range []string{"GHSA-page-0001-0000", "GHSA-page-0002-0000", "GHSA-page-0002-1111", "GHSA-page-0003-0000"} {
		checkAffects(t, byID(t, advs, id), []string{"0.9.0"}, []string{"1.0.0"})
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
