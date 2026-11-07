package advisory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/pogao/pkgwarden/internal/ecosystem"
)

const (
	defaultOSVBase = "https://api.osv.dev"
	osvPageLimit   = 32 << 20
	osvMaxPages    = 100
	summaryMax     = 200
)

// OSV queries the OSV.dev API.
type OSV struct {
	client *http.Client
	base   string
}

// NewOSV returns a Source backed by the OSV API at baseURL, or at
// https://api.osv.dev when baseURL is empty. A nil client means
// http.DefaultClient.
func NewOSV(client *http.Client, baseURL string) *OSV {
	if client == nil {
		client = http.DefaultClient
	}
	if baseURL == "" {
		baseURL = defaultOSVBase
	}
	return &OSV{client: client, base: strings.TrimSuffix(baseURL, "/")}
}

type osvQuery struct {
	Package   osvPackage `json:"package"`
	PageToken string     `json:"page_token,omitempty"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvResponse struct {
	Vulns         []osvVuln `json:"vulns"`
	NextPageToken string    `json:"next_page_token"`
}

type osvVuln struct {
	ID               string   `json:"id"`
	Aliases          []string `json:"aliases"`
	Summary          string   `json:"summary"`
	Details          string   `json:"details"`
	Withdrawn        string   `json:"withdrawn"`
	DatabaseSpecific struct {
		// Raw because database_specific is free-form and a non-string
		// severity must not fail the whole record.
		Severity json.RawMessage `json:"severity"`
	} `json:"database_specific"`
	Affected []osvAffected `json:"affected"`
}

type osvAffected struct {
	Package  osvPackage `json:"package"`
	Versions []string   `json:"versions"`
	Ranges   []struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced   string `json:"introduced"`
			Fixed        string `json:"fixed"`
			LastAffected string `json:"last_affected"`
		} `json:"events"`
	} `json:"ranges"`
}

// Lookup returns the OSV advisories for a package.
func (o *OSV) Lookup(ctx context.Context, eco ecosystem.Ecosystem, name string) ([]Advisory, error) {
	q := osvQuery{Package: osvPackage{Name: name, Ecosystem: eco.OSV()}}
	var out []Advisory
	for range osvMaxPages {
		resp, err := o.query(ctx, q)
		if err != nil {
			return nil, fmt.Errorf("osv lookup %s/%s: %w", eco, name, err)
		}
		for i := range resp.Vulns {
			if adv, ok := osvAdvisory(&resp.Vulns[i], eco, name); ok {
				adv.Source = "osv"
				out = append(out, adv)
			}
		}
		if resp.NextPageToken == "" {
			return out, nil
		}
		q.PageToken = resp.NextPageToken
	}
	return nil, fmt.Errorf("osv lookup %s/%s: more than %d pages", eco, name, osvMaxPages)
}

func (o *OSV) query(ctx context.Context, q osvQuery) (*osvResponse, error) {
	payload, err := json.Marshal(q)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.base+"/v1/query", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	body, _, err := readBody(o.client, req, osvPageLimit)
	if err != nil {
		return nil, err
	}
	var resp osvResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode osv response: %w", err)
	}
	return &resp, nil
}

// osvAdvisory converts an OSV record into an Advisory for the package
// (eco, name). It reports false when the record is withdrawn or none of its
// affected entries name that package. The OSV and OpenSSF sources share it.
func osvAdvisory(v *osvVuln, eco ecosystem.Ecosystem, name string) (Advisory, bool) {
	if v.Withdrawn != "" {
		return Advisory{}, false
	}
	adv := Advisory{
		ID:        v.ID,
		Aliases:   slices.Clone(v.Aliases),
		Summary:   summarize(v.Summary, v.Details),
		Severity:  osvSeverity(v.DatabaseSpecific.Severity),
		URL:       "https://osv.dev/vulnerability/" + v.ID,
		Ecosystem: eco,
	}
	if isMAL(v.ID) || slices.ContainsFunc(v.Aliases, isMAL) {
		adv.Kind = Malicious
	}
	matched := false
	want := eco.Normalize(name)
	for _, a := range v.Affected {
		if a.Package.Ecosystem != eco.OSV() || eco.Normalize(a.Package.Name) != want {
			continue
		}
		matched = true
		for _, ver := range a.Versions {
			if !slices.Contains(adv.Versions, ver) {
				adv.Versions = append(adv.Versions, ver)
			}
		}
		for _, r := range a.Ranges {
			if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue
			}
			var open *Range
			for _, e := range r.Events {
				switch {
				case e.Introduced != "":
					if open == nil {
						open = &Range{Introduced: e.Introduced}
					}
				case open != nil && e.Fixed != "":
					open.Fixed = e.Fixed
					adv.Ranges = append(adv.Ranges, *open)
					open = nil
				case open != nil && e.LastAffected != "":
					open.LastAffected = e.LastAffected
					adv.Ranges = append(adv.Ranges, *open)
					open = nil
				}
			}
			if open != nil {
				adv.Ranges = append(adv.Ranges, *open)
			}
		}
	}
	return adv, matched
}

func isMAL(id string) bool { return strings.HasPrefix(id, "MAL-") }

func osvSeverity(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return normalizeSeverity(s)
}

// normalizeSeverity maps database ratings onto the CVSS names. GitHub calls
// MEDIUM "moderate".
func normalizeSeverity(s string) string {
	switch s = strings.ToUpper(strings.TrimSpace(s)); s {
	case "MODERATE":
		return "MEDIUM"
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return s
	}
	return ""
}

func summarize(summary, details string) string {
	if s := strings.TrimSpace(summary); s != "" {
		return s
	}
	for line := range strings.Lines(details) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if r := []rune(line); len(r) > summaryMax {
			return string(r[:summaryMax]) + "..."
		}
		return line
	}
	return ""
}
