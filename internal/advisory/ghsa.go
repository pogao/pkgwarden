package advisory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pogao/pkgwarden/internal/ecosystem"
)

const (
	defaultGHSABase = "https://api.github.com"
	ghsaPageLimit   = 32 << 20
	ghsaMaxPages    = 50
)

// GHSA queries the GitHub Advisory Database REST API.
type GHSA struct {
	client *http.Client
	base   string
	token  string
}

// NewGHSA returns a Source backed by the GitHub REST API at baseURL, or at
// https://api.github.com when baseURL is empty. token is sent as a bearer
// token when non-empty; unauthenticated requests get a much lower rate
// limit. A nil client means http.DefaultClient.
func NewGHSA(client *http.Client, baseURL, token string) *GHSA {
	if client == nil {
		client = http.DefaultClient
	}
	if baseURL == "" {
		baseURL = defaultGHSABase
	}
	return &GHSA{client: client, base: strings.TrimSuffix(baseURL, "/"), token: token}
}

type ghsaAdvisory struct {
	GHSAID          string  `json:"ghsa_id"`
	CVEID           *string `json:"cve_id"`
	HTMLURL         string  `json:"html_url"`
	Summary         string  `json:"summary"`
	Description     string  `json:"description"`
	Type            string  `json:"type"`
	Severity        string  `json:"severity"`
	WithdrawnAt     *string `json:"withdrawn_at"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
	} `json:"vulnerabilities"`
}

// Lookup returns the GitHub advisories for a package.
func (g *GHSA) Lookup(ctx context.Context, eco ecosystem.Ecosystem, name string) ([]Advisory, error) {
	start, err := url.Parse(g.base + "/advisories")
	if err != nil {
		return nil, fmt.Errorf("ghsa lookup %s/%s: %w", eco, name, err)
	}
	start.RawQuery = url.Values{
		"ecosystem": {eco.GHSA()},
		"affects":   {name},
		"per_page":  {"100"},
	}.Encode()
	next := start
	var out []Advisory
	for range ghsaMaxPages {
		page, link, err := g.page(ctx, next.String())
		if err != nil {
			return nil, fmt.Errorf("ghsa lookup %s/%s: %w", eco, name, err)
		}
		for i := range page {
			if adv, ok := ghsaToAdvisory(&page[i], eco, name); ok {
				out = append(out, adv)
			}
		}
		next = nextLink(link)
		if next == nil {
			return out, nil
		}
		next = start.ResolveReference(next)
		// The token must never leave the configured API host.
		if next.Scheme != start.Scheme || next.Host != start.Host {
			return nil, fmt.Errorf("ghsa lookup %s/%s: pagination link points at another host %q", eco, name, next.Host)
		}
	}
	return nil, fmt.Errorf("ghsa lookup %s/%s: more than %d pages", eco, name, ghsaMaxPages)
}

func (g *GHSA) page(ctx context.Context, u string) ([]ghsaAdvisory, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if g.token != "" {
		req.Header.Set("Authorization", "Bearer "+g.token)
	}
	body, header, err := readBody(g.client, req, ghsaPageLimit)
	if err != nil {
		return nil, "", err
	}
	var page []ghsaAdvisory
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, "", fmt.Errorf("decode github advisories: %w", err)
	}
	return page, header.Get("Link"), nil
}

// nextLink extracts the rel="next" target of an RFC 8288 Link header.
func nextLink(header string) *url.URL {
	for link := range strings.SplitSeq(header, ",") {
		target, params, ok := strings.Cut(strings.TrimSpace(link), ";")
		if !ok || !strings.HasPrefix(target, "<") || !strings.HasSuffix(target, ">") {
			continue
		}
		for p := range strings.SplitSeq(params, ";") {
			if k, v, _ := strings.Cut(strings.TrimSpace(p), "="); k == "rel" && strings.Trim(v, `"`) == "next" {
				u, err := url.Parse(target[1 : len(target)-1])
				if err != nil {
					return nil
				}
				return u
			}
		}
	}
	return nil
}

func ghsaToAdvisory(g *ghsaAdvisory, eco ecosystem.Ecosystem, name string) (Advisory, bool) {
	if g.WithdrawnAt != nil {
		return Advisory{}, false
	}
	adv := Advisory{
		ID:        g.GHSAID,
		Source:    "ghsa",
		Summary:   summarize(g.Summary, g.Description),
		Severity:  normalizeSeverity(g.Severity),
		URL:       g.HTMLURL,
		Ecosystem: eco,
	}
	if g.CVEID != nil && *g.CVEID != "" {
		adv.Aliases = []string{*g.CVEID}
	}
	if g.Type == "malware" {
		adv.Kind = Malicious
	}
	matched := false
	want := eco.Normalize(name)
	for _, v := range g.Vulnerabilities {
		if v.Package.Ecosystem != eco.GHSA() || eco.Normalize(v.Package.Name) != want {
			continue
		}
		matched = true
		exact, r, ok := parseGHSARange(v.VulnerableVersionRange)
		switch {
		case !ok:
			// An unreadable constraint leaves the advisory with no versions
			// or ranges unless a sibling entry adds some, which fails closed.
		case exact != "":
			adv.Versions = append(adv.Versions, exact)
		default:
			adv.Ranges = append(adv.Ranges, r)
		}
	}
	return adv, matched
}

// parseGHSARange parses a vulnerable_version_range such as ">= 1.0, < 1.4.2"
// or "= 3.3.6" into either one exact version or a Range.
func parseGHSARange(s string) (exact string, r Range, ok bool) {
	if strings.TrimSpace(s) == "" {
		return "", Range{}, false
	}
	for c := range strings.SplitSeq(s, ",") {
		c = strings.TrimSpace(c)
		op := c[:len(c)-len(strings.TrimLeft(c, "<>="))]
		v := strings.TrimSpace(c[len(op):])
		if v == "" {
			return "", Range{}, false
		}
		switch op {
		case "=":
			exact = v
		// Range has no exclusive lower bound, so "> v" also covers v itself.
		// Over-blocking that one release is the safe direction to be wrong.
		case ">=", ">":
			r.Introduced = v
		case "<":
			r.Fixed = v
		case "<=":
			r.LastAffected = v
		default:
			return "", Range{}, false
		}
	}
	if exact != "" && r != (Range{}) {
		return "", Range{}, false
	}
	return exact, r, true
}
