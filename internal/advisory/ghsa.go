package advisory

import (
	"context"
	"encoding/json"
	"errors"
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
	npmRegistry     = "https://registry.npmjs.org"
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
	applies := map[string]bool{eco.Normalize(name): true}
	var out []Advisory
	var registryErr error
	for range ghsaMaxPages {
		page, link, err := g.page(ctx, next.String())
		if err != nil {
			return nil, fmt.Errorf("ghsa lookup %s/%s: %w", eco, name, err)
		}
		if eco == ecosystem.Npm {
			registryErr = errors.Join(registryErr, g.misfiled(ctx, name, page, applies))
		}
		for i := range page {
			if adv, ok := ghsaToAdvisory(&page[i], eco, applies); ok {
				out = append(out, adv)
			}
		}
		next = nextLink(link)
		if next == nil {
			if registryErr != nil {
				return out, fmt.Errorf("ghsa lookup %s/%s: %w", eco, name, registryErr)
			}
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

// misfiled records in applies whether the entries of page filed under a
// letter-case variant of the npm package name apply to it. GitHub files a few
// advisories under a spelling the registry does not have, such as Openclaw
// for openclaw, but a spelling the registry has is a legacy package of its
// own, such as jQuery next to jquery. A spelling the registry cannot answer
// for applies, and the error is returned so that the guess is not cached.
func (g *GHSA) misfiled(ctx context.Context, name string, page []ghsaAdvisory, applies map[string]bool) error {
	var errs []error
	for _, adv := range page {
		if adv.WithdrawnAt != nil {
			continue
		}
		for _, v := range adv.Vulnerabilities {
			spelling := v.Package.Name
			if _, seen := applies[spelling]; seen || v.Package.Ecosystem != ecosystem.Npm.GHSA() || !strings.EqualFold(spelling, name) {
				continue
			}
			exists, err := g.npmHas(ctx, spelling)
			if err != nil {
				errs = append(errs, err)
			}
			applies[spelling] = !exists
		}
	}
	return errors.Join(errs...)
}

func (g *GHSA) npmHas(ctx context.Context, name string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, npmRegistry+"/"+url.PathEscape(name), nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := g.client.Do(req)
	if err != nil {
		return false, err
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound, http.StatusGone:
		return false, nil
	}
	return false, fmt.Errorf("HEAD %s: %s", req.URL.Redacted(), resp.Status)
}

func ghsaToAdvisory(g *ghsaAdvisory, eco ecosystem.Ecosystem, applies map[string]bool) (Advisory, bool) {
	if g.WithdrawnAt != nil {
		return Advisory{}, false
	}
	adv := Advisory{
		ID:        g.GHSAID,
		Source:    "ghsa",
		Summary:   summarize(g.Summary, g.Description),
		Severity:  ParseSeverity(g.Severity),
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
	for _, v := range g.Vulnerabilities {
		if v.Package.Ecosystem != eco.GHSA() || !applies[eco.Normalize(v.Package.Name)] {
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
