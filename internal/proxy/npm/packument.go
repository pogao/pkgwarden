package npm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"golang.org/x/mod/semver"

	"github.com/pogao/pkgwarden/internal/ecosystem"
	"github.com/pogao/pkgwarden/internal/policy"
)

// packument is a full npm package document. Every field is kept raw so the
// parts pkgwarden does not rewrite reach the client unchanged.
type packument struct {
	doc         map[string]json.RawMessage
	versions    map[string]manifest
	times       map[string]json.RawMessage
	distTags    map[string]string
	maintainers []string
}

// manifest is one entry of a packument's versions object.
type manifest struct {
	raw            map[string]json.RawMessage
	publisher      string
	installScripts bool
	dist           map[string]json.RawMessage
}

func parsePackument(b []byte) (*packument, error) {
	p := &packument{}
	if err := json.Unmarshal(b, &p.doc); err != nil {
		return nil, fmt.Errorf("decode packument: %w", err)
	}
	var (
		versions    map[string]json.RawMessage
		maintainers []struct {
			Name string `json:"name"`
		}
	)
	for key, dst := range map[string]any{"versions": &versions, "time": &p.times, "dist-tags": &p.distTags, "maintainers": &maintainers} {
		if b, ok := p.doc[key]; ok {
			if err := json.Unmarshal(b, dst); err != nil {
				return nil, fmt.Errorf("decode packument %s: %w", key, err)
			}
		}
	}
	for _, m := range maintainers {
		p.maintainers = append(p.maintainers, m.Name)
	}
	p.versions = make(map[string]manifest, len(versions))
	for v, b := range versions {
		m, err := parseManifest(b)
		if err != nil {
			return nil, fmt.Errorf("decode packument version %s: %w", v, err)
		}
		p.versions[v] = m
	}
	return p, nil
}

func parseManifest(b []byte) (manifest, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return manifest{}, err
	}
	var f struct {
		NpmUser struct {
			Name string `json:"name"`
		} `json:"_npmUser"`
		Scripts map[string]json.RawMessage `json:"scripts"`
		Dist    map[string]json.RawMessage `json:"dist"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return manifest{}, err
	}
	m := manifest{raw: fields, publisher: f.NpmUser.Name, dist: f.Dist}
	for _, s := range []string{"preinstall", "install", "postinstall"} {
		if _, ok := f.Scripts[s]; ok {
			m.installScripts = true
		}
	}
	return m, nil
}

// published returns the time recorded for key in the packument's time
// object, or the zero time when it is missing or malformed.
func (p *packument) published(key string) time.Time {
	var s string
	if json.Unmarshal(p.times[key], &s) != nil {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func (p *packument) policyPackage(name string, weeklyDownloads int64) *policy.Package {
	pkg := &policy.Package{
		Ecosystem:       ecosystem.Npm,
		Name:            name,
		Created:         p.published("created"),
		WeeklyDownloads: weeklyDownloads,
	}
	for v, m := range p.versions {
		publishers := p.maintainers
		if m.publisher != "" {
			publishers = []string{m.publisher}
		}
		pkg.Releases = append(pkg.Releases, policy.Release{
			Version:        v,
			Published:      p.published(v),
			Publishers:     publishers,
			InstallScripts: m.installScripts,
		})
	}
	return pkg
}

// filter returns the packument with every version that allowed rejects
// removed, tarball URLs pointing at tarballBase, and dist-tags moved off
// removed versions. It reports false when versions existed but none is
// allowed.
func (p *packument) filter(allowed func(string) bool, tarballBase, registryPath string) ([]byte, bool, error) {
	kept := make(map[string]json.RawMessage, len(p.versions))
	for v, m := range p.versions {
		if !allowed(v) {
			delete(p.times, v)
			continue
		}
		raw, err := m.withTarball(tarballBase, registryPath)
		if err != nil {
			return nil, false, fmt.Errorf("version %s: %w", v, err)
		}
		kept[v] = raw
	}
	if len(p.versions) > 0 && len(kept) == 0 {
		return nil, false, nil
	}
	if p.doc["versions"] != nil {
		if err := setJSON(p.doc, "versions", kept); err != nil {
			return nil, false, err
		}
	}
	if p.times != nil {
		if err := setJSON(p.doc, "time", p.times); err != nil {
			return nil, false, err
		}
	}
	if p.distTags != nil {
		if err := setJSON(p.doc, "dist-tags", retarget(p.distTags, kept)); err != nil {
			return nil, false, err
		}
	}
	b, err := marshal(p.doc)
	return b, true, err
}

// withTarball returns the manifest with dist.tarball moved from the
// upstream registry onto tarballBase, keeping the upstream path.
func (m manifest) withTarball(tarballBase, registryPath string) (json.RawMessage, error) {
	var tarball string
	if json.Unmarshal(m.dist["tarball"], &tarball) != nil {
		return marshal(m.raw)
	}
	u, err := url.Parse(tarball)
	if err != nil {
		return nil, fmt.Errorf("tarball URL: %w", err)
	}
	if err := setJSON(m.dist, "tarball", tarballBase+strings.TrimPrefix(u.EscapedPath(), registryPath)); err != nil {
		return nil, err
	}
	if err := setJSON(m.raw, "dist", m.dist); err != nil {
		return nil, err
	}
	return marshal(m.raw)
}

// retarget keeps tags that point at kept versions. A latest tag that points
// at a removed version moves to the newest kept stable release no newer than
// it, so a blocked patch never turns into a jump across majors; other tags
// on removed versions are dropped.
func retarget(tags map[string]string, kept map[string]json.RawMessage) map[string]string {
	out := make(map[string]string, len(tags))
	for tag, v := range tags {
		if _, ok := kept[v]; ok {
			out[tag] = v
			continue
		}
		if tag != "latest" {
			continue
		}
		ceiling := "v" + v
		best := ""
		for k := range kept {
			sv := "v" + k
			if !semver.IsValid(sv) || semver.Prerelease(sv) != "" {
				continue
			}
			if semver.IsValid(ceiling) && semver.Compare(sv, ceiling) > 0 {
				continue
			}
			if best == "" || semver.Compare(sv, "v"+best) > 0 {
				best = k
			}
		}
		if best != "" {
			out[tag] = best
		}
	}
	return out
}

func setJSON(m map[string]json.RawMessage, key string, v any) error {
	b, err := marshal(v)
	if err != nil {
		return fmt.Errorf("encode %s: %w", key, err)
	}
	m[key] = b
	return nil
}

// marshal encodes without HTML escaping so readmes and descriptions keep
// their upstream bytes.
func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
