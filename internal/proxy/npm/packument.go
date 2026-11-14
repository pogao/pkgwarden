package npm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"golang.org/x/mod/semver"

	"github.com/pogao/pkgwarden/internal/ecosystem"
	"github.com/pogao/pkgwarden/internal/policy"
)

// snapshot is a packument as the metadata cache keeps it: the upstream
// document, which filtering parses and rewrites for each request, and the
// facts a policy check needs, parsed once.
type snapshot struct {
	raw []byte
	// pkg has no WeeklyDownloads, which come from another document.
	pkg policy.Package
	// files maps each dist.tarball file name to its version.
	files map[string]string
}

// releaseOverhead approximates the memory a release takes in a snapshot
// besides its version string.
const releaseOverhead = 256

func parseSnapshot(name string, raw []byte) (*snapshot, int64, error) {
	var doc struct {
		Versions map[string]struct {
			NpmUser struct {
				Name string `json:"name"`
			} `json:"_npmUser"`
			Scripts map[string]json.RawMessage `json:"scripts"`
			Dist    struct {
				Tarball json.RawMessage `json:"tarball"`
			} `json:"dist"`
		} `json:"versions"`
		Time        map[string]json.RawMessage `json:"time"`
		Maintainers []struct {
			Name string `json:"name"`
		} `json:"maintainers"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, 0, fmt.Errorf("decode packument: %w", err)
	}
	published := func(key string) time.Time {
		var s string
		if json.Unmarshal(doc.Time[key], &s) != nil {
			return time.Time{}
		}
		t, _ := time.Parse(time.RFC3339, s)
		return t
	}
	var maintainers []string
	for _, m := range doc.Maintainers {
		maintainers = append(maintainers, m.Name)
	}
	s := &snapshot{
		raw:   raw,
		pkg:   policy.Package{Ecosystem: ecosystem.Npm, Name: name, Created: published("created")},
		files: make(map[string]string, len(doc.Versions)),
	}
	size := int64(len(raw))
	for v, m := range doc.Versions {
		publishers := maintainers
		if m.NpmUser.Name != "" {
			publishers = []string{m.NpmUser.Name}
		}
		r := policy.Release{Version: v, Published: published(v), Publishers: publishers}
		for _, script := range []string{"preinstall", "install", "postinstall"} {
			if _, ok := m.Scripts[script]; ok {
				r.InstallScripts = true
			}
		}
		s.pkg.Releases = append(s.pkg.Releases, r)
		var tarball string
		if json.Unmarshal(m.Dist.Tarball, &tarball) == nil {
			s.files[path.Base(tarball)] = v
		}
		size += int64(2*len(v)) + releaseOverhead
	}
	return s, size, nil
}

// version returns the version whose dist.tarball has the requested file
// name. Old npm clients named the file after the unnormalized version, so
// express-3.0.0rc3.tgz belongs to 3.0.0-rc3. Failing that, it extracts the
// version from a file name such as widget-1.2.3.tgz. A name that does not
// fit yields a string no release matches, so the policy blocks it as
// unknown.
func (s *snapshot) version(rt route) string {
	if v, ok := s.files[rt.file]; ok {
		return v
	}
	unscoped := rt.name[strings.LastIndex(rt.name, "/")+1:]
	v, _ := strings.CutPrefix(strings.TrimSuffix(rt.file, ".tgz"), unscoped+"-")
	return v
}

// packument is a full npm package document. Every field is kept raw so the
// parts pkgwarden does not rewrite reach the client unchanged.
type packument struct {
	doc      map[string]json.RawMessage
	versions map[string]manifest
	times    map[string]json.RawMessage
	distTags map[string]string
}

// manifest is one entry of a packument's versions object.
type manifest struct {
	raw  map[string]json.RawMessage
	dist map[string]json.RawMessage
}

func parsePackument(b []byte) (*packument, error) {
	p := &packument{}
	if err := json.Unmarshal(b, &p.doc); err != nil {
		return nil, fmt.Errorf("decode packument: %w", err)
	}
	var versions map[string]json.RawMessage
	for key, dst := range map[string]any{"versions": &versions, "time": &p.times, "dist-tags": &p.distTags} {
		if b, ok := p.doc[key]; ok {
			if err := json.Unmarshal(b, dst); err != nil {
				return nil, fmt.Errorf("decode packument %s: %w", key, err)
			}
		}
	}
	p.versions = make(map[string]manifest, len(versions))
	for v, b := range versions {
		var m manifest
		if err := json.Unmarshal(b, &m.raw); err != nil {
			return nil, fmt.Errorf("decode packument version %s: %w", v, err)
		}
		if d, ok := m.raw["dist"]; ok {
			if err := json.Unmarshal(d, &m.dist); err != nil {
				return nil, fmt.Errorf("decode packument version %s: %w", v, err)
			}
		}
		p.versions[v] = m
	}
	return p, nil
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

// latest returns the version the latest tag names, or the highest version
// when there is no latest tag.
func (p *packument) latest() string {
	latest := p.distTags["latest"]
	if latest == "" {
		for v := range p.versions {
			if latest == "" || semver.Compare("v"+v, "v"+latest) > 0 {
				latest = v
			}
		}
	}
	return latest
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
