package advisory

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pogao/pkgwarden/internal/ecosystem"
)

const (
	defaultOpenSSFArchive = "https://codeload.github.com/ossf/malicious-packages/tar.gz/refs/heads/main"
	openSSFArchiveLimit   = 2 << 30
	openSSFUnpackedLimit  = 16 << 30
	openSSFEntryLimit     = 4 << 20
)

// OpenSSF serves the OpenSSF malicious-packages dataset from an in-memory
// index that Refresh rebuilds from the repository archive.
type OpenSSF struct {
	client  *http.Client
	archive string
	index   atomic.Pointer[map[pkgKey][]Advisory]
}

type pkgKey struct {
	eco  ecosystem.Ecosystem
	name string // normalized
}

func keyOf(eco ecosystem.Ecosystem, name string) pkgKey {
	return pkgKey{eco: eco, name: eco.Normalize(name)}
}

// NewOpenSSF returns a Source over the dataset archive at archiveURL, or
// the main branch on GitHub when archiveURL is empty. It holds no data until
// Refresh or Run succeeds. A nil client means http.DefaultClient.
func NewOpenSSF(client *http.Client, archiveURL string) *OpenSSF {
	if client == nil {
		client = http.DefaultClient
	}
	if archiveURL == "" {
		archiveURL = defaultOpenSSFArchive
	}
	return &OpenSSF{client: client, archive: archiveURL}
}

// Lookup returns the malicious-package reports for a package. It fails
// until the dataset has loaded once.
func (o *OpenSSF) Lookup(_ context.Context, eco ecosystem.Ecosystem, name string) ([]Advisory, error) {
	idx := o.index.Load()
	if idx == nil {
		return nil, errors.New("openssf lookup: dataset not loaded yet")
	}
	return (*idx)[keyOf(eco, name)], nil
}

// Refresh downloads the dataset and replaces the index. On any failure the
// previous index stays in place.
func (o *OpenSSF) Refresh(ctx context.Context) error {
	idx, err := o.load(ctx)
	if err != nil {
		return fmt.Errorf("openssf refresh: %w", err)
	}
	o.index.Store(&idx)
	return nil
}

// Run refreshes the dataset immediately and then every interval until ctx
// is done, logging failures. A non-positive interval refreshes only once.
func (o *OpenSSF) Run(ctx context.Context, interval time.Duration) {
	refresh := func() {
		if err := o.Refresh(ctx); err != nil && ctx.Err() == nil {
			slog.ErrorContext(ctx, "advisory dataset refresh failed", "source", "openssf", "err", err)
		}
	}
	refresh()
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		}
	}
}

func (o *OpenSSF) load(ctx context.Context) (map[pkgKey][]Advisory, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.archive, nil)
	if err != nil {
		return nil, err
	}
	resp, err := send(o.client, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	gz, err := gzip.NewReader(capped(resp.Body, openSSFArchiveLimit))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(capped(gz, openSSFUnpackedLimit))
	idx := make(map[pkgKey][]Advisory)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return idx, nil
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg || !isMaliciousEntry(hdr.Name) {
			continue
		}
		raw, err := io.ReadAll(capped(tr, openSSFEntryLimit))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", hdr.Name, err)
		}
		var v osvVuln
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, fmt.Errorf("%s: %w", hdr.Name, err)
		}
		indexOSV(idx, &v)
	}
}

// isMaliciousEntry reports whether an archive path such as
// "malicious-packages-main/osv/malicious/npm/foo/MAL-2024-1.json" holds a
// live report. Withdrawn reports live under osv/withdrawn and are skipped.
func isMaliciousEntry(name string) bool {
	_, rel, ok := strings.Cut(name, "/")
	return ok && strings.HasPrefix(rel, "osv/malicious/") && path.Ext(rel) == ".json"
}

func indexOSV(idx map[pkgKey][]Advisory, v *osvVuln) {
	seen := make(map[pkgKey]bool)
	for _, a := range v.Affected {
		eco, ok := ecosystem.FromOSV(a.Package.Ecosystem)
		if !ok {
			continue
		}
		k := keyOf(eco, a.Package.Name)
		if seen[k] {
			continue
		}
		seen[k] = true
		adv, ok := osvAdvisory(v, eco, a.Package.Name)
		if !ok {
			continue
		}
		adv.Source = "openssf"
		adv.Kind = Malicious
		idx[k] = append(idx[k], adv)
	}
}
