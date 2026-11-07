package policy

import (
	"bufio"
	"os"
	"strings"
	"testing"

	"github.com/pogao/pkgwarden/internal/ecosystem"
)

// typosquatFinding assesses an established, well-downloaded package so that
// typosquatting is the only signal that can fire.
func typosquatFinding(eco ecosystem.Ecosystem, name string) (string, bool) {
	a := assessHeuristics(&Package{
		Ecosystem: eco, Name: name, Created: daysAgo(3000), WeeklyDownloads: 1_000_000,
		Releases: []Release{{Version: "1.0.0", Published: daysAgo(3000)}},
	})
	for _, f := range a.Release("1.0.0").Findings {
		if f.Rule == RuleTyposquat {
			return f.Reason, true
		}
	}
	return "", false
}

func TestTyposquat(t *testing.T) {
	tests := []struct {
		eco  ecosystem.Ecosystem
		name string
		want string // empty when the name must not be flagged
	}{
		{ecosystem.Npm, "lodahs", `resembles popular package "lodash" (one edit away)`},
		{ecosystem.Npm, "expresss", `"express" (one edit away)`},
		{ecosystem.Npm, "typescirpt", `"typescript" (one edit away)`},
		{ecosystem.Npm, "tyepscirpt", `"typescript" (two edits away)`},
		{ecosystem.Npm, "reactdom", `"react-dom" (differs only in separators)`},
		{ecosystem.Npm, "crossenv", `"cross-env" (differs only in separators)`},
		{ecosystem.Npm, "l0dash", `"lodash" (differs only by look-alike characters)`},
		{ecosystem.Npm, "rnocha", `"mocha" (differs only by look-alike characters)`},
		{ecosystem.Npm, "@bable/core", `"@babel/core" (one edit away)`},
		{ecosystem.Npm, "@types/nodes", `"@types/node" (one edit away)`},
		{ecosystem.Npm, "lodash", ""},
		{ecosystem.Npm, "LoDash", ""},
		{ecosystem.Npm, "user-event", ""},
		{ecosystem.Npm, "mss", ""},
		{ecosystem.Npm, "left-pad", ""},
		{ecosystem.Npm, "lodash-utils-extra", ""},

		{ecosystem.PyPI, "reqeusts", `"requests" (one edit away)`},
		{ecosystem.PyPI, "pythondateutil", `"python-dateutil" (differs only in separators)`},
		{ecosystem.PyPI, "djang0", `"django" (differs only by look-alike characters)`},
		{ecosystem.PyPI, "python_dateutil", ""},
		{ecosystem.PyPI, "Requests", ""},
		{ecosystem.PyPI, "ruamel_yaml", ""},

		{ecosystem.RubyGems, "rai1s", `"rails" (differs only by look-alike characters)`},
		{ecosystem.RubyGems, "nokogirl", `"nokogiri" (one edit away)`},
		{ecosystem.RubyGems, "rails", ""},

		{ecosystem.Cargo, "tokoi", `"tokio" (one edit away)`},
		{ecosystem.Cargo, "serdejson", `"serde_json" (differs only in separators)`},
		{ecosystem.Cargo, "serde-json", ""},

		{ecosystem.Go, "github.com/sirupsen/logruss", `"github.com/sirupsen/logrus" (one edit away)`},
		{ecosystem.Go, "github.com/slrupsen/logrus", `"github.com/sirupsen/logrus" (one edit away)`},
		{ecosystem.Go, "githuh.com/stretchr/testify", `"github.com/stretchr/testify" (one edit away)`},
		{ecosystem.Go, "golang.org/x/crypt0", `"golang.org/x/crypto" (differs only by look-alike characters)`},
		{ecosystem.Go, "github.com/Sirupsen/logrus", ""},
		{ecosystem.Go, "github.com/go-redis/redis/v9", ""},
		{ecosystem.Go, "github.com/sirupsen/logrus/v2", ""},
		{ecosystem.Go, "golang.org/x/nett", ""},
	}
	for _, tt := range tests {
		t.Run(string(tt.eco)+"/"+tt.name, func(t *testing.T) {
			got, flagged := typosquatFinding(tt.eco, tt.name)
			switch {
			case tt.want == "" && flagged:
				t.Errorf("flagged: %s", got)
			case tt.want != "" && !strings.Contains(got, tt.want):
				t.Errorf("reason %q, want it to contain %q", got, tt.want)
			}
		})
	}
}

// TestPopularNamesAreNotTyposquats guards the lists against flagging their
// own entries, which would warn on the very packages they protect, and
// against an entry the ecosystem's normalization would not recognize.
func TestPopularNamesAreNotTyposquats(t *testing.T) {
	for _, eco := range ecosystem.All() {
		names := readPopular(t, eco)
		if len(names) < 250 {
			t.Errorf("%s: only %d popular names", eco, len(names))
		}
		for _, name := range names {
			if reason, flagged := typosquatFinding(eco, name); flagged {
				t.Errorf("%s: popular package %q flagged: %s", eco, name, reason)
			}
		}
	}
}

func readPopular(t *testing.T, eco ecosystem.Ecosystem) []string {
	t.Helper()
	f, err := os.Open("popular/" + string(eco) + ".txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var names []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		if line = strings.TrimSpace(line); line != "" {
			names = append(names, line)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return names
}

func BenchmarkTyposquatLookup(b *testing.B) {
	popularIndexes()
	for b.Loop() {
		resembles(ecosystem.Npm, "some-unremarkable-package")
	}
}
