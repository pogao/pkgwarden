package main

import (
	"errors"
	"flag"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/pogao/pkgwarden/internal/advisory"
)

const blockSeverityEnv = "PKGWARDEN_BLOCK_SEVERITY"

// clearEnv unsets every variable parseConfig reads, so a value in the
// developer's shell cannot leak into a test. t.Setenv restores each one
// when the test ends.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "PKGWARDEN_") || k == "GITHUB_TOKEN" {
			t.Setenv(k, "")
			os.Unsetenv(k)
		}
	}
}

func TestBlockSeverity(t *testing.T) {
	clearEnv(t)
	tests := []struct {
		args []string
		want advisory.Severity
	}{
		{nil, advisory.SeverityHigh},
		{[]string{"-block-severity", "none"}, advisory.SeverityUnknown},
		{[]string{"-block-severity", "low"}, advisory.SeverityLow},
		{[]string{"-block-severity", "medium"}, advisory.SeverityMedium},
		{[]string{"-block-severity", "high"}, advisory.SeverityHigh},
		{[]string{"-block-severity", "CRITICAL"}, advisory.SeverityCritical},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			c, err := parseConfig(tt.args)
			if err != nil {
				t.Fatal(err)
			}
			if c.policy.BlockSeverity != tt.want {
				t.Errorf("BlockSeverity = %v, want %v", c.policy.BlockSeverity, tt.want)
			}
		})
	}
}

func TestBlockSeverityFromEnv(t *testing.T) {
	clearEnv(t)
	t.Setenv(blockSeverityEnv, "critical")
	c, err := parseConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.policy.BlockSeverity != advisory.SeverityCritical {
		t.Errorf("BlockSeverity = %v, want CRITICAL from %s", c.policy.BlockSeverity, blockSeverityEnv)
	}
	c, err = parseConfig([]string{"-block-severity", "low"})
	if err != nil {
		t.Fatal(err)
	}
	if c.policy.BlockSeverity != advisory.SeverityLow {
		t.Errorf("BlockSeverity = %v, want the flag's LOW to win over the environment", c.policy.BlockSeverity)
	}
}

func TestBlockSeverityInvalid(t *testing.T) {
	clearEnv(t)
	for _, value := range []string{"moderate", "severe", "", "9.0"} {
		t.Run(value, func(t *testing.T) {
			_, err := parseConfig([]string{"-block-severity", value})
			if err == nil || !strings.Contains(err.Error(), "low, medium, high, critical or none") {
				t.Errorf("err = %v, want an error naming the accepted values", err)
			}
		})
	}
}

func TestHelpHidesGitHubToken(t *testing.T) {
	clearEnv(t)
	t.Setenv("GITHUB_TOKEN", "fake-token-123")
	out, err := os.CreateTemp(t.TempDir(), "help")
	if err != nil {
		t.Fatal(err)
	}
	stderr := os.Stderr
	os.Stderr = out
	_, err = parseConfig([]string{"-h"})
	os.Stderr = stderr
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("err = %v, want flag.ErrHelp", err)
	}
	help, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(help), "-ghsa-token") {
		t.Fatalf("help output lacks -ghsa-token:\n%s", help)
	}
	if strings.Contains(string(help), "fake-token-123") {
		t.Errorf("help output prints the GitHub token:\n%s", help)
	}
}

func TestGHSATokenPrecedence(t *testing.T) {
	tests := []struct {
		name        string
		githubToken string
		envToken    *string
		args        []string
		want        string
	}{
		{name: "nothing set"},
		{name: "GITHUB_TOKEN", githubToken: "gh", want: "gh"},
		{name: "PKGWARDEN_GHSA_TOKEN wins over GITHUB_TOKEN", githubToken: "gh", envToken: ptr("env"), want: "env"},
		{name: "empty PKGWARDEN_GHSA_TOKEN turns the source off", githubToken: "gh", envToken: ptr("")},
		{name: "flag wins over both", githubToken: "gh", envToken: ptr("env"), args: []string{"-ghsa-token", "flag"}, want: "flag"},
		{name: "empty flag turns the source off", githubToken: "gh", args: []string{"-ghsa-token", ""}},
	}
	clearEnv(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GITHUB_TOKEN", tt.githubToken)
			if tt.envToken != nil {
				t.Setenv("PKGWARDEN_GHSA_TOKEN", *tt.envToken)
			}
			c, err := parseConfig(tt.args)
			if err != nil {
				t.Fatal(err)
			}
			if c.ghsaToken != tt.want {
				t.Errorf("ghsaToken = %q, want %q", c.ghsaToken, tt.want)
			}
		})
	}
}

func ptr(s string) *string { return &s }

func TestLogLevel(t *testing.T) {
	tests := []struct {
		args []string
		want slog.Level
	}{
		{nil, slog.LevelInfo},
		{[]string{"-log-level", "debug"}, slog.LevelDebug},
		{[]string{"-log-level", "WARN"}, slog.LevelWarn},
		{[]string{"-log-level", "error"}, slog.LevelError},
	}
	clearEnv(t)
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			c, err := parseConfig(tt.args)
			if err != nil {
				t.Fatal(err)
			}
			if c.logLevel != tt.want {
				t.Errorf("logLevel = %v, want %v", c.logLevel, tt.want)
			}
		})
	}
}

func TestLogLevelInvalid(t *testing.T) {
	clearEnv(t)
	t.Run("flag", func(t *testing.T) {
		if _, err := parseConfig([]string{"-log-level", "loud"}); err == nil {
			t.Error("parseConfig accepted -log-level loud")
		}
	})
	t.Run("environment", func(t *testing.T) {
		t.Setenv("PKGWARDEN_LOG_LEVEL", "loud")
		if _, err := parseConfig(nil); err == nil {
			t.Error("parseConfig accepted PKGWARDEN_LOG_LEVEL=loud")
		}
	})
}
