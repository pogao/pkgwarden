package main

import (
	"os"
	"strings"
	"testing"

	"github.com/pogao/pkgwarden/internal/advisory"
)

const blockSeverityEnv = "PKGWARDEN_BLOCK_SEVERITY"

func unsetEnv(t *testing.T, key string) {
	t.Helper()
	t.Setenv(key, "")
	os.Unsetenv(key)
}

func TestBlockSeverity(t *testing.T) {
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
			unsetEnv(t, blockSeverityEnv)
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
	for _, value := range []string{"moderate", "severe", "", "9.0"} {
		t.Run(value, func(t *testing.T) {
			unsetEnv(t, blockSeverityEnv)
			_, err := parseConfig([]string{"-block-severity", value})
			if err == nil || !strings.Contains(err.Error(), "low, medium, high, critical or none") {
				t.Errorf("err = %v, want an error naming the accepted values", err)
			}
		})
	}
}
