package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := run([]string{"--version"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "lockbox-eso-provider") {
		t.Fatalf("unexpected version output: %q", stdout.String())
	}
}

func TestParseConfigRequiresAllowlist(t *testing.T) {
	t.Setenv("LOCKBOX_ALLOWED_SECRET_IDS", "")
	_, _, err := parseConfig([]string{"--service-account-id=ajeserviceaccount"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "allowed Lockbox secret ID") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseConfigSplitsAllowlist(t *testing.T) {
	t.Setenv("LOCKBOX_ALLOWED_SECRET_IDS", "e6qone, e6qtwo")
	cfg, _, err := parseConfig([]string{"--service-account-id=ajeserviceaccount"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.allowedSecretIDs) != 2 || cfg.allowedSecretIDs[1] != "e6qtwo" {
		t.Fatalf("unexpected allowlist: %#v", cfg.allowedSecretIDs)
	}
}
