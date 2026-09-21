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

	err := run([]string{"--version"}, strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "ycr-credential-provider") {
		t.Fatalf("unexpected version output: %q", stdout.String())
	}
}

func TestRejectsMultipleJSONValues(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run(nil, strings.NewReader(`{} {}`), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
		t.Fatalf("unexpected error: %v", err)
	}
}
