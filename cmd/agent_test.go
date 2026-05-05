package main

import (
	"strings"
	"testing"
)

// TestValidateArtifactName guards the path-traversal boundary. The agent
// receives the artifact name from the platform and joins it under cwd —
// this check is the only thing keeping a malicious / compromised name
// from probing files outside the working directory.
func TestValidateArtifactName(t *testing.T) {
	t.Parallel()

	good := []string{
		"asana-mcp",
		"cmd-injection",
		"my_server",
		"server.v2",
		"@scope_pkg",
	}
	for _, name := range good {
		if err := validateArtifactName(name); err != nil {
			t.Errorf("validateArtifactName(%q) = %v, want nil", name, err)
		}
	}

	bad := map[string]string{
		"":                "empty",
		".":               "leading dot",
		"..":              "leading dot",
		"../escape":       "path separator",
		"../../etc/shadow":"path separator",
		"a/b":             "path separator",
		"a\\b":            "backslash",
		"foo..bar":        "embedded ..",
		".hidden":         "leading dot",
	}
	for name, why := range bad {
		if err := validateArtifactName(name); err == nil {
			t.Errorf("validateArtifactName(%q) = nil, want error (%s)", name, why)
		}
	}
}

// TestParseTargetMaps covers the --target-map=name=path repeatable flag.
func TestParseTargetMaps(t *testing.T) {
	t.Parallel()

	got, err := parseTargetMaps([]string{
		"asana-mcp=./node_modules/@asana/mcp-server",
		"cmd-injection=./examples/cmd-injection",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["asana-mcp"] != "./node_modules/@asana/mcp-server" {
		t.Errorf("asana-mcp mapping wrong: %q", got["asana-mcp"])
	}
	if got["cmd-injection"] != "./examples/cmd-injection" {
		t.Errorf("cmd-injection mapping wrong: %q", got["cmd-injection"])
	}

	bad := []string{
		"missing-equals",
		"=path-only",
		"name=", // empty path
	}
	for _, s := range bad {
		if _, err := parseTargetMaps([]string{s}); err == nil {
			t.Errorf("parseTargetMaps(%q) = nil, want error", s)
		}
	}
}

// TestCandidatePaths is a sanity check that the probe order stays
// stable + the npm-scope branch only kicks in when node_modules exists.
func TestCandidatePaths(t *testing.T) {
	t.Parallel()

	cwd := t.TempDir()
	got := candidatePaths(cwd, "asana-mcp")
	if len(got) < 4 {
		t.Fatalf("expected ≥4 candidate paths, got %d", len(got))
	}
	// First entry is always the bare cwd/<name> form.
	if !strings.HasSuffix(got[0], "asana-mcp") || strings.Contains(got[0], "examples") {
		t.Errorf("first candidate should be cwd/<name>, got %q", got[0])
	}
}
