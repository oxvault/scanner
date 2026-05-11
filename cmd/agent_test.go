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
		// Remote-scheme targets that the scanner's resolver handles —
		// the agent passes them through verbatim instead of joining to cwd
		// (see resolveTarget + isRemoteSchemeTarget).
		"hf:mcpotato/42-eicar-street",
		"github:user/repo",
		"@playwright/mcp",
		"mcpotato/42-eicar-street",
	}
	for _, name := range good {
		if err := validateArtifactName(name); err != nil {
			t.Errorf("validateArtifactName(%q) = %v, want nil", name, err)
		}
	}

	bad := map[string]string{
		"":                  "empty",
		".":                 "leading dot",
		"..":                "leading dot",
		"../escape":         "embedded ..",
		"../../etc/shadow":  "embedded ..",
		"/etc/passwd":       "absolute path",
		"a\\b":              "backslash",
		"foo..bar":          "embedded ..",
		".hidden":           "leading dot",
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

// TestIsRemoteSchemeTarget pins which artifact names the agent forwards
// to the scanner's resolver verbatim (vs. trying to locate locally).
// Regression here ships as a Re-scan button that fails with "could not
// locate artifact" on every npm / HF / GitHub target.
func TestIsRemoteSchemeTarget(t *testing.T) {
	t.Parallel()
	remote := []string{
		"hf:mcpotato/42-eicar-street",
		"hf:openai/clip-vit-base-patch32",
		"github:user/repo",
		"@playwright/mcp",
		"@anthropic/mcp-server",
		"mcpotato/42-eicar-street", // bare npm form, single slash
	}
	for _, n := range remote {
		if !isRemoteSchemeTarget(n) {
			t.Errorf("isRemoteSchemeTarget(%q) = false, want true", n)
		}
	}
	local := []string{
		"asana-mcp",
		"cmd-injection",
		"server.v2",
		"my_server",
		"garbage.onnx", // file basename, no slash → local probe
	}
	for _, n := range local {
		if isRemoteSchemeTarget(n) {
			t.Errorf("isRemoteSchemeTarget(%q) = true, want false", n)
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
