package main

import (
	"strings"
	"testing"
)

// TestStarterConfigShape asserts the `oxvault init` template stays
// inert by default (every key commented out) so users explicitly opt
// into auto-push instead of getting it on first install.
func TestStarterConfigShape(t *testing.T) {
	t.Parallel()

	mustHave := []string{
		"[push]",
		"# auto =",
		"# api_key =",
		"# api_url =",
		"# console_url =",
	}
	for _, frag := range mustHave {
		if !strings.Contains(starterConfig, frag) {
			t.Errorf("starterConfig missing %q", frag)
		}
	}

	// Sanity check: nothing should be uncommented (every key line in
	// the template starts with "#"). If a line begins with one of the
	// known keys without a leading "#", the file would activate by
	// default — exactly what we don't want.
	for _, line := range strings.Split(starterConfig, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "[") {
			continue
		}
		t.Errorf("starterConfig has uncommented line: %q", line)
	}
}
