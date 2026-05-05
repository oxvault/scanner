package userconfig

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoad_MissingFile guarantees the agent / push paths can call
// Load() without a config file present without surfacing an error.
func TestLoad_MissingFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OXVAULT_CONFIG", filepath.Join(dir, "does-not-exist.toml"))

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() with missing file = %v, want nil", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil Config")
	}
	if cfg.Push.Auto || cfg.Push.APIKey != "" {
		t.Errorf("expected zero Config, got %+v", cfg)
	}
}

// TestLoad_HappyPath parses a well-formed TOML file and asserts the
// schema map maps cleanly to the Push struct.
func TestLoad_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := `
[push]
auto = true
api_key = "ox_test123"
api_url = "http://localhost:8080"
quiet  = true
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Setenv("OXVAULT_CONFIG", path)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if !cfg.Push.Auto {
		t.Errorf("Push.Auto = false, want true")
	}
	if cfg.Push.APIKey != "ox_test123" {
		t.Errorf("Push.APIKey = %q, want ox_test123", cfg.Push.APIKey)
	}
	if cfg.Push.APIURL != "http://localhost:8080" {
		t.Errorf("Push.APIURL = %q, want http://localhost:8080", cfg.Push.APIURL)
	}
	if !cfg.Push.Quiet {
		t.Errorf("Push.Quiet = false, want true")
	}
}

// TestLoad_MalformedTOML surfaces a parse error to the caller — both
// `oxvault push` and `oxvault agent` ignore this for now (uc, _ :=
// userconfig.Load()), but a future --validate-config flag relies on
// the error being non-nil.
func TestLoad_MalformedTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("not = valid = toml"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Setenv("OXVAULT_CONFIG", path)

	if _, err := Load(); err == nil {
		t.Fatal("Load() on malformed TOML = nil, want error")
	}
}

// TestPath_HonorsEnvOverride confirms $OXVAULT_CONFIG wins over the
// default ~/.oxvault/config.toml resolution.
func TestPath_HonorsEnvOverride(t *testing.T) {
	t.Setenv("OXVAULT_CONFIG", "/tmp/oxvault-test.toml")
	got, err := Path()
	if err != nil {
		t.Fatalf("Path() = %v", err)
	}
	if got != "/tmp/oxvault-test.toml" {
		t.Errorf("Path() = %q, want /tmp/oxvault-test.toml", got)
	}
}
