package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// writeConfigFile creates a temp MCP client config file with the given server map.
// Returns the path to the created file.
func writeConfigFile(t *testing.T, dir, name string, servers map[string]mcpServerEntry) string {
	t.Helper()

	raw := mcpClientConfig{MCPServers: servers}
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	return path
}

// ── ParseConfigFile ────────────────────────────────────────────────────────

func TestParseConfigFile_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigFile(t, dir, "config.json", map[string]mcpServerEntry{
		"filesystem": {
			Command: "npx",
			Args:    []string{"-y", "@modelcontextprotocol/server-filesystem"},
			Env:     map[string]string{"ROOT": "/tmp"},
		},
		"github": {
			Command: "npx",
			Args:    []string{"-y", "@modelcontextprotocol/server-github"},
		},
	})

	servers, err := ParseConfigFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}

	// Verify all servers have the source path set
	for _, s := range servers {
		if s.Source != path {
			t.Errorf("expected Source=%q, got %q", path, s.Source)
		}
	}

	// Find and validate the "filesystem" server
	var fs *MCPServerConfig
	for i := range servers {
		if servers[i].Name == "filesystem" {
			fs = &servers[i]
			break
		}
	}
	if fs == nil {
		t.Fatal("expected 'filesystem' server in results")
	}
	if fs.Command != "npx" {
		t.Errorf("expected Command='npx', got %q", fs.Command)
	}
	if len(fs.Args) != 2 || fs.Args[1] != "@modelcontextprotocol/server-filesystem" {
		t.Errorf("unexpected Args: %v", fs.Args)
	}
	if fs.Env["ROOT"] != "/tmp" {
		t.Errorf("expected Env.ROOT='/tmp', got %q", fs.Env["ROOT"])
	}
}

func TestParseConfigFile_MissingFile_ReturnsNilNoError(t *testing.T) {
	servers, err := ParseConfigFile("/nonexistent/path/config.json")
	if err != nil {
		t.Errorf("expected no error for missing file, got: %v", err)
	}
	if servers != nil {
		t.Errorf("expected nil servers for missing file, got %v", servers)
	}
}

func TestParseConfigFile_MalformedJSON_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`{not valid json`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := ParseConfigFile(path)
	if err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
}

func TestParseConfigFile_EmptyMCPServers_ReturnsEmptySlice(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigFile(t, dir, "empty.json", map[string]mcpServerEntry{})

	servers, err := ParseConfigFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(servers))
	}
}

func TestParseConfigFile_NoMCPServersKey_ReturnsEmptySlice(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "no-key.json")
	// Valid JSON but no mcpServers key — e.g. a globalShortcut-only config
	if err := os.WriteFile(path, []byte(`{"globalShortcut":"Ctrl+Shift+O"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	servers, err := ParseConfigFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 0 {
		t.Errorf("expected 0 servers for config with no mcpServers key, got %d", len(servers))
	}
}

func TestParseConfigFile_ServerWithNoArgs(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigFile(t, dir, "minimal.json", map[string]mcpServerEntry{
		"simple": {Command: "python3"},
	})

	servers, err := ParseConfigFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	if servers[0].Command != "python3" {
		t.Errorf("expected Command='python3', got %q", servers[0].Command)
	}
	if servers[0].Args != nil && len(servers[0].Args) != 0 {
		t.Errorf("expected nil/empty Args, got %v", servers[0].Args)
	}
}

func TestParseConfigFile_ServerName_SetCorrectly(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigFile(t, dir, "named.json", map[string]mcpServerEntry{
		"my-awesome-server": {Command: "node", Args: []string{"server.js"}},
	})

	servers, err := ParseConfigFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	if servers[0].Name != "my-awesome-server" {
		t.Errorf("expected Name='my-awesome-server', got %q", servers[0].Name)
	}
}

// ── Discover ───────────────────────────────────────────────────────────────

func TestDiscover_SpecificFile_ParsesCorrectly(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigFile(t, dir, "claude_desktop_config.json", map[string]mcpServerEntry{
		"search": {Command: "npx", Args: []string{"-y", "mcp-search"}},
	})

	result, err := Discover(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(result.Servers))
	}
	if result.Servers[0].Name != "search" {
		t.Errorf("expected server name 'search', got %q", result.Servers[0].Name)
	}
	if len(result.SourceFiles) != 1 || result.SourceFiles[0] != path {
		t.Errorf("expected SourceFiles=[%q], got %v", path, result.SourceFiles)
	}
}

func TestDiscover_SpecificFile_Missing_ReturnsEmptyNoError(t *testing.T) {
	result, err := Discover("/nonexistent/path/config.json")
	if err != nil {
		t.Fatalf("unexpected error for missing file: %v", err)
	}
	if len(result.Servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(result.Servers))
	}
	if len(result.SourceFiles) != 0 {
		t.Errorf("expected 0 source files, got %v", result.SourceFiles)
	}
}

func TestDiscover_SpecificFile_Malformed_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`{{invalid`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Discover(path)
	if err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
}

func TestDiscover_Auto_FindsFilesInKnownLocations(t *testing.T) {
	// Override HOME so knownConfigPaths() points into a temp directory we control.
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	// Create .claude dir and a desktop config
	claudeDir := filepath.Join(dir, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeConfigFile(t, claudeDir, "claude_desktop_config.json", map[string]mcpServerEntry{
		"fs":     {Command: "npx", Args: []string{"-y", "mcp-fs"}},
		"github": {Command: "npx", Args: []string{"-y", "mcp-github"}},
	})

	// Create .cursor dir with its config
	cursorDir := filepath.Join(dir, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeConfigFile(t, cursorDir, "mcp.json", map[string]mcpServerEntry{
		"cursor-search": {Command: "node", Args: []string{"search.js"}},
	})

	result, err := Discover("auto")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should find 3 servers total across 2 files
	if len(result.Servers) != 3 {
		t.Errorf("expected 3 servers, got %d: %v", len(result.Servers), result.Servers)
	}
	if len(result.SourceFiles) != 2 {
		t.Errorf("expected 2 source files, got %v", result.SourceFiles)
	}

	// Verify server names are present
	names := make([]string, len(result.Servers))
	for i, s := range result.Servers {
		names[i] = s.Name
	}
	for _, want := range []string{"fs", "github", "cursor-search"} {
		if !slices.Contains(names, want) {
			t.Errorf("expected server %q in results, got names: %v", want, names)
		}
	}
}

func TestDiscover_Auto_NoConfigsPresent_ReturnsEmpty(t *testing.T) {
	// Point HOME at an empty temp directory — no known config files exist.
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	result, err := Discover("auto")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Servers) != 0 {
		t.Errorf("expected 0 servers when no config files exist, got %d", len(result.Servers))
	}
	if len(result.SourceFiles) != 0 {
		t.Errorf("expected 0 source files, got %v", result.SourceFiles)
	}
}

func TestDiscover_Auto_MalformedFile_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	claudeDir := filepath.Join(dir, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Write malformed JSON to a known config path
	if err := os.WriteFile(
		filepath.Join(claudeDir, "claude_desktop_config.json"),
		[]byte(`{broken`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	_, err := Discover("auto")
	if err == nil {
		t.Error("expected error when a config file contains malformed JSON, got nil")
	}
}

func TestDiscover_Auto_SkipsEmptyConfigFiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	// Create a config with no servers
	claudeDir := filepath.Join(dir, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeConfigFile(t, claudeDir, "claude_desktop_config.json", map[string]mcpServerEntry{})

	// Create a config with servers
	cursorDir := filepath.Join(dir, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeConfigFile(t, cursorDir, "mcp.json", map[string]mcpServerEntry{
		"myserver": {Command: "python3"},
	})

	result, err := Discover("auto")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only the cursor file should appear in SourceFiles (empty config is skipped)
	if len(result.SourceFiles) != 1 {
		t.Errorf("expected 1 source file (empty config skipped), got %v", result.SourceFiles)
	}
	if len(result.Servers) != 1 {
		t.Errorf("expected 1 server, got %d", len(result.Servers))
	}
}

func TestDiscover_SpecificFile_EmptyServers_NoSourceFile(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigFile(t, dir, "empty.json", map[string]mcpServerEntry{})

	result, err := Discover(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No servers → SourceFiles should be empty (nothing useful was found)
	if len(result.SourceFiles) != 0 {
		t.Errorf("expected no source files for empty config, got %v", result.SourceFiles)
	}
}

// ── knownConfigPaths ───────────────────────────────────────────────────────

func TestKnownConfigPaths_ContainsClaudeDesktop(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home directory")
	}

	paths := knownConfigPaths()
	want := filepath.Join(home, ".claude", "claude_desktop_config.json")

	if !slices.Contains(paths, want) {
		t.Errorf("expected Claude Desktop config path %q in known paths, got %v", want, paths)
	}
}

func TestKnownConfigPaths_ContainsCursor(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home directory")
	}

	paths := knownConfigPaths()
	want := filepath.Join(home, ".cursor", "mcp.json")

	if !slices.Contains(paths, want) {
		t.Errorf("expected Cursor config path %q in known paths, got %v", want, paths)
	}
}

func TestKnownConfigPaths_NoDuplicates(t *testing.T) {
	paths := knownConfigPaths()
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		if seen[p] {
			t.Errorf("duplicate config path: %q", p)
		}
		seen[p] = true
	}
}
