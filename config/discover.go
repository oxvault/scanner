package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// MCPServerConfig holds the configuration for a single MCP server entry
// parsed from a client config file (Claude Desktop, Cursor, VS Code, etc.)
type MCPServerConfig struct {
	// Name is the server key from the config file (e.g. "filesystem", "github")
	Name string

	// Command is the executable to run (e.g. "npx", "python3")
	Command string `json:"command"`

	// Args are the arguments to pass to Command
	Args []string `json:"args"`

	// Env is the environment variables to set for the process
	Env map[string]string `json:"env"`

	// Source is the config file this server was loaded from
	Source string
}

// mcpClientConfig is the raw JSON structure of an MCP client config file.
// The outer object may contain extra fields (e.g. globalShortcut) which we ignore.
type mcpClientConfig struct {
	MCPServers map[string]mcpServerEntry `json:"mcpServers"`
}

type mcpServerEntry struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
}

// knownConfigPaths returns the canonical list of MCP client config file paths
// that Oxvault knows how to parse, in discovery priority order.
func knownConfigPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		// If we can't determine the home directory, return an empty list so
		// the caller handles this gracefully.
		return nil
	}

	return []string{
		// Claude Desktop
		filepath.Join(home, ".claude", "claude_desktop_config.json"),
		// Claude Code
		filepath.Join(home, ".claude", "claude_code_config.json"),
		// Cursor
		filepath.Join(home, ".cursor", "mcp.json"),
		// VS Code (user-level)
		filepath.Join(home, ".vscode", "mcp.json"),
		// VS Code (workspace-level — resolved relative to cwd)
		filepath.Join(".vscode", "mcp.json"),
		// Windsurf / Codeium
		filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"),
	}
}

// ParseConfigFile reads and parses a single MCP client config file.
// It returns the list of server configs found in the file.
// Missing files return an empty slice without error.
// Malformed JSON returns an error.
func ParseConfigFile(path string) ([]MCPServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read config file %q: %w", path, err)
	}

	var raw mcpClientConfig
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse config file %q: %w", path, err)
	}

	servers := make([]MCPServerConfig, 0, len(raw.MCPServers))
	for name, entry := range raw.MCPServers {
		servers = append(servers, MCPServerConfig{
			Name:    name,
			Command: entry.Command,
			Args:    entry.Args,
			Env:     entry.Env,
			Source:  path,
		})
	}

	return servers, nil
}

// DiscoverResult holds the servers found across one or more config files
// along with metadata about which files were scanned.
type DiscoverResult struct {
	Servers     []MCPServerConfig
	SourceFiles []string // files that actually existed and were parsed
}

// Discover locates and parses MCP server configs.
//
// path behaviour:
//   - "auto"         — scan all known config file locations
//   - anything else  — treat as a specific file path to parse
//
// Missing files are silently skipped; only IO errors and malformed JSON
// cause a non-nil error return.
func Discover(path string) (*DiscoverResult, error) {
	if path == "auto" {
		return discoverAll()
	}
	return discoverOne(path)
}

func discoverOne(path string) (*DiscoverResult, error) {
	servers, err := ParseConfigFile(path)
	if err != nil {
		return nil, err
	}

	result := &DiscoverResult{Servers: servers}
	if len(servers) > 0 {
		result.SourceFiles = []string{path}
	}
	return result, nil
}

func discoverAll() (*DiscoverResult, error) {
	result := &DiscoverResult{}

	for _, candidate := range knownConfigPaths() {
		servers, err := ParseConfigFile(candidate)
		if err != nil {
			// Malformed JSON is a real error — surface it.
			return nil, err
		}
		if len(servers) == 0 {
			continue
		}

		result.SourceFiles = append(result.SourceFiles, candidate)
		result.Servers = append(result.Servers, servers...)
	}

	return result, nil
}
