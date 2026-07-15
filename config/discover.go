package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

	// Transport is "" / "stdio" for command servers, "http" / "sse" for remote.
	Transport string

	// URL is the endpoint for http/sse transports (empty for stdio servers).
	URL string

	// Source is the config file this server was loaded from
	Source string
}

// mcpClientConfig is the raw JSON structure of an MCP client config file.
// The outer object may contain extra fields (e.g. globalShortcut) which we ignore.
type mcpClientConfig struct {
	MCPServers map[string]mcpServerEntry `json:"mcpServers"`
	// Projects holds Claude Code's per-project sections (~/.claude.json).
	Projects map[string]struct {
		MCPServers map[string]mcpServerEntry `json:"mcpServers"`
	} `json:"projects"`
}

type mcpServerEntry struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	Type    string            `json:"type"`
	URL     string            `json:"url"`
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
		// Claude Code — global + project-scoped servers (nested structure).
		filepath.Join(home, ".claude.json"),
		// Claude Code — project-shared config (cwd-relative).
		".mcp.json",
		// Claude Desktop — OS-specific application-support location.
		claudeDesktopConfigPath(home),
		// Cursor — global + project (cwd-relative).
		filepath.Join(home, ".cursor", "mcp.json"),
		filepath.Join(".cursor", "mcp.json"),
		// VS Code — user-level + workspace (cwd-relative).
		filepath.Join(home, ".vscode", "mcp.json"),
		filepath.Join(".vscode", "mcp.json"),
		// Windsurf / Codeium.
		filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"),
	}
}

// claudeDesktopConfigPath returns the OS-specific Claude Desktop config location.
func claudeDesktopConfigPath(home string) string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	case "windows":
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "Claude", "claude_desktop_config.json")
		}
		return filepath.Join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json")
	default: // linux + other unix
		return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json")
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
	collect := func(m map[string]mcpServerEntry) {
		for name, entry := range m {
			servers = append(servers, MCPServerConfig{
				Name:      name,
				Command:   entry.Command,
				Args:      entry.Args,
				Env:       entry.Env,
				Transport: entry.Type,
				URL:       entry.URL,
				Source:    path,
			})
		}
	}
	collect(raw.MCPServers)
	for _, proj := range raw.Projects {
		collect(proj.MCPServers)
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
	seen := make(map[string]bool) // dedup a server that appears in several files

	for _, candidate := range knownConfigPaths() {
		servers, err := ParseConfigFile(candidate)
		if err != nil {
			// Malformed JSON is a real error — surface it.
			return nil, err
		}

		added := 0
		for _, srv := range servers {
			key := serverIdentity(srv)
			if seen[key] {
				continue
			}
			seen[key] = true
			result.Servers = append(result.Servers, srv)
			added++
		}
		if added > 0 {
			result.SourceFiles = append(result.SourceFiles, candidate)
		}
	}

	return result, nil
}

// serverIdentity keys a server by command + args + url for dedup.
func serverIdentity(s MCPServerConfig) string {
	return s.Command + "\x00" + strings.Join(s.Args, "\x00") + "\x00" + s.URL
}
