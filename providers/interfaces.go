package providers

import "time"

// Resolver downloads/clones MCP server packages to a local path.
// Supports: local paths, npm packages, GitHub repos.
type Resolver interface {
	Resolve(target string) (*ResolvedPackage, error)
}

// NetProbe spawns an MCP server in a network-monitored environment and
// detects actual outbound connections made during a live tool-call session.
type NetProbe interface {
	Probe(cmd string, args []string, timeout time.Duration) ([]NetActivity, error)
}

// MCPClient connects to MCP servers via JSON-RPC over stdio.
type MCPClient interface {
	Connect(cmd string, args []string) (*MCPSession, error)
	ListTools(session *MCPSession) ([]MCPTool, error)
	Close(session *MCPSession) error
}

// RuleMatcher scans text for security patterns.
// Used by both scanner (scan-time) and gateway (runtime).
type RuleMatcher interface {
	ScanDescription(description string) []Finding
	ScanArguments(args map[string]any) []Finding
	ScanResponse(response string) []Finding
	ClassifyTool(tool MCPTool, sourceCode string) RiskTier
}

// SASTAnalyzer performs static analysis on MCP server source code.
type SASTAnalyzer interface {
	AnalyzeFile(path string, lang Language) []Finding
	AnalyzeDirectory(dir string) []Finding
	DetectEgress(dir string) []EgressFinding
}

// HookAnalyzer scans npm/PyPI package install scripts for malicious patterns.
// It provides precise, severity-graded findings for install lifecycle hooks
// (preinstall, install, postinstall, prepare) and their referenced script files.
type HookAnalyzer interface {
	AnalyzeDirectory(dir string) []Finding
}

// Reporter formats findings for output.
type Reporter interface {
	Report(findings []Finding, format OutputFormat) ([]byte, error)
}

// PinStore persists and compares tool description hashes.
type PinStore interface {
	Pin(tools []MCPTool) error
	Check(tools []MCPTool) ([]PinDiff, error)
	Load() (map[string]string, error)
}
