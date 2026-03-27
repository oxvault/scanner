package providers

import (
	"time"

	"github.com/oxvault/scanner/patterns"
)

// Type aliases — zero breakage for all consumers.
type Confidence = patterns.Confidence

const (
	ConfidenceLow    = patterns.ConfidenceLow
	ConfidenceMedium = patterns.ConfidenceMedium
	ConfidenceHigh   = patterns.ConfidenceHigh
)

type Severity = patterns.Severity

const (
	SeverityInfo     = patterns.SeverityInfo
	SeverityWarning  = patterns.SeverityWarning
	SeverityHigh     = patterns.SeverityHigh
	SeverityCritical = patterns.SeverityCritical
)

type RiskTier = patterns.RiskTier

const (
	RiskTierLow      = patterns.RiskTierLow
	RiskTierMedium   = patterns.RiskTierMedium
	RiskTierHigh     = patterns.RiskTierHigh
	RiskTierCritical = patterns.RiskTierCritical
)

type Language = patterns.Language

const (
	LangPython     = patterns.LangPython
	LangJavaScript = patterns.LangJavaScript
	LangTypeScript = patterns.LangTypeScript
	LangGo         = patterns.LangGo
	LangJSON       = patterns.LangJSON
	LangUnknown    = patterns.LangUnknown
)

// OutputFormat for report generation
type OutputFormat string

const (
	FormatTerminal OutputFormat = "terminal"
	FormatSARIF    OutputFormat = "sarif"
	FormatJSON     OutputFormat = "json"
)

// Finding represents a single security finding
type Finding struct {
	Rule            string     `json:"rule"`
	Severity        Severity   `json:"severity"`
	Confidence      Confidence `json:"confidence"`
	ConfidenceLabel string     `json:"confidenceLabel"`
	Message         string     `json:"message"`
	File            string     `json:"file,omitempty"`
	Line            int        `json:"line,omitempty"`
	Tool            string     `json:"tool,omitempty"`
	Fix             string     `json:"fix,omitempty"`
	CWE             string     `json:"cwe,omitempty"`        // e.g., "CWE-78"
	References      []string   `json:"references,omitempty"` // CVE IDs, URLs
}

// MCPTool represents a tool from the MCP tools/list response
type MCPTool struct {
	Name        string         `json:"name"`
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema,omitempty"`
	Annotations map[string]any `json:"annotations,omitempty"`
}

// MCPServerInfo from the initialize response
type MCPServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// MCPSession represents an active connection to an MCP server
type MCPSession struct {
	ServerInfo MCPServerInfo
	Tools      []MCPTool
	process    any // internal handle, managed by MCPClient
}

// MCPResult from a tools/call response
type MCPResult struct {
	Content []MCPContent `json:"content"`
}

// MCPContent is a single content block in a tool result
type MCPContent struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	Data     string `json:"data,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
}

// ResolvedPackage is the result of resolving a scan target
type ResolvedPackage struct {
	Path     string   // Local path to extracted files
	Command  string   // Command to start the MCP server
	Args     []string // Arguments for the command
	Language Language // Detected primary language
	Name     string   // Package name
	Version  string   // Package version
}

// PinDiff represents a change detected in a tool's description
type PinDiff struct {
	ToolName    string `json:"tool_name"`
	OldHash     string `json:"old_hash"`
	NewHash     string `json:"new_hash"`
	Changed     bool   `json:"changed"`
	Description string `json:"description,omitempty"` // What changed
}

// EgressFinding represents a detected outbound network call
type EgressFinding struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	Destination string `json:"destination,omitempty"` // URL or hostname if detectable
	Method      string `json:"method"`                // e.g., "requests.post", "fetch"
	ToolName    string `json:"tool_name,omitempty"`
}

// NetActivity represents a single observed outbound network event captured
// during a live probe session of an MCP server.
type NetActivity struct {
	// Type is the protocol observed: "dns", "tcp", or "udp".
	Type string `json:"type"`
	// Destination is the remote address in "host:port" or "ip:port" form.
	Destination string `json:"destination"`
	// Timestamp records when the connection attempt was observed.
	Timestamp time.Time `json:"timestamp"`
	// ToolName is populated when the activity can be correlated to a specific
	// tool call (best-effort — may be empty).
	ToolName string `json:"tool_name,omitempty"`
}
