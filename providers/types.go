package providers

import "time"

// Severity levels for findings
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARNING"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// RiskTier classifies tool exposure level
type RiskTier int

const (
	RiskTierLow    RiskTier = iota // Compute-only, data transformation
	RiskTierMedium                 // Network requests, messaging
	RiskTierHigh                   // Filesystem, database, infrastructure
	RiskTierCritical               // Shell execution, code eval
)

func (t RiskTier) String() string {
	switch t {
	case RiskTierLow:
		return "LOW"
	case RiskTierMedium:
		return "MEDIUM"
	case RiskTierHigh:
		return "HIGH"
	case RiskTierCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// OutputFormat for report generation
type OutputFormat string

const (
	FormatTerminal OutputFormat = "terminal"
	FormatSARIF    OutputFormat = "sarif"
	FormatJSON     OutputFormat = "json"
)

// Language for source code analysis
type Language string

const (
	LangPython     Language = "python"
	LangJavaScript Language = "javascript"
	LangTypeScript Language = "typescript"
	LangGo         Language = "go"
	LangUnknown    Language = "unknown"
)

// Finding represents a single security finding
type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	File     string   `json:"file,omitempty"`
	Line     int      `json:"line,omitempty"`
	Tool     string   `json:"tool,omitempty"`
	Fix      string   `json:"fix,omitempty"`
}

// MCPTool represents a tool from the MCP tools/list response
type MCPTool struct {
	Name        string                 `json:"name"`
	Title       string                 `json:"title,omitempty"`
	Description string                 `json:"description"`
	InputSchema map[string]any         `json:"inputSchema,omitempty"`
	Annotations map[string]any         `json:"annotations,omitempty"`
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
