package patterns

import "regexp"

// KnownVulnerablePackages is the built-in vulnerability database.
// Versions <= MaxAffected are considered affected.
var KnownVulnerablePackages = []VulnerablePackage{
	{
		Name: "mcp-remote", MaxAffected: "0.1.15",
		CVE: "CVE-2025-6514", CVSS: 9.6, Severity: SeverityCritical,
		Description: "OS command injection via OAuth authorization_endpoint",
	},
	{
		Name: "@modelcontextprotocol/inspector", MaxAffected: "0.14.0",
		CVE: "CVE-2025-49596", CVSS: 9.4, Severity: SeverityCritical,
		Description: "Unauthenticated RCE via /sse endpoint",
	},
	{
		Name: "@modelcontextprotocol/server-filesystem", MaxAffected: "0.6.3",
		CVE: "CVE-2025-53110", CVSS: 7.3, Severity: SeverityHigh,
		Description: "Path traversal via directory containment bypass",
	},
	{
		Name: "@modelcontextprotocol/server-filesystem", MaxAffected: "0.6.3",
		CVE: "CVE-2025-53109", CVSS: 8.4, Severity: SeverityCritical,
		Description: "Symlink escape to arbitrary file access",
	},
	{
		Name: "mcp-server-kubernetes", MaxAffected: "2.4.9",
		CVE: "CVE-2025-53355", CVSS: 8.0, Severity: SeverityCritical,
		Description: "execSync command injection via unsanitized input",
	},
	{
		Name: "node-code-sandbox-mcp", MaxAffected: "1.2.9",
		CVE: "CVE-2025-53372", CVSS: 8.0, Severity: SeverityCritical,
		Description: "Sandbox escape via command injection in sandbox_stop",
	},
	{
		Name: "@framelink/figma-mcp", MaxAffected: "0.6.2",
		CVE: "CVE-2025-53967", CVSS: 8.0, Severity: SeverityCritical,
		Description: "Command injection via child_process.exec with unsanitized URL",
	},
	{
		Name: "github-kanban-mcp-server", MaxAffected: "0.3.0",
		CVE: "CVE-2025-53818", CVSS: 8.0, Severity: SeverityCritical,
		Description: "exec() injection via add_comment issue_number parameter",
	},
	{
		Name: "@anthropic/mcp-server-git", MaxAffected: "2025.12.17",
		CVE: "CVE-2025-68145", CVSS: 10.0, Severity: SeverityCritical,
		Description: "Path validation bypass + git_init arbitrary path + argument injection chain",
	},
	{
		Name: "create-mcp-server-stdio", MaxAffected: "0.9.9",
		CVE: "CVE-2025-54994", CVSS: 10.0, Severity: SeverityCritical,
		Description: "Command injection via server name in exec()",
	},
}

// SuspiciousScriptPatterns flags dangerous patterns in npm lifecycle scripts.
var SuspiciousScriptPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bcurl\b`),
	regexp.MustCompile(`\bwget\b`),
	regexp.MustCompile(`\beval\b`),
	regexp.MustCompile(`\bexec\b`),
	regexp.MustCompile(`sh\s+-c\b`),
	regexp.MustCompile(`bash\s+-c\b`),
	regexp.MustCompile(`https?://`),
	regexp.MustCompile(`\bfetch\b`),
}

// LifecycleScripts are the npm script hooks that run automatically on install.
var LifecycleScripts = []string{"preinstall", "install", "postinstall"}
