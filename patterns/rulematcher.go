package patterns

import "regexp"

// DescriptionPatterns contains patterns for detecting tool description poisoning.
var DescriptionPatterns = []DescriptionPattern{
	{
		Pattern:    regexp.MustCompile(`(?i)<(IMPORTANT|SYSTEM|INST|INSTRUCTION|HIDDEN|NOTE)[^>]*>`),
		Rule:       "mcp-tool-poisoning",
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		Message:    "Tool description contains hidden instruction tag <%s>",
		CWE:        "CWE-1321",
	},
	{
		Pattern:    regexp.MustCompile(`(?i)~\/\.(ssh|aws|cursor|config|gnupg|docker|kube)`),
		Rule:       "mcp-sensitive-path-ref",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Message:    "Tool description references sensitive file path: %s",
		CWE:        "CWE-200",
	},
	{
		Pattern:    regexp.MustCompile(`(?i)do\s+not\s+(tell|mention|inform|show|reveal|display)`),
		Rule:       "mcp-secrecy-instruction",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Message:    "Tool description instructs LLM to hide behavior: %s",
		CWE:        "CWE-1321",
	},
	{
		Pattern:    regexp.MustCompile(`(?i)(ignore|forget|disregard|override|bypass).{0,50}(previous|prior|above|earlier|instructions|rules)`),
		Rule:       "mcp-prompt-override",
		Severity:   SeverityCritical,
		Confidence: ConfidenceMedium,
		Message:    "Tool description attempts to override LLM instructions: %s",
		CWE:        "CWE-74",
	},
	{
		Pattern:    regexp.MustCompile(`(?i)pass.{0,30}(content|data|file|key|secret|token).{0,30}(parameter|argument|field|param)`),
		Rule:       "mcp-exfiltration-instruction",
		Severity:   SeverityCritical,
		Confidence: ConfidenceMedium,
		Message:    "Tool description instructs data exfiltration via parameter: %s",
		CWE:        "CWE-200",
	},
	{
		Pattern:    regexp.MustCompile(`(?i)(read|access|open|cat|get).{0,30}(id_rsa|credentials|\.env|mcp\.json|config\.json|password|secret)`),
		Rule:       "mcp-credential-access",
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		Message:    "Tool description instructs credential access: %s",
		CWE:        "CWE-522",
	},
	{
		Pattern:    regexp.MustCompile(`(?i)<!--.*?(ignore|override|bypass|always|must|required|system|instruction|exfiltrate|credential).*?-->`),
		Rule:       "mcp-html-comment-injection",
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		Message:    "HTML comment with instruction-like content detected in description: %s",
		CWE:        "CWE-74",
	},
	{
		Pattern:    regexp.MustCompile(`\[//\]:\s*#`),
		Rule:       "mcp-markdown-hidden-comment",
		Severity:   SeverityHigh,
		Confidence: ConfidenceMedium,
		Message:    "Markdown hidden comment syntax detected in description: %s",
		CWE:        "CWE-74",
	},
	{
		Pattern:    regexp.MustCompile(`(?i)(^|\s)(SYSTEM|USER)\s*:`),
		Rule:       "mcp-role-marker-injection",
		Severity:   SeverityCritical,
		Confidence: ConfidenceMedium,
		Message:    "LLM role marker (SYSTEM:/USER:) detected in description: %s",
		CWE:        "CWE-74",
	},
	{
		Pattern:    regexp.MustCompile(`(?i)\b(always|must|required)\b.{0,60}(call|invoke|run|execute|send|read|access|exfiltrate|fetch)`),
		Rule:       "mcp-imperative-redirect",
		Severity:   SeverityHigh,
		Confidence: ConfidenceMedium,
		Message:    "Imperative instruction redirecting agent behavior: %s",
		CWE:        "CWE-74",
	},
	{
		Pattern:    regexp.MustCompile(`(?i)before\s+(using|calling|invoking)\s+this\s+tool.{0,60}(call|invoke|run|use)`),
		Rule:       "mcp-cross-tool-reference",
		Severity:   SeverityHigh,
		Confidence: ConfidenceMedium,
		Message:    "Description references another tool to call first (possible chained injection): %s",
		CWE:        "CWE-74",
	},
	{
		Pattern:    regexp.MustCompile(`(?i)\b(urgent|critical\s+override|emergency|immediately\s+required)\b`),
		Rule:       "mcp-emotional-manipulation",
		Severity:   SeverityHigh,
		Confidence: ConfidenceLow,
		Message:    "Emotional manipulation language detected in description: %s",
		CWE:        "CWE-74",
	},
}

// ArgumentPatterns contains patterns for detecting argument injection.
var ArgumentPatterns = []ArgumentPattern{
	{
		Pattern:  regexp.MustCompile(`[;&|` + "`" + `$()]`),
		Rule:     "mcp-shell-metachar",
		Severity: SeverityHigh,
		Message:  "Shell metacharacter in argument value: %s",
		CWE:      "CWE-78",
	},
	{
		Pattern:  regexp.MustCompile(`\.\.[/\\]`),
		Rule:     "mcp-path-traversal",
		Severity: SeverityHigh,
		Message:  "Path traversal sequence in argument: %s",
		CWE:      "CWE-22",
	},
	{
		Pattern:  regexp.MustCompile(`(?i)(select|insert|update|delete|drop|union).+(from|into|table|set)`),
		Rule:     "mcp-sql-injection",
		Severity: SeverityHigh,
		Message:  "Possible SQL injection in argument: %s",
		CWE:      "CWE-89",
	},
	{
		Pattern:  regexp.MustCompile(`(?i)169\.254\.169\.254|127\.0\.0\.1|metadata\.google\.internal|localhost`),
		Rule:     "mcp-ssrf",
		Severity: SeverityCritical,
		Message:  "SSRF target in argument: %s",
		CWE:      "CWE-918",
	},
	{
		Pattern:  regexp.MustCompile(`\)\s*\(`),
		Rule:     "mcp-ldap-injection",
		Severity: SeverityHigh,
		Message:  "Possible LDAP injection pattern in argument: %s",
		CWE:      "CWE-90",
	},
	{
		Pattern:  regexp.MustCompile(`<!ENTITY|<!\[CDATA\[`),
		Rule:     "mcp-xml-injection",
		Severity: SeverityHigh,
		Message:  "XML injection pattern in argument: %s",
		CWE:      "CWE-611",
	},
	{
		Pattern:  regexp.MustCompile(`\{\{|\$\{|#\{`),
		Rule:     "mcp-template-injection",
		Severity: SeverityHigh,
		Message:  "Template expression in argument (SSTI risk): %s",
		CWE:      "CWE-1336",
	},
	{
		Pattern:  regexp.MustCompile(`\\[nr]`),
		Rule:     "mcp-log-injection",
		Severity: SeverityWarning,
		Message:  "Newline/carriage-return escape in argument (log injection risk): %s",
		CWE:      "CWE-117",
	},
	{
		Pattern:  regexp.MustCompile(`10\.\d{1,3}\.\d{1,3}\.\d{1,3}`),
		Rule:     "mcp-ssrf-private-ip",
		Severity: SeverityHigh,
		Message:  "RFC 1918 private IP (10.x.x.x) in argument — possible SSRF: %s",
		CWE:      "CWE-918",
	},
	{
		// 172.16.0.0/12 -- covers 172.16.x.x through 172.31.x.x
		Pattern:  regexp.MustCompile(`172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}`),
		Rule:     "mcp-ssrf-private-ip",
		Severity: SeverityHigh,
		Message:  "RFC 1918 private IP (172.16-31.x.x) in argument — possible SSRF: %s",
		CWE:      "CWE-918",
	},
	{
		Pattern:  regexp.MustCompile(`192\.168\.\d{1,3}\.\d{1,3}`),
		Rule:     "mcp-ssrf-private-ip",
		Severity: SeverityHigh,
		Message:  "RFC 1918 private IP (192.168.x.x) in argument — possible SSRF: %s",
		CWE:      "CWE-918",
	},
}

// ResponsePatterns contains patterns for detecting sensitive data in responses.
var ResponsePatterns = []ResponsePattern{
	{
		Pattern:  regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
		Rule:     "mcp-response-aws-key",
		Severity: SeverityCritical,
		Message:  "AWS access key detected in response",
		CWE:      "CWE-200",
	},
	{
		Pattern:  regexp.MustCompile(`-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----`),
		Rule:     "mcp-response-private-key",
		Severity: SeverityCritical,
		Message:  "Private key detected in response",
		CWE:      "CWE-200",
	},
	{
		Pattern:  regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`),
		Rule:     "mcp-response-api-key",
		Severity: SeverityCritical,
		Message:  "API key (OpenAI format) detected in response",
		CWE:      "CWE-200",
	},
	{
		Pattern:  regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
		Rule:     "mcp-response-github-pat",
		Severity: SeverityHigh,
		Message:  "GitHub PAT detected in response",
		CWE:      "CWE-200",
	},
	{
		Pattern:  regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*\S+`),
		Rule:     "mcp-response-password",
		Severity: SeverityHigh,
		Message:  "Password detected in response",
		CWE:      "CWE-200",
	},
	{
		Pattern:  regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		Rule:     "mcp-response-ssn",
		Severity: SeverityHigh,
		Message:  "Possible SSN detected in response",
		CWE:      "CWE-200",
	},
	{
		Pattern:  regexp.MustCompile(`(?i)(postgres|mongodb|mysql|redis)://[^\s]+:[^\s]+@`),
		Rule:     "mcp-response-connection-string",
		Severity: SeverityCritical,
		Message:  "Database connection string with credentials detected in response",
		CWE:      "CWE-200",
	},
	{
		Pattern:  regexp.MustCompile(`eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`),
		Rule:     "mcp-response-jwt",
		Severity: SeverityHigh,
		Message:  "JWT token detected in response",
		CWE:      "CWE-200",
	},
	{
		Pattern:  regexp.MustCompile(`[a-z0-9-]+\.(internal|local|corp|intranet)\b`),
		Rule:     "mcp-response-internal-hostname",
		Severity: SeverityHigh,
		Message:  "Internal hostname detected in response",
		CWE:      "CWE-200",
	},
	{
		Pattern:  regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`),
		Rule:     "mcp-response-private-ip",
		Severity: SeverityWarning,
		Message:  "RFC 1918 private IP address detected in response (potential internal topology leak)",
		CWE:      "CWE-200",
	},
	{
		Pattern:  regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
		Rule:     "mcp-response-email",
		Severity: SeverityWarning,
		Message:  "Email address detected in response (potential PII leak)",
		CWE:      "CWE-200",
	},
	{
		Pattern:  regexp.MustCompile(`sk_live_[a-zA-Z0-9]{20,}`),
		Rule:     "mcp-response-stripe-key",
		Severity: SeverityCritical,
		Message:  "Stripe live secret key detected in response",
		CWE:      "CWE-200",
	},
	{
		Pattern:  regexp.MustCompile(`hooks\.slack\.com/services/`),
		Rule:     "mcp-response-slack-webhook",
		Severity: SeverityHigh,
		Message:  "Slack webhook URL detected in response",
		CWE:      "CWE-200",
	},
	{
		Pattern:  regexp.MustCompile(`discord\.com/api/webhooks/`),
		Rule:     "mcp-response-discord-webhook",
		Severity: SeverityHigh,
		Message:  "Discord webhook URL detected in response",
		CWE:      "CWE-200",
	},
}

// Tier1Keywords are keywords that classify a tool as Tier 1 (Critical): shell execution, code eval.
var Tier1Keywords = []string{
	"exec", "eval", "system(", "popen", "subprocess",
	"child_process", "shell=true", "os.system",
	"exec.command", "run_command", "execute",
}

// Tier2Keywords are keywords that classify a tool as Tier 2 (High): filesystem, database, infrastructure.
var Tier2Keywords = []string{
	"read_file", "write_file", "readfile", "writefile",
	"open(", "fs.read", "fs.write", "unlink", "rmdir",
	"query", "select ", "insert ", "update ", "delete ",
	"cursor.execute", "db.query", "sql",
	"docker", "kubectl", "deploy", "terraform",
}

// Tier3Keywords are keywords that classify a tool as Tier 3 (Medium): network requests, messaging.
var Tier3Keywords = []string{
	"fetch", "request", "http", "url", "api",
	"send_email", "send_message", "notify",
	"webhook", "post(", "get(",
}
