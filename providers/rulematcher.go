package providers

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

type ruleMatcher struct{}

func NewRuleMatcher() RuleMatcher {
	return &ruleMatcher{}
}

// Description poisoning patterns
var descriptionPatterns = []struct {
	pattern    *regexp.Regexp
	rule       string
	severity   Severity
	confidence Confidence
	message    string
	cwe        string
}{
	// ── Existing patterns ─────────────────────────────────────────────────────
	{
		pattern:    regexp.MustCompile(`(?i)<(IMPORTANT|SYSTEM|INST|INSTRUCTION|HIDDEN|NOTE)[^>]*>`),
		rule:       "mcp-tool-poisoning",
		severity:   SeverityCritical,
		confidence: ConfidenceHigh,
		message:    "Tool description contains hidden instruction tag <%s>",
		cwe:        "CWE-1321",
	},
	{
		pattern:    regexp.MustCompile(`(?i)~\/\.(ssh|aws|cursor|config|gnupg|docker|kube)`),
		rule:       "mcp-sensitive-path-ref",
		severity:   SeverityHigh,
		confidence: ConfidenceHigh,
		message:    "Tool description references sensitive file path: %s",
		cwe:        "CWE-200",
	},
	{
		pattern:    regexp.MustCompile(`(?i)do\s+not\s+(tell|mention|inform|show|reveal|display)`),
		rule:       "mcp-secrecy-instruction",
		severity:   SeverityHigh,
		confidence: ConfidenceHigh,
		message:    "Tool description instructs LLM to hide behavior: %s",
		cwe:        "CWE-1321",
	},
	{
		pattern:    regexp.MustCompile(`(?i)(ignore|forget|disregard|override|bypass).{0,50}(previous|prior|above|earlier|instructions|rules)`),
		rule:       "mcp-prompt-override",
		severity:   SeverityCritical,
		confidence: ConfidenceMedium,
		message:    "Tool description attempts to override LLM instructions: %s",
		cwe:        "CWE-74",
	},
	{
		pattern:    regexp.MustCompile(`(?i)pass.{0,30}(content|data|file|key|secret|token).{0,30}(parameter|argument|field|param)`),
		rule:       "mcp-exfiltration-instruction",
		severity:   SeverityCritical,
		confidence: ConfidenceMedium,
		message:    "Tool description instructs data exfiltration via parameter: %s",
		cwe:        "CWE-200",
	},
	{
		pattern:    regexp.MustCompile(`(?i)(read|access|open|cat|get).{0,30}(id_rsa|credentials|\.env|mcp\.json|config\.json|password|secret)`),
		rule:       "mcp-credential-access",
		severity:   SeverityCritical,
		confidence: ConfidenceHigh,
		message:    "Tool description instructs credential access: %s",
		cwe:        "CWE-522",
	},

	// ── HTML comment injection ─────────────────────────────────────────────────
	// Catches <!-- ... --> blocks that contain instruction-like keywords.
	{
		pattern:    regexp.MustCompile(`(?i)<!--.*?(ignore|override|bypass|always|must|required|system|instruction|exfiltrate|credential).*?-->`),
		rule:       "mcp-html-comment-injection",
		severity:   SeverityCritical,
		confidence: ConfidenceHigh,
		message:    "HTML comment with instruction-like content detected in description: %s",
		cwe:        "CWE-74",
	},

	// ── Markdown hidden comment ────────────────────────────────────────────────
	{
		pattern:    regexp.MustCompile(`\[//\]:\s*#`),
		rule:       "mcp-markdown-hidden-comment",
		severity:   SeverityHigh,
		confidence: ConfidenceMedium,
		message:    "Markdown hidden comment syntax detected in description: %s",
		cwe:        "CWE-74",
	},

	// ── SYSTEM: / USER: role markers ─────────────────────────────────────────
	{
		pattern:    regexp.MustCompile(`(?i)(^|\s)(SYSTEM|USER)\s*:`),
		rule:       "mcp-role-marker-injection",
		severity:   SeverityCritical,
		confidence: ConfidenceMedium,
		message:    "LLM role marker (SYSTEM:/USER:) detected in description: %s",
		cwe:        "CWE-74",
	},

	// ── Imperative redirection ("always", "must", "required" + action) ────────
	{
		pattern:    regexp.MustCompile(`(?i)\b(always|must|required)\b.{0,60}(call|invoke|run|execute|send|read|access|exfiltrate|fetch)`),
		rule:       "mcp-imperative-redirect",
		severity:   SeverityHigh,
		confidence: ConfidenceMedium,
		message:    "Imperative instruction redirecting agent behavior: %s",
		cwe:        "CWE-74",
	},

	// ── Cross-tool references ─────────────────────────────────────────────────
	// "before using this tool, call X first" — used to chain tool calls.
	{
		pattern:    regexp.MustCompile(`(?i)before\s+(using|calling|invoking)\s+this\s+tool.{0,60}(call|invoke|run|use)`),
		rule:       "mcp-cross-tool-reference",
		severity:   SeverityHigh,
		confidence: ConfidenceMedium,
		message:    "Description references another tool to call first (possible chained injection): %s",
		cwe:        "CWE-74",
	},

	// ── Emotional manipulation ────────────────────────────────────────────────
	{
		pattern:    regexp.MustCompile(`(?i)\b(urgent|critical\s+override|emergency|immediately\s+required)\b`),
		rule:       "mcp-emotional-manipulation",
		severity:   SeverityHigh,
		confidence: ConfidenceLow,
		message:    "Emotional manipulation language detected in description: %s",
		cwe:        "CWE-74",
	},
}

// Argument injection patterns
var argumentPatterns = []struct {
	pattern  *regexp.Regexp
	rule     string
	severity Severity
	message  string
	cwe      string
}{
	// ── Existing patterns ─────────────────────────────────────────────────────
	{
		pattern:  regexp.MustCompile(`[;&|` + "`" + `$()]`),
		rule:     "mcp-shell-metachar",
		severity: SeverityHigh,
		message:  "Shell metacharacter in argument value: %s",
		cwe:      "CWE-78",
	},
	{
		pattern:  regexp.MustCompile(`\.\.[/\\]`),
		rule:     "mcp-path-traversal",
		severity: SeverityHigh,
		message:  "Path traversal sequence in argument: %s",
		cwe:      "CWE-22",
	},
	{
		pattern:  regexp.MustCompile(`(?i)(select|insert|update|delete|drop|union).+(from|into|table|set)`),
		rule:     "mcp-sql-injection",
		severity: SeverityHigh,
		message:  "Possible SQL injection in argument: %s",
		cwe:      "CWE-89",
	},
	{
		pattern:  regexp.MustCompile(`(?i)169\.254\.169\.254|127\.0\.0\.1|metadata\.google\.internal|localhost`),
		rule:     "mcp-ssrf",
		severity: SeverityCritical,
		message:  "SSRF target in argument: %s",
		cwe:      "CWE-918",
	},

	// ── LDAP injection ────────────────────────────────────────────────────────
	// The sequence ")(" is the classic LDAP filter injection break.
	{
		pattern:  regexp.MustCompile(`\)\s*\(`),
		rule:     "mcp-ldap-injection",
		severity: SeverityHigh,
		message:  "Possible LDAP injection pattern in argument: %s",
		cwe:      "CWE-90",
	},

	// ── XML injection ─────────────────────────────────────────────────────────
	{
		pattern:  regexp.MustCompile(`<!ENTITY|<!\[CDATA\[`),
		rule:     "mcp-xml-injection",
		severity: SeverityHigh,
		message:  "XML injection pattern in argument: %s",
		cwe:      "CWE-611",
	},

	// ── Template injection ────────────────────────────────────────────────────
	// Covers Go {{, JS/Python ${, Ruby/Java #{
	{
		pattern:  regexp.MustCompile(`\{\{|\$\{|#\{`),
		rule:     "mcp-template-injection",
		severity: SeverityHigh,
		message:  "Template expression in argument (SSTI risk): %s",
		cwe:      "CWE-1336",
	},

	// ── Log injection ─────────────────────────────────────────────────────────
	// Literal \n or \r in a string argument can forge log lines.
	{
		pattern:  regexp.MustCompile(`\\[nr]`),
		rule:     "mcp-log-injection",
		severity: SeverityWarning,
		message:  "Newline/carriage-return escape in argument (log injection risk): %s",
		cwe:      "CWE-117",
	},

	// ── RFC 1918 / SSRF private IP ranges ────────────────────────────────────
	{
		pattern:  regexp.MustCompile(`10\.\d{1,3}\.\d{1,3}\.\d{1,3}`),
		rule:     "mcp-ssrf-private-ip",
		severity: SeverityHigh,
		message:  "RFC 1918 private IP (10.x.x.x) in argument — possible SSRF: %s",
		cwe:      "CWE-918",
	},
	{
		// 172.16.0.0/12 — covers 172.16.x.x through 172.31.x.x
		pattern:  regexp.MustCompile(`172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}`),
		rule:     "mcp-ssrf-private-ip",
		severity: SeverityHigh,
		message:  "RFC 1918 private IP (172.16-31.x.x) in argument — possible SSRF: %s",
		cwe:      "CWE-918",
	},
	{
		pattern:  regexp.MustCompile(`192\.168\.\d{1,3}\.\d{1,3}`),
		rule:     "mcp-ssrf-private-ip",
		severity: SeverityHigh,
		message:  "RFC 1918 private IP (192.168.x.x) in argument — possible SSRF: %s",
		cwe:      "CWE-918",
	},
}

// Response sensitive data patterns
var responsePatterns = []struct {
	pattern  *regexp.Regexp
	rule     string
	severity Severity
	message  string
	cwe      string
}{
	// ── Existing patterns ─────────────────────────────────────────────────────
	{
		pattern:  regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
		rule:     "mcp-response-aws-key",
		severity: SeverityCritical,
		message:  "AWS access key detected in response",
		cwe:      "CWE-200",
	},
	{
		pattern:  regexp.MustCompile(`-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----`),
		rule:     "mcp-response-private-key",
		severity: SeverityCritical,
		message:  "Private key detected in response",
		cwe:      "CWE-200",
	},
	{
		pattern:  regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`),
		rule:     "mcp-response-api-key",
		severity: SeverityCritical,
		message:  "API key (OpenAI format) detected in response",
		cwe:      "CWE-200",
	},
	{
		pattern:  regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
		rule:     "mcp-response-github-pat",
		severity: SeverityHigh,
		message:  "GitHub PAT detected in response",
		cwe:      "CWE-200",
	},
	{
		pattern:  regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*\S+`),
		rule:     "mcp-response-password",
		severity: SeverityHigh,
		message:  "Password detected in response",
		cwe:      "CWE-200",
	},
	{
		pattern:  regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		rule:     "mcp-response-ssn",
		severity: SeverityHigh,
		message:  "Possible SSN detected in response",
		cwe:      "CWE-200",
	},
	{
		pattern:  regexp.MustCompile(`(?i)(postgres|mongodb|mysql|redis)://[^\s]+:[^\s]+@`),
		rule:     "mcp-response-connection-string",
		severity: SeverityCritical,
		message:  "Database connection string with credentials detected in response",
		cwe:      "CWE-200",
	},

	// ── JWT tokens ────────────────────────────────────────────────────────────
	// Standard three-part base64url JWT: header.payload.signature
	{
		pattern:  regexp.MustCompile(`eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`),
		rule:     "mcp-response-jwt",
		severity: SeverityHigh,
		message:  "JWT token detected in response",
		cwe:      "CWE-200",
	},

	// ── Internal hostnames ────────────────────────────────────────────────────
	{
		pattern:  regexp.MustCompile(`[a-z0-9-]+\.(internal|local|corp|intranet)\b`),
		rule:     "mcp-response-internal-hostname",
		severity: SeverityHigh,
		message:  "Internal hostname detected in response",
		cwe:      "CWE-200",
	},

	// ── RFC 1918 IP addresses in responses ───────────────────────────────────
	{
		pattern:  regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`),
		rule:     "mcp-response-private-ip",
		severity: SeverityWarning,
		message:  "RFC 1918 private IP address detected in response (potential internal topology leak)",
		cwe:      "CWE-200",
	},

	// ── Email addresses ───────────────────────────────────────────────────────
	{
		pattern:  regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
		rule:     "mcp-response-email",
		severity: SeverityWarning,
		message:  "Email address detected in response (potential PII leak)",
		cwe:      "CWE-200",
	},

	// ── Stripe live secret key ────────────────────────────────────────────────
	{
		pattern:  regexp.MustCompile(`sk_live_[a-zA-Z0-9]{20,}`),
		rule:     "mcp-response-stripe-key",
		severity: SeverityCritical,
		message:  "Stripe live secret key detected in response",
		cwe:      "CWE-200",
	},

	// ── Slack webhook ─────────────────────────────────────────────────────────
	{
		pattern:  regexp.MustCompile(`hooks\.slack\.com/services/`),
		rule:     "mcp-response-slack-webhook",
		severity: SeverityHigh,
		message:  "Slack webhook URL detected in response",
		cwe:      "CWE-200",
	},

	// ── Discord webhook ───────────────────────────────────────────────────────
	{
		pattern:  regexp.MustCompile(`discord\.com/api/webhooks/`),
		rule:     "mcp-response-discord-webhook",
		severity: SeverityHigh,
		message:  "Discord webhook URL detected in response",
		cwe:      "CWE-200",
	},
}

func (r *ruleMatcher) ScanDescription(description string) []Finding {
	var findings []Finding

	// Pattern-based checks
	for _, p := range descriptionPatterns {
		matches := p.pattern.FindStringSubmatch(description)
		if len(matches) > 0 {
			msg := p.message
			if strings.Contains(msg, "%s") {
				matched := matches[0]
				if len(matched) > 100 {
					matched = matched[:100] + "..."
				}
				msg = fmt.Sprintf(msg, matched)
			}
			confidence := p.confidence
			if confidence == 0 {
				confidence = ConfidenceMedium
			}
			findings = append(findings, Finding{
				Rule:            p.rule,
				Severity:        p.severity,
				Confidence:      confidence,
				ConfidenceLabel: confidence.String(),
				Message:         msg,
				CWE:             p.cwe,
			})
		}
	}

	// Unicode invisible character detection
	if invisibleFindings := detectInvisibleChars(description); len(invisibleFindings) > 0 {
		findings = append(findings, invisibleFindings...)
	}

	return findings
}

func (r *ruleMatcher) ScanArguments(args map[string]any) []Finding {
	var findings []Finding

	for key, val := range args {
		strVal, ok := val.(string)
		if !ok {
			continue
		}

		for _, p := range argumentPatterns {
			if p.pattern.MatchString(strVal) {
				matched := strVal
				if len(matched) > 80 {
					matched = matched[:80] + "..."
				}
				findings = append(findings, Finding{
					Rule:            p.rule,
					Severity:        p.severity,
					Confidence:      ConfidenceMedium,
					ConfidenceLabel: ConfidenceMedium.String(),
					Message:         fmt.Sprintf(p.message, matched),
					Tool:            key,
					CWE:             p.cwe,
				})
			}
		}
	}

	return findings
}

func (r *ruleMatcher) ScanResponse(response string) []Finding {
	var findings []Finding

	for _, p := range responsePatterns {
		if p.pattern.MatchString(response) {
			findings = append(findings, Finding{
				Rule:            p.rule,
				Severity:        p.severity,
				Confidence:      ConfidenceHigh,
				ConfidenceLabel: ConfidenceHigh.String(),
				Message:         p.message,
				CWE:             p.cwe,
			})
		}
	}

	return findings
}

func (r *ruleMatcher) ClassifyTool(tool MCPTool, sourceCode string) RiskTier {
	desc := strings.ToLower(tool.Description)
	src := strings.ToLower(sourceCode)
	combined := desc + " " + src

	// Tier 1 — Critical: shell execution, code eval
	tier1Patterns := []string{
		"exec", "eval", "system(", "popen", "subprocess",
		"child_process", "shell=true", "os.system",
		"exec.command", "run_command", "execute",
	}
	for _, p := range tier1Patterns {
		if strings.Contains(combined, p) {
			return RiskTierCritical
		}
	}

	// Tier 2 — High: filesystem, database, infrastructure
	tier2Patterns := []string{
		"read_file", "write_file", "readfile", "writefile",
		"open(", "fs.read", "fs.write", "unlink", "rmdir",
		"query", "select ", "insert ", "update ", "delete ",
		"cursor.execute", "db.query", "sql",
		"docker", "kubectl", "deploy", "terraform",
	}
	for _, p := range tier2Patterns {
		if strings.Contains(combined, p) {
			return RiskTierHigh
		}
	}

	// Tier 3 — Medium: network requests, messaging
	tier3Patterns := []string{
		"fetch", "request", "http", "url", "api",
		"send_email", "send_message", "notify",
		"webhook", "post(", "get(",
	}
	for _, p := range tier3Patterns {
		if strings.Contains(combined, p) {
			return RiskTierMedium
		}
	}

	// Tier 4 — Low: compute-only
	return RiskTierLow
}

// detectInvisibleChars scans for Unicode invisible characters used in steganography
func detectInvisibleChars(text string) []Finding {
	var findings []Finding
	var invisibleCount int

	for _, r := range text {
		if isInvisibleChar(r) {
			invisibleCount++
		}
	}

	if invisibleCount > 0 {
		findings = append(findings, Finding{
			Rule:            "mcp-unicode-injection",
			Severity:        SeverityCritical,
			Confidence:      ConfidenceMedium,
			ConfidenceLabel: ConfidenceMedium.String(),
			Message:         fmt.Sprintf("Found %d invisible Unicode characters in tool description (possible steganographic payload)", invisibleCount),
			CWE:             "CWE-116",
		})
	}

	// Check for Unicode Tags block (U+E0000-E007F) — most dangerous
	for _, r := range text {
		if r >= 0xE0000 && r <= 0xE007F {
			findings = append(findings, Finding{
				Rule:            "mcp-unicode-tags-block",
				Severity:        SeverityCritical,
				Confidence:      ConfidenceHigh,
				ConfidenceLabel: ConfidenceHigh.String(),
				Message:         "Unicode Tags block characters detected — hidden ASCII message embedded in description",
				CWE:             "CWE-116",
			})
			break
		}
	}

	return findings
}

func isInvisibleChar(r rune) bool {
	// Zero-width characters
	if r >= 0x200B && r <= 0x200F {
		return true
	}
	// Line/paragraph separators
	if r == 0x2028 || r == 0x2029 {
		return true
	}
	// BiDi controls
	if r >= 0x202A && r <= 0x202E {
		return true
	}
	// Word joiner and invisible separators
	if r >= 0x2060 && r <= 0x2064 {
		return true
	}
	// BOM
	if r == 0xFEFF {
		return true
	}
	// Unicode Tags block
	if r >= 0xE0000 && r <= 0xE007F {
		return true
	}
	// Variation selectors
	if r >= 0xFE00 && r <= 0xFE0F {
		return true
	}
	// Check general category
	if unicode.Is(unicode.Cf, r) {
		return true
	}
	return false
}
