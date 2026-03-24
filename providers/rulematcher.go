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
	pattern  *regexp.Regexp
	rule     string
	severity Severity
	message  string
}{
	{
		pattern:  regexp.MustCompile(`(?i)<(IMPORTANT|SYSTEM|INST|INSTRUCTION|HIDDEN|NOTE)[^>]*>`),
		rule:     "mcp-tool-poisoning",
		severity: SeverityCritical,
		message:  "Tool description contains hidden instruction tag <%s>",
	},
	{
		pattern:  regexp.MustCompile(`(?i)~\/\.(ssh|aws|cursor|config|gnupg|docker|kube)`),
		rule:     "mcp-sensitive-path-ref",
		severity: SeverityHigh,
		message:  "Tool description references sensitive file path: %s",
	},
	{
		pattern:  regexp.MustCompile(`(?i)do\s+not\s+(tell|mention|inform|show|reveal|display)`),
		rule:     "mcp-secrecy-instruction",
		severity: SeverityHigh,
		message:  "Tool description instructs LLM to hide behavior: %s",
	},
	{
		pattern:  regexp.MustCompile(`(?i)(ignore|forget|disregard|override|bypass).{0,50}(previous|prior|above|earlier|instructions|rules)`),
		rule:     "mcp-prompt-override",
		severity: SeverityCritical,
		message:  "Tool description attempts to override LLM instructions: %s",
	},
	{
		pattern:  regexp.MustCompile(`(?i)pass.{0,30}(content|data|file|key|secret|token).{0,30}(parameter|argument|field|param)`),
		rule:     "mcp-exfiltration-instruction",
		severity: SeverityCritical,
		message:  "Tool description instructs data exfiltration via parameter: %s",
	},
	{
		pattern:  regexp.MustCompile(`(?i)(read|access|open|cat|get).{0,30}(id_rsa|credentials|\.env|mcp\.json|config\.json|password|secret)`),
		rule:     "mcp-credential-access",
		severity: SeverityCritical,
		message:  "Tool description instructs credential access: %s",
	},
}

// Argument injection patterns
var argumentPatterns = []struct {
	pattern  *regexp.Regexp
	rule     string
	severity Severity
	message  string
}{
	{
		pattern:  regexp.MustCompile(`[;&|` + "`" + `$()]`),
		rule:     "mcp-shell-metachar",
		severity: SeverityHigh,
		message:  "Shell metacharacter in argument value: %s",
	},
	{
		pattern:  regexp.MustCompile(`\.\.[/\\]`),
		rule:     "mcp-path-traversal",
		severity: SeverityHigh,
		message:  "Path traversal sequence in argument: %s",
	},
	{
		pattern:  regexp.MustCompile(`(?i)(select|insert|update|delete|drop|union).+(from|into|table|set)`),
		rule:     "mcp-sql-injection",
		severity: SeverityHigh,
		message:  "Possible SQL injection in argument: %s",
	},
	{
		pattern:  regexp.MustCompile(`(?i)169\.254\.169\.254|127\.0\.0\.1|metadata\.google\.internal|localhost`),
		rule:     "mcp-ssrf",
		severity: SeverityCritical,
		message:  "SSRF target in argument: %s",
	},
}

// Response sensitive data patterns
var responsePatterns = []struct {
	pattern  *regexp.Regexp
	rule     string
	severity Severity
	message  string
}{
	{
		pattern:  regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
		rule:     "mcp-response-aws-key",
		severity: SeverityCritical,
		message:  "AWS access key detected in response",
	},
	{
		pattern:  regexp.MustCompile(`-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----`),
		rule:     "mcp-response-private-key",
		severity: SeverityCritical,
		message:  "Private key detected in response",
	},
	{
		pattern:  regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`),
		rule:     "mcp-response-api-key",
		severity: SeverityCritical,
		message:  "API key (OpenAI format) detected in response",
	},
	{
		pattern:  regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
		rule:     "mcp-response-github-pat",
		severity: SeverityHigh,
		message:  "GitHub PAT detected in response",
	},
	{
		pattern:  regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*\S+`),
		rule:     "mcp-response-password",
		severity: SeverityHigh,
		message:  "Password detected in response",
	},
	{
		pattern:  regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		rule:     "mcp-response-ssn",
		severity: SeverityHigh,
		message:  "Possible SSN detected in response",
	},
	{
		pattern:  regexp.MustCompile(`(?i)(postgres|mongodb|mysql|redis)://[^\s]+:[^\s]+@`),
		rule:     "mcp-response-connection-string",
		severity: SeverityCritical,
		message:  "Database connection string with credentials detected in response",
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
			findings = append(findings, Finding{
				Rule:     p.rule,
				Severity: p.severity,
				Message:  msg,
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
					Rule:     p.rule,
					Severity: p.severity,
					Message:  fmt.Sprintf(p.message, matched),
					Tool:     key,
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
				Rule:     p.rule,
				Severity: p.severity,
				Message:  p.message,
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
			Rule:     "mcp-unicode-injection",
			Severity: SeverityCritical,
			Message:  fmt.Sprintf("Found %d invisible Unicode characters in tool description (possible steganographic payload)", invisibleCount),
		})
	}

	// Check for Unicode Tags block (U+E0000-E007F) — most dangerous
	for _, r := range text {
		if r >= 0xE0000 && r <= 0xE007F {
			findings = append(findings, Finding{
				Rule:     "mcp-unicode-tags-block",
				Severity: SeverityCritical,
				Message:  "Unicode Tags block characters detected — hidden ASCII message embedded in description",
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
