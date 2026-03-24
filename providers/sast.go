package providers

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type sastAnalyzer struct{}

func NewSASTAnalyzer() SASTAnalyzer {
	return &sastAnalyzer{}
}

// sourcePattern represents a pattern to match in source code
type sourcePattern struct {
	pattern         *regexp.Regexp
	rule            string
	severity        Severity
	message         string
	langs           []Language
	cwe             string
	isSecretRule    bool         // Fix 1 & 2: enables placeholder/self-assignment exclusions
	excludePatterns []*regexp.Regexp // Fix 5: skip finding when any exclusion matches the line
}

// ── Fix 1: Placeholder secret exclusion ──────────────────────────────────────

// placeholderPatterns is a compiled list of patterns that indicate a value is
// an example or placeholder rather than a real secret.
var placeholderPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)your[_-]`),
	regexp.MustCompile(`(?i)example`),
	regexp.MustCompile(`(?i)sample`),
	regexp.MustCompile(`(?i)dummy`),
	regexp.MustCompile(`(?i)placeholder`),
	regexp.MustCompile(`(?i)changeme`),
	regexp.MustCompile(`(?i)xxx`),
	regexp.MustCompile(`(?i)yyy`),
	regexp.MustCompile(`(?i)zzz`),
	regexp.MustCompile(`(?i)insert[_-]`),
	regexp.MustCompile(`(?i)replace[_-]`),
	regexp.MustCompile(`(?i)_here$`),
	regexp.MustCompile(`(?i)todo`),
	regexp.MustCompile(`(?i)fixme`),
	regexp.MustCompile(`(?i)<your`),
	regexp.MustCompile(`(?i)\{your`),
}

// isPlaceholderSecret returns true when value looks like a documentation
// placeholder rather than a real credential.
func isPlaceholderSecret(value string) bool {
	for _, re := range placeholderPatterns {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

// ── Fix 2: Constant self-assignment exclusion ─────────────────────────────────

// extractKeyValue attempts to extract the key and quoted value from a line
// like `SOME_NAME = 'SOME_NAME'` or `api_key = "api_key"`.
// Returns ("", "") when the pattern cannot be identified.
func extractKeyValue(line string) (key, value string) {
	// Match: <identifier> <op> <quote><value><quote>
	re := regexp.MustCompile(`(?i)([A-Z0-9_]+)\s*[:=]+\s*["']([^"']+)["']`)
	m := re.FindStringSubmatch(line)
	if len(m) < 3 {
		return "", ""
	}
	return m[1], m[2]
}

// isSelfAssignedSecret returns true when the value in a secret assignment is
// identical to its key name (e.g. `TOKEN = "TOKEN"`).
func isSelfAssignedSecret(line string) bool {
	key, value := extractKeyValue(line)
	if key == "" {
		return false
	}
	return strings.EqualFold(key, value)
}

// ── Fix 3: Comment line detection ────────────────────────────────────────────

// commentOnlyLanguages lists extensions where `#` begins a single-line comment.
var commentOnlyLanguages = map[Language]bool{
	LangPython: true,
}

// isCommentLine returns true when the trimmed line is a comment that should
// suppress all SAST rules.  The set of comment prefixes is language-aware:
// `#` is only treated as a comment for Python/Ruby/Shell/YAML/TOML, not for
// JS/TS/Go (where `#` can appear in shebangs but is not a regular comment).
func isCommentLine(line string, lang Language) bool {
	t := strings.TrimSpace(line)
	if t == "" {
		return false
	}
	// Universal comment prefixes (all supported languages)
	if strings.HasPrefix(t, "//") ||
		strings.HasPrefix(t, "/*") ||
		strings.HasPrefix(t, "*") ||
		strings.HasPrefix(t, "--") {
		return true
	}
	// `#` is a comment only in Python (and YAML/TOML which we don't scan)
	if strings.HasPrefix(t, "#") && commentOnlyLanguages[lang] {
		return true
	}
	return false
}

// ── Fix 7: Temp-dir path detection ───────────────────────────────────────────

// tempDirPatterns detects when a destructive FS operation clearly targets a
// temporary directory, reducing the severity to INFO.
// Note: patterns intentionally match as prefixes (tmp, temp, cache) so that
// variable names like tmpdir, tempDir, cacheDir are also recognized.
var tempDirPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)tmp`),
	regexp.MustCompile(`(?i)temp`),
	regexp.MustCompile(`(?i)cache`),
	regexp.MustCompile(`os\.tmpdir\s*\(`),
	regexp.MustCompile(`tempfile`),
	regexp.MustCompile(`mkdtemp`),
	regexp.MustCompile(`RUNNER_TEMP`),
}

// isTempDirOperation returns true when the line's argument clearly references
// a temporary directory.
func isTempDirOperation(line string) bool {
	for _, re := range tempDirPatterns {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

var sourcePatterns = []sourcePattern{
	// ── Command injection — Python ────────────────────────────────────────────

	{
		pattern:  regexp.MustCompile(`os\.(popen|system)\s*\(`),
		rule:     "mcp-cmd-injection",
		severity: SeverityCritical,
		message:  "Direct OS command execution: %s",
		langs:    []Language{LangPython},
		cwe:      "CWE-78",
	},
	{
		// subprocess.run/call/Popen/check_output with shell=True on the same line
		pattern:  regexp.MustCompile(`subprocess\.(run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True`),
		rule:     "mcp-cmd-injection",
		severity: SeverityCritical,
		message:  "Subprocess with shell=True: %s",
		langs:    []Language{LangPython},
		cwe:      "CWE-78",
	},
	{
		// subprocess.check_output alone (may use shell=True on a different line
		// or the call itself is dangerous if args contain user input)
		pattern:  regexp.MustCompile(`subprocess\.check_output\s*\(`),
		rule:     "mcp-cmd-injection",
		severity: SeverityHigh,
		message:  "subprocess.check_output usage (verify shell=False and safe args): %s",
		langs:    []Language{LangPython},
		cwe:      "CWE-78",
	},
	{
		// subprocess.Popen alone
		pattern:  regexp.MustCompile(`subprocess\.Popen\s*\(`),
		rule:     "mcp-cmd-injection",
		severity: SeverityHigh,
		message:  "subprocess.Popen usage (verify shell=False and safe args): %s",
		langs:    []Language{LangPython},
		cwe:      "CWE-78",
	},
	{
		// exec() — Python built-in dynamic code execution
		pattern:  regexp.MustCompile(`\bexec\s*\(`),
		rule:     "mcp-code-eval",
		severity: SeverityCritical,
		message:  "Python exec() dynamic code execution: %s",
		langs:    []Language{LangPython},
		cwe:      "CWE-94",
	},
	{
		pattern:  regexp.MustCompile(`eval\s*\(`),
		rule:     "mcp-code-eval",
		severity: SeverityCritical,
		message:  "Dynamic code evaluation: %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript},
		cwe:      "CWE-94",
	},
	{
		// __import__ — dynamic module import, often used in payloads.
		// Fix 5: exclude standard library boilerplate patterns that are benign.
		pattern:  regexp.MustCompile(`__import__\s*\(`),
		rule:     "mcp-dynamic-import",
		severity: SeverityHigh,
		message:  "Dynamic __import__() call (potential payload execution): %s",
		langs:    []Language{LangPython},
		cwe:      "CWE-94",
		excludePatterns: []*regexp.Regexp{
			// pkgutil.extend_path boilerplate: __import__('pkgutil').extend_path(...)
			regexp.MustCompile(`__import__\s*\(\s*['"]pkgutil['"]\s*\)`),
			regexp.MustCompile(`pkgutil`),
			// importlib.import_module is standard library, not a payload
			regexp.MustCompile(`importlib\.import_module`),
		},
	},

	// ── Deserialization — Python ──────────────────────────────────────────────

	{
		pattern:  regexp.MustCompile(`pickle\.(loads?)\s*\(`),
		rule:     "mcp-unsafe-deserialization",
		severity: SeverityCritical,
		message:  "Unsafe pickle deserialization (arbitrary code execution risk): %s",
		langs:    []Language{LangPython},
		cwe:      "CWE-502",
	},
	{
		// yaml.load( without Loader= is the unsafe form; yaml.safe_load is fine
		pattern:  regexp.MustCompile(`yaml\.load\s*\([^)]*\)`),
		rule:     "mcp-unsafe-deserialization",
		severity: SeverityHigh,
		message:  "Unsafe yaml.load() without SafeLoader (use yaml.safe_load): %s",
		langs:    []Language{LangPython},
		cwe:      "CWE-502",
	},

	// ── SSRF / open redirect — Python ────────────────────────────────────────

	{
		// requests.get/post with a variable URL (potential SSRF)
		pattern:  regexp.MustCompile(`requests\.(get|post)\s*\(\s*[^"'\s][^)]*\)`),
		rule:     "mcp-ssrf-risk",
		severity: SeverityWarning,
		message:  "requests.%s with dynamic URL (potential SSRF — validate/allowlist URLs): %s",
		langs:    []Language{LangPython},
		cwe:      "CWE-918",
	},

	// ── Destructive file operations — Python ─────────────────────────────────

	{
		pattern:  regexp.MustCompile(`shutil\.rmtree\s*\(`),
		rule:     "mcp-destructive-fs",
		severity: SeverityHigh,
		message:  "shutil.rmtree() — recursive directory deletion: %s",
		langs:    []Language{LangPython},
		cwe:      "CWE-73",
	},
	{
		pattern:  regexp.MustCompile(`os\.remove\s*\(`),
		rule:     "mcp-destructive-fs",
		severity: SeverityHigh,
		message:  "os.remove() — file deletion: %s",
		langs:    []Language{LangPython},
		cwe:      "CWE-73",
	},

	// ── Command injection — JavaScript/TypeScript ─────────────────────────────

	// Fix 4: Only flag child_process.exec/execSync when the argument contains
	// string concatenation (+) or template literals (`), indicating potential
	// injection.  Bare imports and safe static calls are no longer flagged.
	{
		// child_process.exec( or child_process.execSync( with concatenation/template
		pattern:  regexp.MustCompile("child_process\\.(exec|execSync)\\s*\\([^)]*(?:\\+|`)"),
		rule:     "mcp-cmd-injection",
		severity: SeverityCritical,
		message:  "child_process.exec with string concatenation/template (injection risk): %s",
		langs:    []Language{LangJavaScript, LangTypeScript},
		cwe:      "CWE-78",
	},
	{
		// exec( / execSync( called directly (imported as named binding) with
		// concatenation or template literal
		pattern:  regexp.MustCompile("\\bexecSync?\\s*\\([^)]*(?:\\+|`)"),
		rule:     "mcp-cmd-injection",
		severity: SeverityCritical,
		message:  "execSync with string concatenation/template (injection risk): %s",
		langs:    []Language{LangJavaScript, LangTypeScript},
		cwe:      "CWE-78",
	},
	{
		// child_process.spawn with shell: true
		pattern:  regexp.MustCompile(`child_process\.spawn\s*\([^)]*shell\s*:\s*true`),
		rule:     "mcp-cmd-injection",
		severity: SeverityCritical,
		message:  "child_process.spawn with shell:true: %s",
		langs:    []Language{LangJavaScript, LangTypeScript},
		cwe:      "CWE-78",
	},
	{
		// require('child_process') — reduced to INFO: it's an import, not usage.
		// Fix 4: bare imports are no longer HIGH; only actual dangerous calls count.
		pattern:  regexp.MustCompile(`require\s*\(\s*['"]child_process['"]\s*\)`),
		rule:     "mcp-cmd-injection",
		severity: SeverityInfo,
		message:  "child_process module imported (verify no unsafe .exec usage): %s",
		langs:    []Language{LangJavaScript, LangTypeScript},
		cwe:      "CWE-78",
	},

	// ── Code generation / eval — JavaScript/TypeScript ───────────────────────

	{
		// new Function(...) — runtime code generation
		pattern:  regexp.MustCompile(`new\s+Function\s*\(`),
		rule:     "mcp-code-eval",
		severity: SeverityCritical,
		message:  "new Function() — dynamic code generation: %s",
		langs:    []Language{LangJavaScript, LangTypeScript},
		cwe:      "CWE-94",
	},
	{
		// setTimeout/setInterval with a string first argument (implicit eval)
		pattern:  regexp.MustCompile(`(setTimeout|setInterval)\s*\(\s*["'\x60]`),
		rule:     "mcp-code-eval",
		severity: SeverityHigh,
		message:  "setTimeout/setInterval with string argument (implicit eval): %s",
		langs:    []Language{LangJavaScript, LangTypeScript},
		cwe:      "CWE-94",
	},
	{
		// vm.runInNewContext / vm.runInThisContext — Node.js sandbox escape
		pattern:  regexp.MustCompile(`vm\.(runInNewContext|runInThisContext)\s*\(`),
		rule:     "mcp-sandbox-escape",
		severity: SeverityCritical,
		message:  "vm.%s — Node.js sandbox escape risk: %s",
		langs:    []Language{LangJavaScript, LangTypeScript},
		cwe:      "CWE-265",
	},

	// ── Destructive file operations — JavaScript/TypeScript ───────────────────

	{
		pattern:  regexp.MustCompile(`fs\.(unlinkSync|rmdir(?:Sync)?|rm(?:Sync)?)\s*\(`),
		rule:     "mcp-destructive-fs",
		severity: SeverityHigh,
		message:  "Destructive filesystem operation: %s",
		langs:    []Language{LangJavaScript, LangTypeScript},
		cwe:      "CWE-73",
	},

	// ── Environment variable leakage — JavaScript/TypeScript ─────────────────

	// Fix 6: HIGH only when env value flows into output (return, res.send, console.log,
	// string interpolation in tool output, etc.).
	{
		pattern:  regexp.MustCompile(`(return|console\.(log|warn|error)|res\.(send|json|write)|\.push|\.join|` + "`" + `).*process\.env\.[A-Z_][A-Z0-9_]*`),
		rule:     "mcp-env-leakage",
		severity: SeverityHigh,
		message:  "Environment variable leaked to output/response: %s",
		langs:    []Language{LangJavaScript, LangTypeScript},
		cwe:      "CWE-526",
	},
	// Fix 6: INFO when process.env is used in a standard config/auth pattern
	// (assignment to a config variable, auth header construction, path join, etc.)
	// These are normal usage patterns, not leakage.
	{
		pattern:  regexp.MustCompile(`process\.env\.[A-Z_][A-Z0-9_]*`),
		rule:     "mcp-env-read",
		severity: SeverityInfo,
		message:  "Environment variable read (verify it is not exposed to output): %s",
		langs:    []Language{LangJavaScript, LangTypeScript},
		cwe:      "CWE-526",
	},

	// ── Path traversal — all languages ───────────────────────────────────────

	{
		pattern:  regexp.MustCompile(`(?i)(open|readFile|readFileSync|writeFile|writeFileSync)\s*\([^)]*\+`),
		rule:     "mcp-path-traversal-risk",
		severity: SeverityHigh,
		message:  "File operation with concatenated path (traversal risk): %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript},
		cwe:      "CWE-22",
	},

	// ── Path containment bypass — JavaScript/TypeScript ──────────────────────
	//
	// CVE-2025-53110 / CVE-2025-53109: using String.startsWith() as a directory
	// containment check is bypassable.  The safe pattern requires resolving the
	// real path first and appending a path separator before the check.

	{
		// readFileSync / readFile called on a variable that was checked with startsWith
		// Pattern: detect readFileSync used after a startsWith containment guard
		// (both lines appear in the same file, so we catch the readFileSync call itself
		// when no path.resolve/realpathSync is present — detected at directory level).
		pattern:  regexp.MustCompile(`\.startsWith\s*\([^)]*(?:Dir|dir|Path|path|Root|root|Base|base)[^)]*\)`),
		rule:     "mcp-path-containment-bypass",
		severity: SeverityHigh,
		message:  "startsWith() used as path containment check — bypassable via prefix confusion or symlinks (use path.resolve + path.sep): %s",
		langs:    []Language{LangJavaScript, LangTypeScript},
		cwe:      "CWE-22",
	},

	// ── Broken SSRF guard — JavaScript/TypeScript ────────────────────────────
	//
	// CVE-2025-65513: SSRF guard calls startsWith("10.") or startsWith("192.168.")
	// on a full URL string instead of the extracted hostname, so the check always
	// passes for targets like http://169.254.169.254/.

	{
		pattern:  regexp.MustCompile(`\.startsWith\s*\(\s*["'](10\.|192\.168\.|172\.)`),
		rule:     "mcp-ssrf-broken-check",
		severity: SeverityCritical,
		message:  "startsWith() used to check for private IP — ineffective on full URLs (extract hostname first): %s",
		langs:    []Language{LangJavaScript, LangTypeScript},
		cwe:      "CWE-918",
	},

	// ── MCP config with malicious shell commands — JSON ───────────────────────
	//
	// CVE-2025-54136: MCP server config (mcp.json / .cursor/mcp.json) can contain
	// malicious commands that execute on IDE startup.  Flag PowerShell download
	// cradles and IEX patterns in any JSON-like file.

	{
		pattern:  regexp.MustCompile(`(?i)(IEX|Invoke-Expression)\s*\(`),
		rule:     "mcp-config-rce",
		severity: SeverityCritical,
		message:  "PowerShell Invoke-Expression (IEX) in MCP config — possible rug-pull RCE payload: %s",
		langs:    []Language{LangJSON},
		cwe:      "CWE-78",
	},
	{
		pattern:  regexp.MustCompile(`(?i)DownloadString\s*\(`),
		rule:     "mcp-config-rce",
		severity: SeverityCritical,
		message:  "PowerShell DownloadString in MCP config — remote payload download pattern: %s",
		langs:    []Language{LangJSON},
		cwe:      "CWE-78",
	},

	// ── Template injection — JavaScript/TypeScript ────────────────────────────

	// (XSS via template.HTML is in Go section below)

	// ── Go: exec with concatenation ──────────────────────────────────────────

	{
		// exec.Command( followed by string concatenation on the same line
		pattern:  regexp.MustCompile(`exec\.Command\s*\([^)]*\+`),
		rule:     "mcp-cmd-injection",
		severity: SeverityCritical,
		message:  "exec.Command with string concatenation (injection risk): %s",
		langs:    []Language{LangGo},
		cwe:      "CWE-78",
	},
	{
		// exec.Command without concatenation — flag for review
		pattern:  regexp.MustCompile(`exec\.Command\s*\(`),
		rule:     "mcp-cmd-injection",
		severity: SeverityHigh,
		message:  "exec.Command usage (verify args do not contain user input): %s",
		langs:    []Language{LangGo},
		cwe:      "CWE-78",
	},

	// ── Go: destructive file operations ──────────────────────────────────────

	{
		pattern:  regexp.MustCompile(`os\.(Remove|RemoveAll)\s*\(`),
		rule:     "mcp-destructive-fs",
		severity: SeverityHigh,
		message:  "os.%s — file/directory deletion: %s",
		langs:    []Language{LangGo},
		cwe:      "CWE-73",
	},

	// ── Go: XSS via template.HTML ────────────────────────────────────────────

	{
		pattern:  regexp.MustCompile(`template\.HTML\s*\(`),
		rule:     "mcp-xss-risk",
		severity: SeverityHigh,
		message:  "template.HTML() type conversion bypasses auto-escaping (XSS risk): %s",
		langs:    []Language{LangGo},
		cwe:      "CWE-79",
	},

	// ── Go: outbound connections ──────────────────────────────────────────────

	{
		pattern:  regexp.MustCompile(`net\.(Dial|DialTimeout)\s*\(`),
		rule:     "mcp-outbound-connection",
		severity: SeverityWarning,
		message:  "net.Dial outbound TCP/UDP connection: %s",
		langs:    []Language{LangGo},
		cwe:      "CWE-918",
	},

	// ── Hardcoded credentials ─────────────────────────────────────────────────

	{
		pattern:      regexp.MustCompile(`(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*["'][a-zA-Z0-9+/=_-]{16,}["']`),
		rule:         "mcp-hardcoded-secret",
		severity:     SeverityCritical,
		message:      "Hardcoded credential: %s",
		langs:        []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
		cwe:          "CWE-798",
		isSecretRule: true,
	},
	{
		pattern:      regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
		rule:         "mcp-hardcoded-aws-key",
		severity:     SeverityCritical,
		message:      "Hardcoded AWS access key: %s",
		langs:        []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
		cwe:          "CWE-798",
		isSecretRule: true,
	},
	{
		pattern:      regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`),
		rule:         "mcp-hardcoded-api-key",
		severity:     SeverityCritical,
		message:      "Hardcoded API key (OpenAI format): %s",
		langs:        []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
		cwe:          "CWE-798",
		isSecretRule: true,
	},
	{
		pattern:      regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
		rule:         "mcp-hardcoded-github-pat",
		severity:     SeverityHigh,
		message:      "Hardcoded GitHub PAT: %s",
		langs:        []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
		cwe:          "CWE-798",
		isSecretRule: true,
	},

	// ── Cross-language: bearer tokens ────────────────────────────────────────

	{
		pattern:      regexp.MustCompile(`Bearer\s+[a-zA-Z0-9\-._~+/]{20,}=*`),
		rule:         "mcp-hardcoded-bearer-token",
		severity:     SeverityCritical,
		message:      "Hardcoded Bearer token: %s",
		langs:        []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
		cwe:          "CWE-798",
		isSecretRule: true,
	},

	// ── Cross-language: private key content ──────────────────────────────────

	{
		pattern:  regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
		rule:     "mcp-hardcoded-private-key",
		severity: SeverityCritical,
		message:  "Private key material embedded in source code: %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
		cwe:      "CWE-798",
	},

	// ── Cross-language: webhook URLs ─────────────────────────────────────────

	{
		pattern:  regexp.MustCompile(`hooks\.slack\.com/services/`),
		rule:     "mcp-hardcoded-webhook",
		severity: SeverityHigh,
		message:  "Hardcoded Slack webhook URL: %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
		cwe:      "CWE-798",
	},
	{
		pattern:  regexp.MustCompile(`discord\.com/api/webhooks/`),
		rule:     "mcp-hardcoded-webhook",
		severity: SeverityHigh,
		message:  "Hardcoded Discord webhook URL: %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
		cwe:      "CWE-798",
	},

	// ── Cross-language: Stripe live secret key ────────────────────────────────

	{
		pattern:      regexp.MustCompile(`sk_live_[a-zA-Z0-9]{20,}`),
		rule:         "mcp-hardcoded-stripe-key",
		severity:     SeverityCritical,
		message:      "Hardcoded Stripe live secret key: %s",
		langs:        []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
		cwe:          "CWE-798",
		isSecretRule: true,
	},

	// ── Cross-language: Twilio tokens ────────────────────────────────────────

	{
		// Twilio auth token: 32 hex chars; API key starts with SK + 32 alphanum
		pattern:      regexp.MustCompile(`SK[a-zA-Z0-9]{32}`),
		rule:         "mcp-hardcoded-twilio-key",
		severity:     SeverityHigh,
		message:      "Possible hardcoded Twilio API key (SK...): %s",
		langs:        []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
		cwe:          "CWE-798",
		isSecretRule: true,
	},
	{
		// Twilio account SID starts with AC followed by 32 hex chars
		pattern:      regexp.MustCompile(`AC[a-f0-9]{32}`),
		rule:         "mcp-hardcoded-twilio-sid",
		severity:     SeverityHigh,
		message:      "Possible hardcoded Twilio account SID (AC...): %s",
		langs:        []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
		cwe:          "CWE-798",
		isSecretRule: true,
	},
}

// Egress detection patterns
var egressPatterns = []struct {
	pattern *regexp.Regexp
	method  string
	langs   []Language
}{
	// ── Python ───────────────────────────────────────────────────────────────
	{regexp.MustCompile(`requests\.(get|post|put|delete|patch)\s*\(`), "requests.%s", []Language{LangPython}},
	{regexp.MustCompile(`urllib\.request\.urlopen\s*\(`), "urllib.request.urlopen", []Language{LangPython}},
	{regexp.MustCompile(`http\.client\.HTTPConnection\s*\(`), "http.client.HTTPConnection", []Language{LangPython}},
	{regexp.MustCompile(`\.connect\s*\(`), "socket.connect", []Language{LangPython}},
	{regexp.MustCompile(`smtplib\.SMTP\s*\(`), "smtplib.SMTP", []Language{LangPython}},
	{regexp.MustCompile(`paramiko\.SSHClient\s*\(`), "paramiko.SSHClient", []Language{LangPython}},

	// ── JavaScript / TypeScript ───────────────────────────────────────────────
	{regexp.MustCompile(`fetch\s*\(`), "fetch", []Language{LangJavaScript, LangTypeScript}},
	{regexp.MustCompile(`axios\.(get|post|put|delete|patch)\s*\(`), "axios.%s", []Language{LangJavaScript, LangTypeScript}},
	{regexp.MustCompile(`net\.connect\s*\(`), "net.connect", []Language{LangJavaScript, LangTypeScript}},
	{regexp.MustCompile(`dgram\.createSocket\s*\(`), "dgram.createSocket", []Language{LangJavaScript, LangTypeScript}},
	{regexp.MustCompile(`new\s+WebSocket\s*\(`), "ws.WebSocket", []Language{LangJavaScript, LangTypeScript}},
	{regexp.MustCompile(`new\s+XMLHttpRequest\s*\(`), "XMLHttpRequest", []Language{LangJavaScript, LangTypeScript}},

	// ── Go ────────────────────────────────────────────────────────────────────
	{regexp.MustCompile(`http\.Get\s*\(|http\.Post\s*\(`), "net/http", []Language{LangGo}},
	{regexp.MustCompile(`http\.NewRequest\s*\(`), "http.NewRequest", []Language{LangGo}},
	{regexp.MustCompile(`rpc\.Dial\s*\(`), "rpc.Dial", []Language{LangGo}},
}

// isTestDir returns true when the directory name is a well-known test directory
// that should be skipped during analysis.
func isTestDir(name string) bool {
	switch name {
	case "test", "tests", "__tests__", "spec", "testdata":
		return true
	}
	return false
}

// isTestFile returns true when the file name matches common test file conventions.
func isTestFile(name string) bool {
	// Go test files
	if strings.HasSuffix(name, "_test.go") {
		return true
	}
	// JavaScript / TypeScript test files
	if strings.HasSuffix(name, ".test.js") || strings.HasSuffix(name, ".test.ts") ||
		strings.HasSuffix(name, ".spec.js") || strings.HasSuffix(name, ".spec.ts") ||
		strings.HasSuffix(name, ".test.mjs") || strings.HasSuffix(name, ".spec.mjs") {
		return true
	}
	// Python test files
	if strings.HasSuffix(name, "_test.py") || strings.HasPrefix(name, "test_") {
		return true
	}
	return false
}

func (s *sastAnalyzer) AnalyzeFile(path string, lang Language) []Finding {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var findings []Finding
	lines := strings.Split(string(content), "\n")

	for _, sp := range sourcePatterns {
		if !languageMatch(sp.langs, lang) {
			continue
		}

		for lineNum, line := range lines {
			// Fix 3: skip comment lines — no rules fire on commented-out code.
			if isCommentLine(line, lang) {
				continue
			}

			matches := sp.pattern.FindStringSubmatch(line)
			if len(matches) == 0 {
				continue
			}

			// Fix 5: skip when any exclusion pattern matches the line.
			excluded := false
			for _, excl := range sp.excludePatterns {
				if excl.MatchString(line) {
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}

			// Fix 1 & 2: for secret rules, suppress placeholder/self-assigned values.
			if sp.isSecretRule {
				// Extract the matched value (the quoted secret part).
				// Use the full line match for placeholder check.
				matchedValue := matches[0]
				if isPlaceholderSecret(matchedValue) {
					continue
				}
				if isSelfAssignedSecret(line) {
					continue
				}
			}

			matched := strings.TrimSpace(line)
			if len(matched) > 100 {
				matched = matched[:100] + "..."
			}

			// Fix 7: downgrade destructive-fs severity to INFO when the target
			// is clearly a temporary directory.
			severity := sp.severity
			if sp.rule == "mcp-destructive-fs" && isTempDirOperation(line) {
				severity = SeverityInfo
			}

			findings = append(findings, Finding{
				Rule:     sp.rule,
				Severity: severity,
				Message:  fmt.Sprintf(sp.message, matched),
				File:     path,
				Line:     lineNum + 1,
				CWE:      sp.cwe,
			})
		}
	}

	return findings
}

func (s *sastAnalyzer) AnalyzeDirectory(dir string) []Finding {
	var findings []Finding

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == "node_modules" || base == ".git" || base == "__pycache__" || base == ".venv" {
				return filepath.SkipDir
			}
			if isTestDir(base) {
				return filepath.SkipDir
			}
			return nil
		}

		if isTestFile(filepath.Base(path)) {
			return nil
		}

		lang := detectLanguage(path)
		if lang == LangUnknown {
			return nil
		}

		fileFindings := s.AnalyzeFile(path, lang)
		findings = append(findings, fileFindings...)
		return nil
	})

	return findings
}

func (s *sastAnalyzer) DetectEgress(dir string) []EgressFinding {
	var findings []EgressFinding

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == "node_modules" || base == ".git" || base == "__pycache__" || base == ".venv" {
				return filepath.SkipDir
			}
			if isTestDir(base) {
				return filepath.SkipDir
			}
			return nil
		}

		if isTestFile(filepath.Base(path)) {
			return nil
		}

		lang := detectLanguage(path)
		if lang == LangUnknown {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer func() { _ = file.Close() }()

		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			for _, ep := range egressPatterns {
				if !languageMatch(ep.langs, lang) {
					continue
				}
				matches := ep.pattern.FindStringSubmatch(line)
				if len(matches) > 0 {
					method := ep.method
					if strings.Contains(method, "%s") && len(matches) > 1 {
						method = fmt.Sprintf(method, matches[1])
					}
					findings = append(findings, EgressFinding{
						File:   path,
						Line:   lineNum,
						Method: method,
					})
				}
			}
		}
		return nil
	})

	return findings
}

func detectLanguage(path string) Language {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".py":
		return LangPython
	case ".js", ".mjs", ".cjs":
		return LangJavaScript
	case ".ts", ".mts":
		return LangTypeScript
	case ".go":
		return LangGo
	case ".json":
		// Only scan JSON files that look like MCP config files for malicious
		// command patterns (rug-pull / CVE-2025-54136 class).
		base := strings.ToLower(filepath.Base(path))
		if isMCPConfigFile(base) {
			return LangJSON
		}
		return LangUnknown
	default:
		return LangUnknown
	}
}

// isMCPConfigFile returns true for JSON filenames commonly used as MCP server
// configuration, where malicious command injection (rug-pull) is a known risk.
func isMCPConfigFile(base string) bool {
	mcpConfigNames := []string{
		"mcp.json",
		"mcp_servers.json",
		"mcp-servers.json",
		"claude_desktop_config.json",
		"cursor_mcp.json",
	}
	for _, name := range mcpConfigNames {
		if base == name {
			return true
		}
	}
	return false
}

func languageMatch(supported []Language, lang Language) bool {
	for _, l := range supported {
		if l == lang {
			return true
		}
	}
	return false
}
