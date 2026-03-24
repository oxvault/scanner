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
	pattern  *regexp.Regexp
	rule     string
	severity Severity
	message  string
	langs    []Language
}

var sourcePatterns = []sourcePattern{
	// ── Command injection — Python ────────────────────────────────────────────

	{
		pattern:  regexp.MustCompile(`os\.(popen|system)\s*\(`),
		rule:     "mcp-cmd-injection",
		severity: SeverityCritical,
		message:  "Direct OS command execution: %s",
		langs:    []Language{LangPython},
	},
	{
		// subprocess.run/call/Popen/check_output with shell=True on the same line
		pattern:  regexp.MustCompile(`subprocess\.(run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True`),
		rule:     "mcp-cmd-injection",
		severity: SeverityCritical,
		message:  "Subprocess with shell=True: %s",
		langs:    []Language{LangPython},
	},
	{
		// subprocess.check_output alone (may use shell=True on a different line
		// or the call itself is dangerous if args contain user input)
		pattern:  regexp.MustCompile(`subprocess\.check_output\s*\(`),
		rule:     "mcp-cmd-injection",
		severity: SeverityHigh,
		message:  "subprocess.check_output usage (verify shell=False and safe args): %s",
		langs:    []Language{LangPython},
	},
	{
		// subprocess.Popen alone
		pattern:  regexp.MustCompile(`subprocess\.Popen\s*\(`),
		rule:     "mcp-cmd-injection",
		severity: SeverityHigh,
		message:  "subprocess.Popen usage (verify shell=False and safe args): %s",
		langs:    []Language{LangPython},
	},
	{
		// exec() — Python built-in dynamic code execution
		pattern:  regexp.MustCompile(`\bexec\s*\(`),
		rule:     "mcp-code-eval",
		severity: SeverityCritical,
		message:  "Python exec() dynamic code execution: %s",
		langs:    []Language{LangPython},
	},
	{
		pattern:  regexp.MustCompile(`eval\s*\(`),
		rule:     "mcp-code-eval",
		severity: SeverityCritical,
		message:  "Dynamic code evaluation: %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript},
	},
	{
		// __import__ — dynamic module import, often used in payloads
		pattern:  regexp.MustCompile(`__import__\s*\(`),
		rule:     "mcp-dynamic-import",
		severity: SeverityHigh,
		message:  "Dynamic __import__() call (potential payload execution): %s",
		langs:    []Language{LangPython},
	},

	// ── Deserialization — Python ──────────────────────────────────────────────

	{
		pattern:  regexp.MustCompile(`pickle\.(loads?)\s*\(`),
		rule:     "mcp-unsafe-deserialization",
		severity: SeverityCritical,
		message:  "Unsafe pickle deserialization (arbitrary code execution risk): %s",
		langs:    []Language{LangPython},
	},
	{
		// yaml.load( without Loader= is the unsafe form; yaml.safe_load is fine
		pattern:  regexp.MustCompile(`yaml\.load\s*\([^)]*\)`),
		rule:     "mcp-unsafe-deserialization",
		severity: SeverityHigh,
		message:  "Unsafe yaml.load() without SafeLoader (use yaml.safe_load): %s",
		langs:    []Language{LangPython},
	},

	// ── SSRF / open redirect — Python ────────────────────────────────────────

	{
		// requests.get/post with a variable URL (potential SSRF)
		pattern:  regexp.MustCompile(`requests\.(get|post)\s*\(\s*[^"'\s][^)]*\)`),
		rule:     "mcp-ssrf-risk",
		severity: SeverityWarning,
		message:  "requests.%s with dynamic URL (potential SSRF — validate/allowlist URLs): %s",
		langs:    []Language{LangPython},
	},

	// ── Destructive file operations — Python ─────────────────────────────────

	{
		pattern:  regexp.MustCompile(`shutil\.rmtree\s*\(`),
		rule:     "mcp-destructive-fs",
		severity: SeverityHigh,
		message:  "shutil.rmtree() — recursive directory deletion: %s",
		langs:    []Language{LangPython},
	},
	{
		pattern:  regexp.MustCompile(`os\.remove\s*\(`),
		rule:     "mcp-destructive-fs",
		severity: SeverityHigh,
		message:  "os.remove() — file deletion: %s",
		langs:    []Language{LangPython},
	},

	// ── Command injection — JavaScript/TypeScript ─────────────────────────────

	{
		pattern:  regexp.MustCompile(`child_process\.(exec|execSync)\s*\(`),
		rule:     "mcp-cmd-injection",
		severity: SeverityCritical,
		message:  "child_process.exec with potential injection: %s",
		langs:    []Language{LangJavaScript, LangTypeScript},
	},
	{
		// child_process.execSync standalone import
		pattern:  regexp.MustCompile(`child_process\.execSync\s*\(`),
		rule:     "mcp-cmd-injection",
		severity: SeverityCritical,
		message:  "child_process.execSync (synchronous shell execution): %s",
		langs:    []Language{LangJavaScript, LangTypeScript},
	},
	{
		// child_process.spawn with shell: true
		pattern:  regexp.MustCompile(`child_process\.spawn\s*\([^)]*shell\s*:\s*true`),
		rule:     "mcp-cmd-injection",
		severity: SeverityCritical,
		message:  "child_process.spawn with shell:true: %s",
		langs:    []Language{LangJavaScript, LangTypeScript},
	},
	{
		// require('child_process') — flag the import itself; egress picks up usage
		pattern:  regexp.MustCompile(`require\s*\(\s*['"]child_process['"]\s*\)`),
		rule:     "mcp-cmd-injection",
		severity: SeverityHigh,
		message:  "child_process module imported (verify no unsafe .exec usage): %s",
		langs:    []Language{LangJavaScript, LangTypeScript},
	},

	// ── Code generation / eval — JavaScript/TypeScript ───────────────────────

	{
		// new Function(...) — runtime code generation
		pattern:  regexp.MustCompile(`new\s+Function\s*\(`),
		rule:     "mcp-code-eval",
		severity: SeverityCritical,
		message:  "new Function() — dynamic code generation: %s",
		langs:    []Language{LangJavaScript, LangTypeScript},
	},
	{
		// setTimeout/setInterval with a string first argument (implicit eval)
		pattern:  regexp.MustCompile(`(setTimeout|setInterval)\s*\(\s*["'\x60]`),
		rule:     "mcp-code-eval",
		severity: SeverityHigh,
		message:  "setTimeout/setInterval with string argument (implicit eval): %s",
		langs:    []Language{LangJavaScript, LangTypeScript},
	},
	{
		// vm.runInNewContext / vm.runInThisContext — Node.js sandbox escape
		pattern:  regexp.MustCompile(`vm\.(runInNewContext|runInThisContext)\s*\(`),
		rule:     "mcp-sandbox-escape",
		severity: SeverityCritical,
		message:  "vm.%s — Node.js sandbox escape risk: %s",
		langs:    []Language{LangJavaScript, LangTypeScript},
	},

	// ── Destructive file operations — JavaScript/TypeScript ───────────────────

	{
		pattern:  regexp.MustCompile(`fs\.(unlinkSync|rmdir(?:Sync)?|rm(?:Sync)?)\s*\(`),
		rule:     "mcp-destructive-fs",
		severity: SeverityHigh,
		message:  "Destructive filesystem operation: %s",
		langs:    []Language{LangJavaScript, LangTypeScript},
	},

	// ── Environment variable leakage — JavaScript/TypeScript ─────────────────

	{
		// process.env.SOMETHING returned or logged directly
		pattern:  regexp.MustCompile(`process\.env\.[A-Z_][A-Z0-9_]*`),
		rule:     "mcp-env-leakage",
		severity: SeverityWarning,
		message:  "Direct process.env access (verify env vars are not leaked to output): %s",
		langs:    []Language{LangJavaScript, LangTypeScript},
	},

	// ── Path traversal — all languages ───────────────────────────────────────

	{
		pattern:  regexp.MustCompile(`(?i)(open|readFile|readFileSync|writeFile|writeFileSync)\s*\([^)]*\+`),
		rule:     "mcp-path-traversal-risk",
		severity: SeverityHigh,
		message:  "File operation with concatenated path (traversal risk): %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript},
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
	},
	{
		pattern:  regexp.MustCompile(`(?i)DownloadString\s*\(`),
		rule:     "mcp-config-rce",
		severity: SeverityCritical,
		message:  "PowerShell DownloadString in MCP config — remote payload download pattern: %s",
		langs:    []Language{LangJSON},
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
	},
	{
		// exec.Command without concatenation — flag for review
		pattern:  regexp.MustCompile(`exec\.Command\s*\(`),
		rule:     "mcp-cmd-injection",
		severity: SeverityHigh,
		message:  "exec.Command usage (verify args do not contain user input): %s",
		langs:    []Language{LangGo},
	},

	// ── Go: destructive file operations ──────────────────────────────────────

	{
		pattern:  regexp.MustCompile(`os\.(Remove|RemoveAll)\s*\(`),
		rule:     "mcp-destructive-fs",
		severity: SeverityHigh,
		message:  "os.%s — file/directory deletion: %s",
		langs:    []Language{LangGo},
	},

	// ── Go: XSS via template.HTML ────────────────────────────────────────────

	{
		pattern:  regexp.MustCompile(`template\.HTML\s*\(`),
		rule:     "mcp-xss-risk",
		severity: SeverityHigh,
		message:  "template.HTML() type conversion bypasses auto-escaping (XSS risk): %s",
		langs:    []Language{LangGo},
	},

	// ── Go: outbound connections ──────────────────────────────────────────────

	{
		pattern:  regexp.MustCompile(`net\.(Dial|DialTimeout)\s*\(`),
		rule:     "mcp-outbound-connection",
		severity: SeverityWarning,
		message:  "net.Dial outbound TCP/UDP connection: %s",
		langs:    []Language{LangGo},
	},

	// ── Hardcoded credentials ─────────────────────────────────────────────────

	{
		pattern:  regexp.MustCompile(`(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*["'][a-zA-Z0-9+/=_-]{16,}["']`),
		rule:     "mcp-hardcoded-secret",
		severity: SeverityCritical,
		message:  "Hardcoded credential: %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
	},
	{
		pattern:  regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
		rule:     "mcp-hardcoded-aws-key",
		severity: SeverityCritical,
		message:  "Hardcoded AWS access key: %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
	},
	{
		pattern:  regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`),
		rule:     "mcp-hardcoded-api-key",
		severity: SeverityCritical,
		message:  "Hardcoded API key (OpenAI format): %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
	},
	{
		pattern:  regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
		rule:     "mcp-hardcoded-github-pat",
		severity: SeverityHigh,
		message:  "Hardcoded GitHub PAT: %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
	},

	// ── Cross-language: bearer tokens ────────────────────────────────────────

	{
		pattern:  regexp.MustCompile(`Bearer\s+[a-zA-Z0-9\-._~+/]{20,}=*`),
		rule:     "mcp-hardcoded-bearer-token",
		severity: SeverityCritical,
		message:  "Hardcoded Bearer token: %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
	},

	// ── Cross-language: private key content ──────────────────────────────────

	{
		pattern:  regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
		rule:     "mcp-hardcoded-private-key",
		severity: SeverityCritical,
		message:  "Private key material embedded in source code: %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
	},

	// ── Cross-language: webhook URLs ─────────────────────────────────────────

	{
		pattern:  regexp.MustCompile(`hooks\.slack\.com/services/`),
		rule:     "mcp-hardcoded-webhook",
		severity: SeverityHigh,
		message:  "Hardcoded Slack webhook URL: %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
	},
	{
		pattern:  regexp.MustCompile(`discord\.com/api/webhooks/`),
		rule:     "mcp-hardcoded-webhook",
		severity: SeverityHigh,
		message:  "Hardcoded Discord webhook URL: %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
	},

	// ── Cross-language: Stripe live secret key ────────────────────────────────

	{
		pattern:  regexp.MustCompile(`sk_live_[a-zA-Z0-9]{20,}`),
		rule:     "mcp-hardcoded-stripe-key",
		severity: SeverityCritical,
		message:  "Hardcoded Stripe live secret key: %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
	},

	// ── Cross-language: Twilio tokens ────────────────────────────────────────

	{
		// Twilio auth token: 32 hex chars; API key starts with SK + 32 alphanum
		pattern:  regexp.MustCompile(`SK[a-zA-Z0-9]{32}`),
		rule:     "mcp-hardcoded-twilio-key",
		severity: SeverityHigh,
		message:  "Possible hardcoded Twilio API key (SK...): %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
	},
	{
		// Twilio account SID starts with AC followed by 32 hex chars
		pattern:  regexp.MustCompile(`AC[a-f0-9]{32}`),
		rule:     "mcp-hardcoded-twilio-sid",
		severity: SeverityHigh,
		message:  "Possible hardcoded Twilio account SID (AC...): %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
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
			matches := sp.pattern.FindStringSubmatch(line)
			if len(matches) > 0 {
				matched := strings.TrimSpace(line)
				if len(matched) > 100 {
					matched = matched[:100] + "..."
				}
				findings = append(findings, Finding{
					Rule:     sp.rule,
					Severity: sp.severity,
					Message:  fmt.Sprintf(sp.message, matched),
					File:     path,
					Line:     lineNum + 1,
				})
			}
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
		defer file.Close()

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
