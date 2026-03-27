package patterns

import "regexp"

// PlaceholderPatterns is a compiled list of patterns that indicate a value is
// an example or placeholder rather than a real secret.
var PlaceholderPatterns = []*regexp.Regexp{
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
	// Substring match (no word boundary) so that "mocked", "mocking" etc. are
	// all suppressed, not just the bare word "mock".
	regexp.MustCompile(`(?i)mock`),
	regexp.MustCompile(`(?i)fake`),
	regexp.MustCompile(`(?i)\btest\b`),
	regexp.MustCompile(`(?i)^pending[_-]`),
}

// TempDirPatterns detects when a destructive FS operation clearly targets a
// temporary directory, reducing the severity to INFO.
var TempDirPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)tmp`),
	regexp.MustCompile(`(?i)temp`),
	regexp.MustCompile(`(?i)cache`),
	regexp.MustCompile(`os\.tmpdir\s*\(`),
	regexp.MustCompile(`tempfile`),
	regexp.MustCompile(`mkdtemp`),
	regexp.MustCompile(`RUNNER_TEMP`),
}

// CommentOnlyLanguages lists extensions where `#` begins a single-line comment.
var CommentOnlyLanguages = map[Language]bool{
	LangPython: true,
}

// TestDirs are well-known test directory names that should be skipped during analysis.
var TestDirs = []string{
	"test", "tests", "__tests__", "spec", "testdata",
	"evals", "eval", "fixtures", "fixture",
	"__mocks__", "mocks", "mock",
	"__fixtures__",
}

// ExcludedDirs are directories that should be entirely skipped during SAST analysis.
// This does NOT include test dirs -- those are checked separately via TestDirs.
var ExcludedDirs = []string{
	"node_modules", "vendor",
	".smithery",
	".git", "__pycache__", ".venv",
	"dist", "build", "out",
	"third_party", "third-party",
}

// MCPConfigNames are JSON filenames commonly used as MCP server configuration.
var MCPConfigNames = []string{
	"mcp.json",
	"mcp_servers.json",
	"mcp-servers.json",
	"claude_desktop_config.json",
	"cursor_mcp.json",
}

// SourcePatterns contains all SAST source code analysis patterns.
var SourcePatterns = []SourcePattern{
	// ── Command injection -- Python ────────────────────────────────────────────

	{
		Pattern:    regexp.MustCompile(`os\.(popen|system)\s*\(`),
		Rule:       "mcp-cmd-injection",
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		Message:    "Direct OS command execution: %s",
		Langs:      []Language{LangPython},
		CWE:        "CWE-78",
	},
	{
		// subprocess.run/call/Popen/check_output with shell=True on the same line
		Pattern:    regexp.MustCompile(`subprocess\.(run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True`),
		Rule:       "mcp-cmd-injection",
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		Message:    "Subprocess with shell=True: %s",
		Langs:      []Language{LangPython},
		CWE:        "CWE-78",
	},
	{
		// subprocess.check_output alone
		Pattern:    regexp.MustCompile(`subprocess\.check_output\s*\(`),
		Rule:       "mcp-cmd-injection",
		Severity:   SeverityHigh,
		Confidence: ConfidenceMedium,
		Message:    "subprocess.check_output usage (verify shell=False and safe args): %s",
		Langs:      []Language{LangPython},
		CWE:        "CWE-78",
	},
	{
		// subprocess.Popen alone
		Pattern:    regexp.MustCompile(`subprocess\.Popen\s*\(`),
		Rule:       "mcp-cmd-injection",
		Severity:   SeverityHigh,
		Confidence: ConfidenceMedium,
		Message:    "subprocess.Popen usage (verify shell=False and safe args): %s",
		Langs:      []Language{LangPython},
		CWE:        "CWE-78",
	},
	{
		// exec() -- Python built-in dynamic code execution.
		Pattern:    regexp.MustCompile(`\bexec\s*\(`),
		Rule:       "mcp-code-eval",
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		Message:    "Python exec() dynamic code execution: %s",
		Langs:      []Language{LangPython},
		CWE:        "CWE-94",
		ExcludePatterns: []*regexp.Regexp{
			regexp.MustCompile(`["'][^"']*\bexec\s*\(`),
		},
	},
	{
		Pattern:    regexp.MustCompile(`\beval\s*\(`),
		Rule:       "mcp-code-eval",
		Severity:   SeverityCritical,
		Confidence: ConfidenceMedium,
		Message:    "Dynamic code evaluation: %s",
		Langs:      []Language{LangPython, LangJavaScript, LangTypeScript},
		CWE:        "CWE-94",
		ExcludePatterns: []*regexp.Regexp{
			regexp.MustCompile(`ast\.literal_eval\s*\(`),
			regexp.MustCompile(`\$\$?eval\s*\(`),
			regexp.MustCompile(`["'][^"']*\beval\s*\(`),
		},
	},
	{
		// __import__ -- dynamic module import
		Pattern:    regexp.MustCompile(`__import__\s*\(`),
		Rule:       "mcp-dynamic-import",
		Severity:   SeverityHigh,
		Confidence: ConfidenceMedium,
		Message:    "Dynamic __import__() call (potential payload execution): %s",
		Langs:      []Language{LangPython},
		CWE:        "CWE-94",
		ExcludePatterns: []*regexp.Regexp{
			regexp.MustCompile(`__import__\s*\(\s*['"]pkgutil['"]\s*\)`),
			regexp.MustCompile(`pkgutil`),
			regexp.MustCompile(`importlib\.import_module`),
		},
	},

	// ── Deserialization -- Python ──────────────────────────────────────────────

	{
		Pattern:    regexp.MustCompile(`pickle\.(loads?)\s*\(`),
		Rule:       "mcp-unsafe-deserialization",
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		Message:    "Unsafe pickle deserialization (arbitrary code execution risk): %s",
		Langs:      []Language{LangPython},
		CWE:        "CWE-502",
		ExcludePatterns: []*regexp.Regexp{
			regexp.MustCompile(`["'][^"']*pickle\.(loads?)\s*\(`),
		},
	},
	{
		// yaml.load( without Loader= is the unsafe form
		Pattern:    regexp.MustCompile(`yaml\.load\s*\([^)]*\)`),
		Rule:       "mcp-unsafe-deserialization",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Message:    "Unsafe yaml.load() without SafeLoader (use yaml.safe_load): %s",
		Langs:      []Language{LangPython},
		CWE:        "CWE-502",
		ExcludePatterns: []*regexp.Regexp{
			regexp.MustCompile(`["'][^"']*yaml\.load\s*\(`),
		},
	},

	// ── SSRF / open redirect -- Python ────────────────────────────────────────

	{
		Pattern:    regexp.MustCompile(`requests\.(get|post)\s*\(\s*[^"'\s][^)]*\)`),
		Rule:       "mcp-ssrf-risk",
		Severity:   SeverityWarning,
		Confidence: ConfidenceLow,
		Message:    "requests.%s with dynamic URL (potential SSRF — validate/allowlist URLs): %s",
		Langs:      []Language{LangPython},
		CWE:        "CWE-918",
	},

	// ── Destructive file operations -- Python ─────────────────────────────────

	{
		Pattern:    regexp.MustCompile(`shutil\.rmtree\s*\(`),
		Rule:       "mcp-destructive-fs",
		Severity:   SeverityHigh,
		Confidence: ConfidenceMedium,
		Message:    "shutil.rmtree() — recursive directory deletion: %s",
		Langs:      []Language{LangPython},
		CWE:        "CWE-73",
	},
	{
		Pattern:    regexp.MustCompile(`os\.remove\s*\(`),
		Rule:       "mcp-destructive-fs",
		Severity:   SeverityHigh,
		Confidence: ConfidenceMedium,
		Message:    "os.remove() — file deletion: %s",
		Langs:      []Language{LangPython},
		CWE:        "CWE-73",
	},

	// ── Command injection -- JavaScript/TypeScript ─────────────────────────────

	{
		Pattern:    regexp.MustCompile("child_process\\.(exec|execSync)\\s*\\([^)]*(?:\\+|`)"),
		Rule:       "mcp-cmd-injection",
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		Message:    "child_process.exec with string concatenation/template (injection risk): %s",
		Langs:      []Language{LangJavaScript, LangTypeScript},
		CWE:        "CWE-78",
		ExcludePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(\$\{?\s*)?(ppid|process\.pid|process\.ppid)\s*\}?`),
		},
	},
	{
		Pattern:    regexp.MustCompile("\\bexecSync?\\s*\\([^)]*(?:\\+|`)"),
		Rule:       "mcp-cmd-injection",
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		Message:    "execSync with string concatenation/template (injection risk): %s",
		Langs:      []Language{LangJavaScript, LangTypeScript},
		CWE:        "CWE-78",
		ExcludePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(\$\{?\s*)?(ppid|process\.pid|process\.ppid)\s*\}?`),
		},
	},
	{
		Pattern:    regexp.MustCompile(`child_process\.spawn\s*\([^)]*shell\s*:\s*true`),
		Rule:       "mcp-cmd-injection",
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		Message:    "child_process.spawn with shell:true: %s",
		Langs:      []Language{LangJavaScript, LangTypeScript},
		CWE:        "CWE-78",
	},
	{
		Pattern:    regexp.MustCompile(`require\s*\(\s*['"]child_process['"]\s*\)`),
		Rule:       "mcp-cmd-injection",
		Severity:   SeverityInfo,
		Confidence: ConfidenceLow,
		Message:    "child_process module imported (verify no unsafe .exec usage): %s",
		Langs:      []Language{LangJavaScript, LangTypeScript},
		CWE:        "CWE-78",
	},

	// ── Code generation / eval -- JavaScript/TypeScript ───────────────────────

	{
		Pattern:    regexp.MustCompile(`new\s+Function\s*\(`),
		Rule:       "mcp-code-eval",
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		Message:    "new Function() — dynamic code generation: %s",
		Langs:      []Language{LangJavaScript, LangTypeScript},
		CWE:        "CWE-94",
	},
	{
		Pattern:    regexp.MustCompile(`(setTimeout|setInterval)\s*\(\s*["'\x60]`),
		Rule:       "mcp-code-eval",
		Severity:   SeverityHigh,
		Confidence: ConfidenceMedium,
		Message:    "setTimeout/setInterval with string argument (implicit eval): %s",
		Langs:      []Language{LangJavaScript, LangTypeScript},
		CWE:        "CWE-94",
	},
	{
		Pattern:    regexp.MustCompile(`vm\.(runInNewContext|runInThisContext)\s*\(`),
		Rule:       "mcp-sandbox-escape",
		Severity:   SeverityCritical,
		Confidence: ConfidenceMedium,
		Message:    "vm.%s — Node.js sandbox escape risk: %s",
		Langs:      []Language{LangJavaScript, LangTypeScript},
		CWE:        "CWE-265",
	},

	// ── Destructive file operations -- JavaScript/TypeScript ───────────────────

	{
		Pattern:    regexp.MustCompile(`fs\.(unlinkSync|rmdir(?:Sync)?|rm(?:Sync)?)\s*\(`),
		Rule:       "mcp-destructive-fs",
		Severity:   SeverityHigh,
		Confidence: ConfidenceMedium,
		Message:    "Destructive filesystem operation: %s",
		Langs:      []Language{LangJavaScript, LangTypeScript},
		CWE:        "CWE-73",
	},

	// ── Environment variable leakage -- JavaScript/TypeScript ─────────────────

	{
		Pattern:    regexp.MustCompile(`(return|console\.(log|warn|error)|res\.(send|json|write)|\.push|\.join|` + "`" + `).*process\.env\.[A-Z_][A-Z0-9_]*`),
		Rule:       "mcp-env-leakage",
		Severity:   SeverityHigh,
		Confidence: ConfidenceMedium,
		Message:    "Environment variable leaked to output/response: %s",
		Langs:      []Language{LangJavaScript, LangTypeScript},
		CWE:        "CWE-526",
	},
	{
		Pattern:    regexp.MustCompile(`process\.env\.[A-Z_][A-Z0-9_]*`),
		Rule:       "mcp-env-read",
		Severity:   SeverityInfo,
		Confidence: ConfidenceLow,
		Message:    "Environment variable read (verify it is not exposed to output): %s",
		Langs:      []Language{LangJavaScript, LangTypeScript},
		CWE:        "CWE-526",
	},

	// ── Path traversal -- all languages ───────────────────────────────────────

	{
		Pattern:    regexp.MustCompile(`(?i)(open|readFile|readFileSync|writeFile|writeFileSync)\s*\([^)]*\+`),
		Rule:       "mcp-path-traversal-risk",
		Severity:   SeverityHigh,
		Confidence: ConfidenceMedium,
		Message:    "File operation with concatenated path (traversal risk): %s",
		Langs:      []Language{LangPython, LangJavaScript, LangTypeScript},
		CWE:        "CWE-22",
	},

	// ── Path containment bypass -- JavaScript/TypeScript ──────────────────────

	{
		Pattern:    regexp.MustCompile(`\.startsWith\s*\([^)]*(?:Dir|dir|Path|path|Root|root|Base|base)[^)]*\)`),
		Rule:       "mcp-path-containment-bypass",
		Severity:   SeverityHigh,
		Confidence: ConfidenceMedium,
		Message:    "startsWith() used as path containment check — bypassable via prefix confusion or symlinks (use path.resolve + path.sep): %s",
		Langs:      []Language{LangJavaScript, LangTypeScript},
		CWE:        "CWE-22",
		ExcludePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(cors|route|url|pathname|origin|host)`),
		},
	},

	// ── Broken SSRF guard -- JavaScript/TypeScript ────────────────────────────

	{
		Pattern:    regexp.MustCompile(`\.startsWith\s*\(\s*["'](10\.|192\.168\.|172\.)`),
		Rule:       "mcp-ssrf-broken-check",
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		Message:    "startsWith() used to check for private IP — ineffective on full URLs (extract hostname first): %s",
		Langs:      []Language{LangJavaScript, LangTypeScript},
		CWE:        "CWE-918",
	},

	// ── MCP config with malicious shell commands -- JSON ───────────────────────

	{
		Pattern:    regexp.MustCompile(`(?i)(IEX|Invoke-Expression)\s*\(`),
		Rule:       "mcp-config-rce",
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		Message:    "PowerShell Invoke-Expression (IEX) in MCP config — possible rug-pull RCE payload: %s",
		Langs:      []Language{LangJSON},
		CWE:        "CWE-78",
	},
	{
		Pattern:    regexp.MustCompile(`(?i)DownloadString\s*\(`),
		Rule:       "mcp-config-rce",
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		Message:    "PowerShell DownloadString in MCP config — remote payload download pattern: %s",
		Langs:      []Language{LangJSON},
		CWE:        "CWE-78",
	},

	// ── Go: exec with concatenation ──────────────────────────────────────────

	{
		Pattern:    regexp.MustCompile(`exec\.Command\s*\([^)]*\+`),
		Rule:       "mcp-cmd-injection",
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		Message:    "exec.Command with string concatenation (injection risk): %s",
		Langs:      []Language{LangGo},
		CWE:        "CWE-78",
	},
	{
		Pattern:    regexp.MustCompile(`exec\.Command\s*\(`),
		Rule:       "mcp-cmd-injection",
		Severity:   SeverityHigh,
		Confidence: ConfidenceMedium,
		Message:    "exec.Command usage (verify args do not contain user input): %s",
		Langs:      []Language{LangGo},
		CWE:        "CWE-78",
	},

	// ── Go: destructive file operations ──────────────────────────────────────

	{
		Pattern:    regexp.MustCompile(`os\.(Remove|RemoveAll)\s*\(`),
		Rule:       "mcp-destructive-fs",
		Severity:   SeverityHigh,
		Confidence: ConfidenceMedium,
		Message:    "os.%s — file/directory deletion: %s",
		Langs:      []Language{LangGo},
		CWE:        "CWE-73",
	},

	// ── Go: XSS via template.HTML ────────────────────────────────────────────

	{
		Pattern:    regexp.MustCompile(`template\.HTML\s*\(`),
		Rule:       "mcp-xss-risk",
		Severity:   SeverityHigh,
		Confidence: ConfidenceMedium,
		Message:    "template.HTML() type conversion bypasses auto-escaping (XSS risk): %s",
		Langs:      []Language{LangGo},
		CWE:        "CWE-79",
	},

	// ── Go: outbound connections ──────────────────────────────────────────────

	{
		Pattern:    regexp.MustCompile(`net\.(Dial|DialTimeout)\s*\(`),
		Rule:       "mcp-outbound-connection",
		Severity:   SeverityWarning,
		Confidence: ConfidenceLow,
		Message:    "net.Dial outbound TCP/UDP connection: %s",
		Langs:      []Language{LangGo},
		CWE:        "CWE-918",
	},

	// ── Hardcoded credentials ─────────────────────────────────────────────────

	{
		Pattern:      regexp.MustCompile(`(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*["'][a-zA-Z0-9+/=_-]{16,}["']`),
		Rule:         "mcp-hardcoded-secret",
		Severity:     SeverityCritical,
		Confidence:   ConfidenceMedium,
		Message:      "Hardcoded credential: %s",
		Langs:        []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
		CWE:          "CWE-798",
		IsSecretRule: true,
	},
	{
		Pattern:      regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
		Rule:         "mcp-hardcoded-aws-key",
		Severity:     SeverityCritical,
		Confidence:   ConfidenceHigh,
		Message:      "Hardcoded AWS access key: %s",
		Langs:        []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
		CWE:          "CWE-798",
		IsSecretRule: true,
	},
	{
		Pattern:      regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`),
		Rule:         "mcp-hardcoded-api-key",
		Severity:     SeverityCritical,
		Confidence:   ConfidenceHigh,
		Message:      "Hardcoded API key (OpenAI format): %s",
		Langs:        []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
		CWE:          "CWE-798",
		IsSecretRule: true,
	},
	{
		Pattern:      regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
		Rule:         "mcp-hardcoded-github-pat",
		Severity:     SeverityHigh,
		Confidence:   ConfidenceHigh,
		Message:      "Hardcoded GitHub PAT: %s",
		Langs:        []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
		CWE:          "CWE-798",
		IsSecretRule: true,
	},

	// ── Cross-language: bearer tokens ────────────────────────────────────────

	{
		Pattern:      regexp.MustCompile(`Bearer\s+[a-zA-Z0-9\-._~+/]{20,}=*`),
		Rule:         "mcp-hardcoded-bearer-token",
		Confidence:   ConfidenceHigh,
		Severity:     SeverityCritical,
		Message:      "Hardcoded Bearer token: %s",
		Langs:        []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
		CWE:          "CWE-798",
		IsSecretRule: true,
	},

	// ── Cross-language: private key content ──────────────────────────────────

	{
		Pattern:    regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
		Rule:       "mcp-hardcoded-private-key",
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		Message:    "Private key material embedded in source code: %s",
		Langs:      []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
		CWE:        "CWE-798",
		ExcludePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)regexp\.MustCompile|regexp\.Compile|re\.compile|new\s+RegExp`),
			regexp.MustCompile("`[^`]*-----BEGIN"),
		},
	},

	// ── Cross-language: webhook URLs ─────────────────────────────────────────

	{
		Pattern:    regexp.MustCompile(`hooks\.slack\.com/services/`),
		Rule:       "mcp-hardcoded-webhook",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Message:    "Hardcoded Slack webhook URL: %s",
		Langs:      []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
		CWE:        "CWE-798",
	},
	{
		Pattern:    regexp.MustCompile(`discord\.com/api/webhooks/`),
		Rule:       "mcp-hardcoded-webhook",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Message:    "Hardcoded Discord webhook URL: %s",
		Langs:      []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
		CWE:        "CWE-798",
	},

	// ── Cross-language: Stripe live secret key ────────────────────────────────

	{
		Pattern:      regexp.MustCompile(`sk_live_[a-zA-Z0-9]{20,}`),
		Rule:         "mcp-hardcoded-stripe-key",
		Severity:     SeverityCritical,
		Confidence:   ConfidenceHigh,
		Message:      "Hardcoded Stripe live secret key: %s",
		Langs:        []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
		CWE:          "CWE-798",
		IsSecretRule: true,
	},

	// ── Cross-language: Twilio tokens ────────────────────────────────────────

	{
		Pattern:      regexp.MustCompile(`SK[a-zA-Z0-9]{32}`),
		Rule:         "mcp-hardcoded-twilio-key",
		Severity:     SeverityHigh,
		Confidence:   ConfidenceMedium,
		Message:      "Possible hardcoded Twilio API key (SK...): %s",
		Langs:        []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
		CWE:          "CWE-798",
		IsSecretRule: true,
	},
	{
		Pattern:      regexp.MustCompile(`AC[a-f0-9]{32}`),
		Rule:         "mcp-hardcoded-twilio-sid",
		Severity:     SeverityHigh,
		Confidence:   ConfidenceMedium,
		Message:      "Possible hardcoded Twilio account SID (AC...): %s",
		Langs:        []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
		CWE:          "CWE-798",
		IsSecretRule: true,
	},
}

// EgressPatterns contains patterns for detecting outbound network calls.
var EgressPatterns = []EgressPattern{
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
