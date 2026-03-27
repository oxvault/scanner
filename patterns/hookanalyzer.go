package patterns

import "regexp"

// HookInstallScripts is the set of package.json script keys that run during install.
var HookInstallScripts = []string{
	"preinstall",
	"install",
	"postinstall",
	"prepare",
}

// HookPatterns are ordered from most to least severe.
var HookPatterns = []HookPattern{
	// ── CRITICAL: Direct execution threats ──────────────────────────────────

	{
		// curl ... | sh / curl ... | bash / curl ... | /bin/sh
		Pattern:  regexp.MustCompile(`(?i)(curl|wget)\s+[^\|]+\|\s*(bash|sh|/bin/sh|/bin/bash)`),
		Rule:     "mcp-install-hook-pipe-to-shell",
		Severity: SeverityCritical,
		Message:  "Install script pipes remote download to shell: %s",
		CWE:      "CWE-506",
	},
	{
		// eval(...) with dynamic content
		Pattern:  regexp.MustCompile(`\beval\s*\(`),
		Rule:     "mcp-install-hook-eval",
		Severity: SeverityCritical,
		Message:  "Install script uses eval() for dynamic code execution: %s",
		CWE:      "CWE-506",
	},
	{
		// Base64 decode piped to eval or exec
		Pattern:  regexp.MustCompile(`(?i)base64\s+(-d|--decode)\s*\|?\s*(bash|sh|eval|exec)`),
		Rule:     "mcp-install-hook-base64-exec",
		Severity: SeverityCritical,
		Message:  "Install script decodes base64 and executes result: %s",
		CWE:      "CWE-506",
	},
	{
		// node -e "..." inline code execution
		Pattern:  regexp.MustCompile(`node\s+-e\s+["'\x60]`),
		Rule:     "mcp-install-hook-node-inline",
		Severity: SeverityCritical,
		Message:  "Install script uses node -e for inline code execution: %s",
		CWE:      "CWE-506",
	},
	{
		// python -c "..." inline code execution
		Pattern:  regexp.MustCompile(`python[23]?\s+-c\s+["'\x60]`),
		Rule:     "mcp-install-hook-python-inline",
		Severity: SeverityCritical,
		Message:  "Install script uses python -c for inline code execution: %s",
		CWE:      "CWE-506",
	},
	{
		// sh -c "..." shell command execution
		Pattern:  regexp.MustCompile(`\bsh\s+-c\s+["'\x60]`),
		Rule:     "mcp-install-hook-sh-inline",
		Severity: SeverityCritical,
		Message:  "Install script uses sh -c for inline shell execution: %s",
		CWE:      "CWE-506",
	},
	{
		// child_process.exec in referenced JS/TS files
		Pattern:  regexp.MustCompile(`child_process\.(exec|execSync)\s*\(`),
		Rule:     "mcp-install-hook-child-process-exec",
		Severity: SeverityCritical,
		Message:  "Install script file uses child_process.exec (arbitrary command execution): %s",
		CWE:      "CWE-506",
	},
	{
		// Binary download to a path then chmod+x or direct execution
		Pattern:  regexp.MustCompile(`(?i)(curl|wget)\s+.*-[oO]\s+\S+.*&&.*(chmod|exec|\.\/)`),
		Rule:     "mcp-install-hook-binary-download",
		Severity: SeverityCritical,
		Message:  "Install script downloads and executes a binary: %s",
		CWE:      "CWE-506",
	},

	// ── HIGH: Suspicious but possibly legitimate ──────────────────────────────

	{
		Pattern:  regexp.MustCompile(`(?i)(curl|wget)\s+https?://`),
		Rule:     "mcp-install-hook-outbound-download",
		Severity: SeverityHigh,
		Message:  "Install script fetches external URL (data exfiltration or supply-chain risk): %s",
		CWE:      "CWE-506",
	},
	{
		Pattern:  regexp.MustCompile(`(?i)(process\.env\.|getenv\().*?(curl|wget|fetch|http\.get|axios)`),
		Rule:     "mcp-install-hook-env-exfil",
		Severity: SeverityHigh,
		Message:  "Install script reads environment variable and makes network call (possible exfiltration): %s",
		CWE:      "CWE-506",
	},
	{
		Pattern:  regexp.MustCompile(`(?i)(readFile|readFileSync|open)\s*\(\s*['"\x60]?(~\/\.(ssh|aws|gnupg|kube|docker)|\.env)[^)]*\)`),
		Rule:     "mcp-install-hook-sensitive-file-read",
		Severity: SeverityHigh,
		Message:  "Install script file reads sensitive credential path: %s",
		CWE:      "CWE-506",
	},

	// ── WARNING: Worth reviewing ──────────────────────────────────────────────

	{
		Pattern:  regexp.MustCompile(`(?i)(fetch|http\.get|http\.request|https\.get|https\.request|axios|requests\.get|requests\.post)\s*\(`),
		Rule:     "mcp-install-hook-network-call",
		Severity: SeverityWarning,
		Message:  "Install script makes network request (packages should not phone home during install): %s",
		CWE:      "CWE-506",
	},
	{
		Pattern:  regexp.MustCompile(`(?i)(writeFile|writeFileSync|fs\.write)\s*\(\s*['"\x60]\/`),
		Rule:     "mcp-install-hook-fs-write-absolute",
		Severity: SeverityWarning,
		Message:  "Install script writes to absolute filesystem path outside package directory: %s",
		CWE:      "CWE-506",
	},
	{
		Pattern:  regexp.MustCompile(`process\.env\.[A-Z_][A-Z0-9_]*`),
		Rule:     "mcp-install-hook-env-access",
		Severity: SeverityWarning,
		Message:  "Install script accesses environment variables (verify no sensitive data is read): %s",
		CWE:      "CWE-506",
	},
}

// PyPIPatterns detect malicious Python package install hook patterns.
var PyPIPatterns = []HookPattern{
	{
		Pattern:  regexp.MustCompile(`cmdclass\s*=\s*\{[^}]*['"]install['"]\s*:`),
		Rule:     "mcp-install-hook-pypi-cmdclass",
		Severity: SeverityHigh,
		Message:  "setup.py overrides install command via cmdclass (code runs during pip install): %s",
		CWE:      "CWE-506",
	},
	{
		Pattern:  regexp.MustCompile(`\[tool\.setuptools\.cmdclass\]`),
		Rule:     "mcp-install-hook-pypi-cmdclass",
		Severity: SeverityHigh,
		Message:  "pyproject.toml defines setuptools cmdclass override (code runs during pip install): %s",
		CWE:      "CWE-506",
	},
}
