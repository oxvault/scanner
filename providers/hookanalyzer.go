package providers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// hookPattern represents a single malicious pattern to match in install scripts.
type hookPattern struct {
	pattern  *regexp.Regexp
	rule     string
	severity Severity
	message  string
}

// hookInstallScripts is the set of package.json script keys that run during install.
var hookInstallScripts = []string{
	"preinstall",
	"install",
	"postinstall",
	"prepare",
}

// hookPatterns are ordered from most to least severe.
var hookPatterns = []hookPattern{
	// ── CRITICAL: Direct execution threats ──────────────────────────────────

	{
		// curl ... | sh / curl ... | bash / curl ... | /bin/sh
		pattern:  regexp.MustCompile(`(?i)(curl|wget)\s+[^\|]+\|\s*(bash|sh|/bin/sh|/bin/bash)`),
		rule:     "mcp-install-hook-pipe-to-shell",
		severity: SeverityCritical,
		message:  "Install script pipes remote download to shell: %s",
	},
	{
		// eval(...) with dynamic content
		pattern:  regexp.MustCompile(`\beval\s*\(`),
		rule:     "mcp-install-hook-eval",
		severity: SeverityCritical,
		message:  "Install script uses eval() for dynamic code execution: %s",
	},
	{
		// Base64 decode piped to eval or exec: echo ... | base64 -d | sh
		pattern:  regexp.MustCompile(`(?i)base64\s+(-d|--decode)\s*\|?\s*(bash|sh|eval|exec)`),
		rule:     "mcp-install-hook-base64-exec",
		severity: SeverityCritical,
		message:  "Install script decodes base64 and executes result: %s",
	},
	{
		// node -e "..." inline code execution in shell script value
		pattern:  regexp.MustCompile(`node\s+-e\s+["'\x60]`),
		rule:     "mcp-install-hook-node-inline",
		severity: SeverityCritical,
		message:  "Install script uses node -e for inline code execution: %s",
	},
	{
		// python -c "..." inline code execution
		pattern:  regexp.MustCompile(`python[23]?\s+-c\s+["'\x60]`),
		rule:     "mcp-install-hook-python-inline",
		severity: SeverityCritical,
		message:  "Install script uses python -c for inline code execution: %s",
	},
	{
		// sh -c "..." shell command execution
		pattern:  regexp.MustCompile(`\bsh\s+-c\s+["'\x60]`),
		rule:     "mcp-install-hook-sh-inline",
		severity: SeverityCritical,
		message:  "Install script uses sh -c for inline shell execution: %s",
	},
	{
		// child_process.exec in referenced JS/TS files
		pattern:  regexp.MustCompile(`child_process\.(exec|execSync)\s*\(`),
		rule:     "mcp-install-hook-child-process-exec",
		severity: SeverityCritical,
		message:  "Install script file uses child_process.exec (arbitrary command execution): %s",
	},
	{
		// Binary download to a path then chmod+x or direct execution
		pattern:  regexp.MustCompile(`(?i)(curl|wget)\s+.*-[oO]\s+\S+.*&&.*(chmod|exec|\.\/)`),
		rule:     "mcp-install-hook-binary-download",
		severity: SeverityCritical,
		message:  "Install script downloads and executes a binary: %s",
	},

	// ── HIGH: Suspicious but possibly legitimate ──────────────────────────────

	{
		// curl/wget to any external URL (data exfiltration / supply chain risk)
		pattern:  regexp.MustCompile(`(?i)(curl|wget)\s+https?://`),
		rule:     "mcp-install-hook-outbound-download",
		severity: SeverityHigh,
		message:  "Install script fetches external URL (data exfiltration or supply-chain risk): %s",
	},
	{
		// Environment variable access combined with a network call on the same line
		pattern:  regexp.MustCompile(`(?i)(process\.env\.|getenv\().*?(curl|wget|fetch|http\.get|axios)`),
		rule:     "mcp-install-hook-env-exfil",
		severity: SeverityHigh,
		message:  "Install script reads environment variable and makes network call (possible exfiltration): %s",
	},
	{
		// fs.readFile on sensitive credential paths in referenced scripts
		pattern:  regexp.MustCompile(`(?i)(readFile|readFileSync|open)\s*\(\s*['"\x60]?(~\/\.(ssh|aws|gnupg|kube|docker)|\.env)[^)]*\)`),
		rule:     "mcp-install-hook-sensitive-file-read",
		severity: SeverityHigh,
		message:  "Install script file reads sensitive credential path: %s",
	},

	// ── WARNING: Worth reviewing ──────────────────────────────────────────────

	{
		// Any network call in install scripts (npm packages should not phone home)
		pattern:  regexp.MustCompile(`(?i)(fetch|http\.get|http\.request|https\.get|https\.request|axios|requests\.get|requests\.post)\s*\(`),
		rule:     "mcp-install-hook-network-call",
		severity: SeverityWarning,
		message:  "Install script makes network request (packages should not phone home during install): %s",
	},
	{
		// File system writes outside package directory (writes to absolute paths)
		pattern:  regexp.MustCompile(`(?i)(writeFile|writeFileSync|fs\.write)\s*\(\s*['"\x60]\/`),
		rule:     "mcp-install-hook-fs-write-absolute",
		severity: SeverityWarning,
		message:  "Install script writes to absolute filesystem path outside package directory: %s",
	},
	{
		// process.env access in install scripts
		pattern:  regexp.MustCompile(`process\.env\.[A-Z_][A-Z0-9_]*`),
		rule:     "mcp-install-hook-env-access",
		severity: SeverityWarning,
		message:  "Install script accesses environment variables (verify no sensitive data is read): %s",
	},
}

// pypiPatterns detect malicious Python package install hook patterns.
var pypiPatterns = []hookPattern{
	{
		// setup.py with custom cmdclass that overrides install
		pattern:  regexp.MustCompile(`cmdclass\s*=\s*\{[^}]*['"]install['"]\s*:`),
		rule:     "mcp-install-hook-pypi-cmdclass",
		severity: SeverityHigh,
		message:  "setup.py overrides install command via cmdclass (code runs during pip install): %s",
	},
	{
		// pyproject.toml cmdclass override
		pattern:  regexp.MustCompile(`\[tool\.setuptools\.cmdclass\]`),
		rule:     "mcp-install-hook-pypi-cmdclass",
		severity: SeverityHigh,
		message:  "pyproject.toml defines setuptools cmdclass override (code runs during pip install): %s",
	},
}

type hookAnalyzer struct{}

// NewHookAnalyzer creates a new HookAnalyzer.
func NewHookAnalyzer() HookAnalyzer {
	return &hookAnalyzer{}
}

func (h *hookAnalyzer) AnalyzeDirectory(dir string) []Finding {
	var findings []Finding

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if filepath.Base(path) == "node_modules" || filepath.Base(path) == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		base := filepath.Base(path)
		switch base {
		case "package.json":
			findings = append(findings, h.analyzePackageJSON(path)...)
		case "setup.py":
			findings = append(findings, h.analyzePythonSetup(path, pypiPatterns)...)
		case "pyproject.toml":
			findings = append(findings, h.analyzePyproject(path)...)
		}

		return nil
	})

	return findings
}

// analyzePackageJSON parses a package.json, extracts install hooks, and scans them.
func (h *hookAnalyzer) analyzePackageJSON(path string) []Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		// Malformed JSON — emit a warning finding.
		return []Finding{
			{
				Rule:     "mcp-install-hook-malformed-json",
				Severity: SeverityWarning,
				Message:  fmt.Sprintf("package.json could not be parsed (malformed JSON): %s", path),
				File:     path,
			},
		}
	}

	if len(pkg.Scripts) == 0 {
		return nil
	}

	var findings []Finding
	pkgDir := filepath.Dir(path)

	for _, hook := range hookInstallScripts {
		script, ok := pkg.Scripts[hook]
		if !ok || strings.TrimSpace(script) == "" {
			continue
		}

		// Scan the inline script value itself.
		scriptFindings := scanScriptContent(script, path, hook)
		findings = append(findings, scriptFindings...)

		// If the script references a local file, scan that file too.
		if referencedPath, ok := extractReferencedFile(script, pkgDir); ok {
			fileFindings := scanReferencedFile(referencedPath, hook)
			findings = append(findings, fileFindings...)
		}
	}

	return findings
}

// scanScriptContent scans a single script string value for malicious patterns.
func scanScriptContent(script, pkgFile, hookName string) []Finding {
	var findings []Finding
	for _, hp := range hookPatterns {
		if hp.pattern.MatchString(script) {
			trimmed := script
			if len(trimmed) > 120 {
				trimmed = trimmed[:120] + "..."
			}
			findings = append(findings, Finding{
				Rule:     hp.rule,
				Severity: hp.severity,
				Message:  fmt.Sprintf(hp.message, trimmed),
				File:     pkgFile,
				// Line is not available from JSON value; omit.
			})
		}
	}
	return findings
}

// extractReferencedFile checks whether a script string references a local file and returns its path.
// Examples: "node scripts/setup.js", "node ./install.js arg1", "python scripts/install.py"
func extractReferencedFile(script, pkgDir string) (string, bool) {
	// Match: (node|python3?|ts-node)\s+(<path>)
	refPattern := regexp.MustCompile(`(?i)(?:node|python[23]?|ts-node)\s+(\.{0,2}[/\w.-]+\.(js|mjs|cjs|ts|py))`)
	m := refPattern.FindStringSubmatch(script)
	if m == nil {
		return "", false
	}
	rel := m[1]
	full := filepath.Join(pkgDir, rel)
	if _, err := os.Stat(full); err != nil {
		return "", false
	}
	return full, true
}

// scanReferencedFile reads a script file and scans each line for malicious patterns.
func scanReferencedFile(path, hookName string) []Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var findings []Finding
	lines := strings.Split(string(data), "\n")

	for lineNum, line := range lines {
		for _, hp := range hookPatterns {
			if hp.pattern.MatchString(line) {
				trimmed := strings.TrimSpace(line)
				if len(trimmed) > 120 {
					trimmed = trimmed[:120] + "..."
				}
				findings = append(findings, Finding{
					Rule:     hp.rule,
					Severity: hp.severity,
					Message:  fmt.Sprintf(hp.message, trimmed),
					File:     path,
					Line:     lineNum + 1,
				})
			}
		}
	}

	return findings
}

// analyzePythonSetup scans a setup.py file for malicious install hook patterns.
func (h *hookAnalyzer) analyzePythonSetup(path string, patterns []hookPattern) []Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var findings []Finding
	lines := strings.Split(string(data), "\n")

	for lineNum, line := range lines {
		for _, hp := range patterns {
			if hp.pattern.MatchString(line) {
				trimmed := strings.TrimSpace(line)
				if len(trimmed) > 120 {
					trimmed = trimmed[:120] + "..."
				}
				findings = append(findings, Finding{
					Rule:     hp.rule,
					Severity: hp.severity,
					Message:  fmt.Sprintf(hp.message, trimmed),
					File:     path,
					Line:     lineNum + 1,
				})
			}
		}
	}

	return findings
}

// analyzePyproject scans a pyproject.toml for cmdclass overrides.
func (h *hookAnalyzer) analyzePyproject(path string) []Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var findings []Finding
	lines := strings.Split(string(data), "\n")

	for lineNum, line := range lines {
		for _, hp := range pypiPatterns {
			if hp.pattern.MatchString(line) {
				trimmed := strings.TrimSpace(line)
				if len(trimmed) > 120 {
					trimmed = trimmed[:120] + "..."
				}
				findings = append(findings, Finding{
					Rule:     hp.rule,
					Severity: hp.severity,
					Message:  fmt.Sprintf(hp.message, trimmed),
					File:     path,
					Line:     lineNum + 1,
				})
			}
		}
	}

	return findings
}
