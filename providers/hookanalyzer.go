package providers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/oxvault/scanner/patterns"
)

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
			findings = append(findings, h.analyzePythonSetup(path, patterns.PyPIPatterns)...)
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

	for _, hook := range patterns.HookInstallScripts {
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
	for _, hp := range patterns.HookPatterns {
		if hp.Pattern.MatchString(script) {
			trimmed := script
			if len(trimmed) > 120 {
				trimmed = trimmed[:120] + "..."
			}
			findings = append(findings, Finding{
				Rule:     hp.Rule,
				Severity: hp.Severity,
				Message:  fmt.Sprintf(hp.Message, trimmed),
				File:     pkgFile,
				CWE:      hp.CWE,
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
		for _, hp := range patterns.HookPatterns {
			if hp.Pattern.MatchString(line) {
				trimmed := strings.TrimSpace(line)
				if len(trimmed) > 120 {
					trimmed = trimmed[:120] + "..."
				}
				findings = append(findings, Finding{
					Rule:     hp.Rule,
					Severity: hp.Severity,
					Message:  fmt.Sprintf(hp.Message, trimmed),
					File:     path,
					Line:     lineNum + 1,
					CWE:      hp.CWE,
				})
			}
		}
	}

	return findings
}

// analyzePythonSetup scans a setup.py file for malicious install hook patterns.
func (h *hookAnalyzer) analyzePythonSetup(path string, hpats []patterns.HookPattern) []Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var findings []Finding
	lines := strings.Split(string(data), "\n")

	for lineNum, line := range lines {
		for _, hp := range hpats {
			if hp.Pattern.MatchString(line) {
				trimmed := strings.TrimSpace(line)
				if len(trimmed) > 120 {
					trimmed = trimmed[:120] + "..."
				}
				findings = append(findings, Finding{
					Rule:     hp.Rule,
					Severity: hp.Severity,
					Message:  fmt.Sprintf(hp.Message, trimmed),
					File:     path,
					Line:     lineNum + 1,
					CWE:      hp.CWE,
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
		for _, hp := range patterns.PyPIPatterns {
			if hp.Pattern.MatchString(line) {
				trimmed := strings.TrimSpace(line)
				if len(trimmed) > 120 {
					trimmed = trimmed[:120] + "..."
				}
				findings = append(findings, Finding{
					Rule:     hp.Rule,
					Severity: hp.Severity,
					Message:  fmt.Sprintf(hp.Message, trimmed),
					File:     path,
					Line:     lineNum + 1,
					CWE:      hp.CWE,
				})
			}
		}
	}

	return findings
}
