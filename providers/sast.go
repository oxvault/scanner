package providers

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/oxvault/scanner/patterns"
)

type sastAnalyzer struct{}

func NewSASTAnalyzer() SASTAnalyzer {
	return &sastAnalyzer{}
}

// ── Fix 1: Placeholder secret exclusion ────────────���─────────────────────────

// isPlaceholderSecret returns true when value looks like a documentation
// placeholder rather than a real credential.
func isPlaceholderSecret(value string) bool {
	for _, re := range patterns.PlaceholderPatterns {
		if re.MatchString(value) {
			return true
		}
	}
	// Detect PascalCase type-name placeholders like "GlobalContinuationToken",
	// "SomeTypeName", "AccessTokenType" — values that are clearly Go/Python/TS
	// type names used as a placeholder rather than an actual secret string.
	// Require: at least 2 consecutive uppercase-lowercase transitions and no
	// hyphens/underscores (real tokens use those as separators, type names don't).
	if isPascalCaseTypeName(value) {
		return true
	}
	return false
}

// pascalCaseTypeNameRe detects multi-word PascalCase identifiers that look
// like type names (e.g. GlobalContinuationToken, AccessTokenType).
// Requirements: starts with uppercase, has at least two uppercase-then-lowercase
// transitions, contains only letters, and is at least 8 chars long.
var pascalCaseTypeNameRe = regexp.MustCompile(`^[A-Z][a-z]+(?:[A-Z][a-z]+){1,}$`)

func isPascalCaseTypeName(value string) bool {
	return pascalCaseTypeNameRe.MatchString(value)
}

// ── Fix 2: Constant self-assignment exclusion ─────────���───────────────────────

// keyValueRe matches key-value assignments like `SOME_NAME = "value"`.
var keyValueRe = regexp.MustCompile(`(?i)([A-Z0-9_]+)\s*[:=]+\s*["']([^"']+)["']`)

// extractKeyValue attempts to extract the key and quoted value from a line
// like `SOME_NAME = 'SOME_NAME'` or `api_key = "api_key"`.
// Returns ("", "") when the pattern cannot be identified.
func extractKeyValue(line string) (key, value string) {
	// Match: <identifier> <op> <quote><value><quote>
	m := keyValueRe.FindStringSubmatch(line)
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

// ── Fix 3: Comment line detection ───────────────────────────────────────────��

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
	if strings.HasPrefix(t, "#") && patterns.CommentOnlyLanguages[lang] {
		return true
	}
	return false
}

// ── Fix 7: Temp-dir path detection ────────────────��──────────────────────────

// isTempDirOperation returns true when the line's argument clearly references
// a temporary directory.
func isTempDirOperation(line string) bool {
	for _, re := range patterns.TempDirPatterns {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

// toSet converts a string slice into a set (map[string]bool) for O(1) lookups.
func toSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, item := range items {
		m[item] = true
	}
	return m
}

var testDirSet = toSet(patterns.TestDirs)
var excludedDirSet = toSet(patterns.ExcludedDirs)

// isTestDir returns true when the directory name is a well-known test directory
// that should be skipped during analysis.
func isTestDir(name string) bool {
	return testDirSet[name]
}

// isExcludedDir returns true when the directory should be entirely skipped
// during SAST analysis.  It covers:
//   - dependency directories: node_modules (npm), vendor (Go)
//   - build / toolchain directories: .smithery (Smithery bundler output)
//   - VCS / cache directories: .git, __pycache__, .venv
//   - test directories (delegates to isTestDir)
func isExcludedDir(name string) bool {
	if excludedDirSet[name] {
		return true
	}
	return isTestDir(name)
}

// isExcludedFile returns true when the file should be skipped during SAST
// analysis regardless of its directory.  It covers:
//   - TypeScript declaration files (*.d.ts) — type metadata, never executed
//   - Minified JS files (*.min.js, *.min.mjs, *.min.cjs)
//   - Bundled JS files (*.bundle.js, bundle.js)
//   - Test files (delegates to isTestFile)
func isExcludedFile(name string) bool {
	lower := strings.ToLower(name)

	// TypeScript declaration files
	if strings.HasSuffix(lower, ".d.ts") || strings.HasSuffix(lower, ".d.mts") {
		return true
	}

	// CommonJS bundle files (.cjs) — transpiled output, not hand-written source
	if strings.HasSuffix(lower, ".cjs") {
		return true
	}

	// Minified files
	if strings.HasSuffix(lower, ".min.js") ||
		strings.HasSuffix(lower, ".min.mjs") ||
		strings.HasSuffix(lower, ".min.cjs") {
		return true
	}

	// Bundled files
	if strings.HasSuffix(lower, ".bundle.js") ||
		strings.HasSuffix(lower, ".bundle.mjs") {
		return true
	}

	// Plain bundle.js (common Webpack/esbuild output name)
	if lower == "bundle.js" || lower == "bundle.mjs" {
		return true
	}

	// Files with "bundle" in the name (e.g. lighthouse-devtools-mcp-bundle.js)
	if strings.Contains(lower, "-bundle.") || strings.Contains(lower, "_bundle.") {
		return true
	}

	return isTestFile(name)
}

// isTestFile returns true when the file name matches common test file conventions.
func isTestFile(name string) bool {
	// Go test files
	if strings.HasSuffix(name, "_test.go") {
		return true
	}
	// JavaScript / TypeScript test / spec / mock files
	if strings.HasSuffix(name, ".test.js") || strings.HasSuffix(name, ".test.ts") ||
		strings.HasSuffix(name, ".spec.js") || strings.HasSuffix(name, ".spec.ts") ||
		strings.HasSuffix(name, ".test.mjs") || strings.HasSuffix(name, ".spec.mjs") {
		return true
	}
	// Files with "mock" in the name (e.g. start-mock-stdio.ts, mock-server.ts)
	lower := strings.ToLower(name)
	if strings.Contains(lower, "mock") || strings.Contains(lower, "-mock") ||
		strings.HasPrefix(lower, "mock-") || strings.HasPrefix(lower, "mock_") {
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

	// Skip bundled/transpiled files: if any of the first 20 lines exceeds
	// 1000 characters, this is generated output (webpack, esbuild, rollup),
	// not hand-written source code.
	if lang == LangJavaScript || lang == LangTypeScript {
		limit := 20
		if len(lines) < limit {
			limit = len(lines)
		}
		for i := 0; i < limit; i++ {
			if len(lines[i]) > 1000 {
				return nil
			}
		}
	}

	for _, sp := range patterns.SourcePatterns {
		if !languageMatch(sp.Langs, lang) {
			continue
		}

		for lineNum, line := range lines {
			// Fix 3: skip comment lines — no rules fire on commented-out code.
			if isCommentLine(line, lang) {
				continue
			}

			matches := sp.Pattern.FindStringSubmatch(line)
			if len(matches) == 0 {
				continue
			}

			// Fix 5: skip when any exclusion pattern matches the line.
			excluded := false
			for _, excl := range sp.ExcludePatterns {
				if excl.MatchString(line) {
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}

			// Fix 1 & 2: for secret rules, suppress placeholder/self-assigned values.
			if sp.IsSecretRule {
				// Use the full regex match for broad placeholder checks (e.g. "example",
				// "mock", "your_").
				matchedValue := matches[0]
				if isPlaceholderSecret(matchedValue) {
					continue
				}
				if isSelfAssignedSecret(line) {
					continue
				}
				// Also extract the quoted value alone and check whether it is a
				// placeholder or PascalCase type name (e.g. GlobalContinuationToken,
				// PENDING_COGNITO_TOKEN) — these are clearly identifiers or
				// placeholder values, not real secret values.
				_, quotedValue := extractKeyValue(line)
				if quotedValue != "" {
					if isPlaceholderSecret(quotedValue) {
						continue
					}
					if isPascalCaseTypeName(quotedValue) {
						continue
					}
				}
			}

			matched := strings.TrimSpace(line)
			if len(matched) > 100 {
				matched = matched[:100] + "..."
			}

			// Fix 7: downgrade destructive-fs severity to INFO when the target
			// is clearly a temporary directory.
			severity := sp.Severity
			if sp.Rule == "mcp-destructive-fs" && isTempDirOperation(line) {
				severity = SeverityInfo
			}

			// Apply confidence: default to Medium when not explicitly set.
			confidence := sp.Confidence
			if confidence == 0 {
				confidence = ConfidenceMedium
			}

			findings = append(findings, Finding{
				Rule:            sp.Rule,
				Severity:        severity,
				Confidence:      confidence,
				ConfidenceLabel: confidence.String(),
				Message:         fmt.Sprintf(sp.Message, matched),
				File:            path,
				Line:            lineNum + 1,
				CWE:             sp.CWE,
			})
		}
	}

	return findings
}

// walkSourceFiles walks dir, skipping excluded directories and files, and calls
// fn for each source file with a recognised language. This eliminates the
// duplicated filepath.Walk boilerplate in AnalyzeDirectory and DetectEgress.
func walkSourceFiles(dir string, fn func(path string, lang Language)) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if isExcludedDir(filepath.Base(path)) {
				return filepath.SkipDir
			}
			return nil
		}

		if isExcludedFile(filepath.Base(path)) {
			return nil
		}

		lang := detectLanguage(path)
		if lang == LangUnknown {
			return nil
		}

		fn(path, lang)
		return nil
	})
}

func (s *sastAnalyzer) AnalyzeDirectory(dir string) []Finding {
	var findings []Finding

	_ = walkSourceFiles(dir, func(path string, lang Language) {
		fileFindings := s.AnalyzeFile(path, lang)
		findings = append(findings, fileFindings...)
	})

	return findings
}

func (s *sastAnalyzer) DetectEgress(dir string) []EgressFinding {
	var findings []EgressFinding

	_ = walkSourceFiles(dir, func(path string, lang Language) {
		file, err := os.Open(path)
		if err != nil {
			return
		}
		defer func() { _ = file.Close() }()

		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			for _, ep := range patterns.EgressPatterns {
				if !languageMatch(ep.Langs, lang) {
					continue
				}
				matches := ep.Pattern.FindStringSubmatch(line)
				if len(matches) > 0 {
					method := ep.Method
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

var mcpConfigSet = toSet(patterns.MCPConfigNames)

// isMCPConfigFile returns true for JSON filenames commonly used as MCP server
// configuration, where malicious command injection (rug-pull) is a known risk.
func isMCPConfigFile(base string) bool {
	return mcpConfigSet[base]
}

func languageMatch(supported []Language, lang Language) bool {
	for _, l := range supported {
		if l == lang {
			return true
		}
	}
	return false
}
