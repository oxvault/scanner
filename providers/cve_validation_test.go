package providers

// CVE Validation Suite — proves the scanner catches real MCP vulnerabilities.
//
// Each test case loads a minimum-viable vulnerable file from testdata/cve/ and
// asserts that the SAST analyzer or dependency auditor produces at least one
// finding with the expected rule ID.  If a CVE is NOT caught the test fails
// with a precise message so the gap can be closed immediately.
//
// Run:
//
//	go test ./providers/ -run TestCVEValidation -v -count=1

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// cveTestCase describes a single CVE that the scanner must detect.
type cveTestCase struct {
	// CVE identifier shown in test output.
	name string
	// Path to the vulnerable source or config file under testdata/cve/.
	file string
	// Language to pass to AnalyzeFile; LangUnknown means skip SAST.
	lang Language
	// expectedSAST lists rule IDs that must appear in SAST findings.
	expectedSAST []string
	// depPackageJSON is an optional package.json path (relative to testdata/cve/)
	// whose directory will be audited by DepAuditor.
	depPackageJSON string
	// expectedDep lists rule IDs that must appear in dep audit findings.
	expectedDep []string
}

// cveTestDataDir returns the absolute path to testdata/cve/ relative to this
// source file, so the tests work regardless of working directory.
func cveTestDataDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// file is .../providers/cve_validation_test.go
	// testdata is one level up: .../testdata/cve/
	return filepath.Join(filepath.Dir(file), "..", "testdata", "cve")
}

func TestCVEValidation(t *testing.T) {
	tdDir := cveTestDataDir(t)

	tests := []cveTestCase{
		// ── CVE-2025-6514 ── mcp-remote OS command injection ──────────────────
		{
			name:           "CVE-2025-6514 mcp-remote command injection",
			file:           "CVE-2025-6514.js",
			lang:           LangJavaScript,
			expectedSAST:   []string{"mcp-cmd-injection"},
			depPackageJSON: "package_6514.json",
			expectedDep:    []string{"dep-audit-vulnerable"},
		},

		// ── CVE-2025-49596 ── MCP Inspector unauthenticated RCE ──────────────
		{
			name:           "CVE-2025-49596 MCP Inspector unauthenticated RCE",
			file:           "CVE-2025-49596.js",
			lang:           LangJavaScript,
			expectedSAST:   []string{"mcp-cmd-injection"},
			depPackageJSON: "package_49596.json",
			expectedDep:    []string{"dep-audit-vulnerable"},
		},

		// ── CVE-2025-53967 ── Figma MCP command injection ─────────────────────
		{
			name:         "CVE-2025-53967 Figma MCP command injection",
			file:         "CVE-2025-53967.js",
			lang:         LangJavaScript,
			expectedSAST: []string{"mcp-cmd-injection"},
		},

		// ── CVE-2025-53355 ── K8s MCP execSync injection ──────────────────────
		{
			name:         "CVE-2025-53355 K8s MCP execSync injection",
			file:         "CVE-2025-53355.js",
			lang:         LangJavaScript,
			expectedSAST: []string{"mcp-cmd-injection"},
		},

		// ── CVE-2025-53372 ── code-sandbox-mcp sandbox escape ─────────────────
		{
			name:         "CVE-2025-53372 code-sandbox-mcp sandbox escape",
			file:         "CVE-2025-53372.js",
			lang:         LangJavaScript,
			expectedSAST: []string{"mcp-cmd-injection"},
		},

		// ── CVE-2025-53818 ── github-kanban-mcp exec injection ────────────────
		{
			name:         "CVE-2025-53818 github-kanban-mcp exec injection",
			file:         "CVE-2025-53818.js",
			lang:         LangJavaScript,
			expectedSAST: []string{"mcp-cmd-injection"},
		},

		// ── CVE-2025-53110 ── filesystem MCP path traversal ───────────────────
		{
			name:         "CVE-2025-53110 filesystem MCP startsWith path traversal",
			file:         "CVE-2025-53110.js",
			lang:         LangJavaScript,
			expectedSAST: []string{"mcp-path-containment-bypass"},
		},

		// ── CVE-2025-53109 ── filesystem MCP symlink escape ───────────────────
		{
			name:         "CVE-2025-53109 filesystem MCP symlink escape",
			file:         "CVE-2025-53109.js",
			lang:         LangJavaScript,
			expectedSAST: []string{"mcp-path-containment-bypass"},
		},

		// ── CVE-2025-65513 ── mcp-fetch-server SSRF ───────────────────────────
		{
			name:         "CVE-2025-65513 mcp-fetch-server broken SSRF check",
			file:         "CVE-2025-65513.ts",
			lang:         LangTypeScript,
			expectedSAST: []string{"mcp-ssrf-broken-check"},
		},

		// ── CVE-2025-68145 ── mcp-server-git path validation + arg injection ──
		{
			name:         "CVE-2025-68145 mcp-server-git path validation bypass",
			file:         "CVE-2025-68145.py",
			lang:         LangPython,
			expectedSAST: []string{"mcp-cmd-injection"},
		},

		// ── CVE-2025-54994 ── create-mcp-server-stdio command injection ────────
		{
			name:         "CVE-2025-54994 create-mcp-server-stdio command injection",
			file:         "CVE-2025-54994.js",
			lang:         LangJavaScript,
			expectedSAST: []string{"mcp-cmd-injection"},
		},

		// ── CVE-2025-54136 ── Cursor IDE MCP config RCE (rug-pull) ────────────
		{
			name:         "CVE-2025-54136 Cursor MCP config PowerShell RCE",
			file:         "CVE-2025-54136.json",
			lang:         LangJSON,
			expectedSAST: []string{"mcp-config-rce"},
		},
	}

	sast := NewSASTAnalyzer()
	depAuditor := NewDepAuditor()

	detected := 0
	total := len(tests)

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			filePath := filepath.Join(tdDir, tt.file)

			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				t.Fatalf("testdata file not found: %s", filePath)
			}

			cveDetected := true

			// ── SAST analysis ──────────────────────────────────────────────────
			if tt.lang != LangUnknown && len(tt.expectedSAST) > 0 {
				findings := sast.AnalyzeFile(filePath, tt.lang)

				for _, wantRule := range tt.expectedSAST {
					found := false
					for _, f := range findings {
						if f.Rule == wantRule {
							found = true
							break
						}
					}
					if !found {
						cveDetected = false
						presentRules := collectRules(findings)
						t.Errorf(
							"SAST MISS: expected rule %q for %s\n  file: %s\n  findings present: %s",
							wantRule, tt.name, filePath, presentRules,
						)
					}
				}
			}

			// ── Dependency audit ───────────────────────────────────────────────
			if tt.depPackageJSON != "" && len(tt.expectedDep) > 0 {
				pkgJSONPath := filepath.Join(tdDir, tt.depPackageJSON)
				depDir := filepath.Dir(pkgJSONPath)

				// Write a temp copy named package.json so AuditDirectory picks it up.
				tmpDir := t.TempDir()
				data, err := os.ReadFile(pkgJSONPath)
				if err != nil {
					t.Fatalf("read dep package.json: %v", err)
				}
				tmpPkg := filepath.Join(tmpDir, "package.json")
				if err := os.WriteFile(tmpPkg, data, 0o644); err != nil {
					t.Fatalf("write tmp package.json: %v", err)
				}
				_ = depDir

				depFindings := depAuditor.AuditDirectory(tmpDir)

				for _, wantRule := range tt.expectedDep {
					found := false
					for _, f := range depFindings {
						if f.Rule == wantRule {
							found = true
							break
						}
					}
					if !found {
						cveDetected = false
						presentRules := collectRules(depFindings)
						t.Errorf(
							"DEP MISS: expected rule %q for %s\n  package.json: %s\n  findings present: %s",
							wantRule, tt.name, pkgJSONPath, presentRules,
						)
					}
				}
			}

			if cveDetected {
				detected++
			}
		})
	}

	// Print detection rate summary.  This always runs even when sub-tests fail.
	t.Logf("\n%s\nCVE Detection Rate: %d/%d (%.0f%%)\n%s",
		strings.Repeat("─", 50),
		detected, total,
		float64(detected)/float64(total)*100,
		strings.Repeat("─", 50),
	)
	if detected < total {
		missing := total - detected
		t.Logf("WARNING: %d CVE(s) NOT detected — see FAIL lines above", missing)
	}
}

// collectRules returns a formatted string of rule IDs from findings.
func collectRules(findings []Finding) string {
	if len(findings) == 0 {
		return "(none)"
	}
	seen := make(map[string]struct{}, len(findings))
	var rules []string
	for _, f := range findings {
		if _, ok := seen[f.Rule]; !ok {
			seen[f.Rule] = struct{}{}
			rules = append(rules, fmt.Sprintf("%q", f.Rule))
		}
	}
	return strings.Join(rules, ", ")
}
