package providers

import (
	"os"
	"path/filepath"
	"testing"
)

// ── helpers ────────────────────────────────────────────────────────────────────

func newSuppressor(t *testing.T) *suppressor {
	t.Helper()
	return &suppressor{}
}

// writeIgnoreFile creates a .oxvaultignore file in dir with the given content.
func writeIgnoreFile(t *testing.T, dir, content string) {
	t.Helper()
	path := filepath.Join(dir, ".oxvaultignore")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write .oxvaultignore: %v", err)
	}
}

// makeFinding is a quick constructor for test findings.
func makeFinding(rule, file string, line int) Finding {
	return Finding{
		Rule:     rule,
		Severity: SeverityHigh,
		Message:  "test finding",
		File:     file,
		Line:     line,
	}
}

// ── lineHasIgnore unit tests ───────────────────────────────────────────────────

func TestLineHasIgnore(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		ruleName string
		want     bool
	}{
		{
			name:     "python style exact rule match",
			line:     `result = os.popen(cmd)  # oxvault:ignore mcp-cmd-injection`,
			ruleName: "mcp-cmd-injection",
			want:     true,
		},
		{
			name:     "python style no rule — suppresses all",
			line:     `result = os.popen(cmd)  # oxvault:ignore`,
			ruleName: "mcp-cmd-injection",
			want:     true,
		},
		{
			name:     "python style no rule — suppresses different rule too",
			line:     `result = os.popen(cmd)  # oxvault:ignore`,
			ruleName: "mcp-env-leakage",
			want:     true,
		},
		{
			name:     "js style exact rule match",
			line:     `exec(cmd)  // oxvault:ignore mcp-code-eval`,
			ruleName: "mcp-code-eval",
			want:     true,
		},
		{
			name:     "go style no rule — suppresses all",
			line:     `cmd := exec.Command("rm", path) // oxvault:ignore`,
			ruleName: "mcp-cmd-injection",
			want:     true,
		},
		{
			name:     "wrong rule name — does NOT suppress",
			line:     `result = os.popen(cmd)  # oxvault:ignore mcp-env-leakage`,
			ruleName: "mcp-cmd-injection",
			want:     false,
		},
		{
			name:     "no comment — does NOT suppress",
			line:     `result = os.popen(cmd)`,
			ruleName: "mcp-cmd-injection",
			want:     false,
		},
		{
			name:     "unrelated comment — does NOT suppress",
			line:     `result = os.popen(cmd)  # this is fine`,
			ruleName: "mcp-cmd-injection",
			want:     false,
		},
		{
			name:     "marker at start of line",
			line:     `# oxvault:ignore mcp-hardcoded-secret`,
			ruleName: "mcp-hardcoded-secret",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := lineHasIgnore(tt.line, tt.ruleName)
			if got != tt.want {
				t.Errorf("lineHasIgnore(%q, %q) = %v, want %v", tt.line, tt.ruleName, got, tt.want)
			}
		})
	}
}

// ── IsInlineSuppressed integration tests ──────────────────────────────────────

func TestIsInlineSuppressed(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name     string
		filename string
		content  string
		rule     string
		line     int
		want     bool
	}{
		{
			name:     "python inline ignore exact rule",
			filename: "server.py",
			content:  "import os\nresult = os.popen(cmd)  # oxvault:ignore mcp-cmd-injection\n",
			rule:     "mcp-cmd-injection",
			line:     2,
			want:     true,
		},
		{
			name:     "python inline ignore no rule",
			filename: "server2.py",
			content:  "import os\nresult = os.popen(cmd)  # oxvault:ignore\n",
			rule:     "mcp-cmd-injection",
			line:     2,
			want:     true,
		},
		{
			name:     "js inline ignore exact rule",
			filename: "server.js",
			content:  "const cp = require('child_process')\ncp.exec(cmd)  // oxvault:ignore mcp-code-eval\n",
			rule:     "mcp-code-eval",
			line:     2,
			want:     true,
		},
		{
			name:     "go inline ignore no rule",
			filename: "tool.go",
			content:  "package main\nexec.Command(\"rm\", path) // oxvault:ignore\n",
			rule:     "mcp-cmd-injection",
			line:     2,
			want:     true,
		},
		{
			name:     "wrong rule name does not suppress",
			filename: "wrong.py",
			content:  "import os\nresult = os.popen(cmd)  # oxvault:ignore mcp-env-leakage\n",
			rule:     "mcp-cmd-injection",
			line:     2,
			want:     false,
		},
		{
			name:     "no comment does not suppress",
			filename: "nocomment.py",
			content:  "import os\nresult = os.popen(cmd)\n",
			rule:     "mcp-cmd-injection",
			line:     2,
			want:     false,
		},
		{
			name:     "zero line number — no suppression",
			filename: "noline.py",
			content:  "x = 1\n",
			rule:     "mcp-cmd-injection",
			line:     0,
			want:     false,
		},
		{
			name:     "empty file path — no suppression",
			filename: "",
			content:  "",
			rule:     "mcp-cmd-injection",
			line:     1,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSuppressor(t)
			f := Finding{Rule: tt.rule, Line: tt.line}

			if tt.filename != "" {
				path := filepath.Join(dir, tt.filename)
				if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
					t.Fatalf("write file: %v", err)
				}
				f.File = path
			}

			got := s.IsInlineSuppressed(f)
			if got != tt.want {
				t.Errorf("IsInlineSuppressed() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ── LoadIgnoreFile tests ───────────────────────────────────────────────────────

func TestLoadIgnoreFile_MissingFile(t *testing.T) {
	s := newSuppressor(t)
	dir := t.TempDir()

	// No .oxvaultignore created — should return nil with no rules loaded.
	if err := s.LoadIgnoreFile(dir); err != nil {
		t.Errorf("expected no error for missing file, got %v", err)
	}
	if len(s.rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(s.rules))
	}
}

func TestLoadIgnoreFile_CommentsAndBlankLines(t *testing.T) {
	dir := t.TempDir()
	writeIgnoreFile(t, dir, `
# This is a comment

# Another comment

`)
	s := newSuppressor(t)
	if err := s.LoadIgnoreFile(dir); err != nil {
		t.Fatalf("LoadIgnoreFile: %v", err)
	}
	if len(s.rules) != 0 {
		t.Errorf("expected 0 rules from comments/blanks, got %d", len(s.rules))
	}
}

func TestLoadIgnoreFile_ParsesAllRuleTypes(t *testing.T) {
	dir := t.TempDir()
	writeIgnoreFile(t, dir, `
# glob patterns
*_test.py
tests/**

# rule suppression
!mcp-env-leakage
!mcp-network-egress

# file+rule combos
server.py:mcp-cmd-injection
legacy/*.py:mcp-hardcoded-secret
`)
	s := newSuppressor(t)
	if err := s.LoadIgnoreFile(dir); err != nil {
		t.Fatalf("LoadIgnoreFile: %v", err)
	}
	if len(s.rules) != 6 {
		t.Errorf("expected 6 rules, got %d: %+v", len(s.rules), s.rules)
	}
}

// ── Filter tests ───────────────────────────────────────────────────────────────

func TestFilter_GlobSuppressesMatchingFiles(t *testing.T) {
	dir := t.TempDir()

	// Create an actual file so inline check doesn't fail (though glob will catch it first)
	testFile := filepath.Join(dir, "server_test.py")
	if err := os.WriteFile(testFile, []byte("x = 1\n"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	writeIgnoreFile(t, dir, "*_test.py\n")
	s := newSuppressor(t)
	if err := s.LoadIgnoreFile(dir); err != nil {
		t.Fatalf("LoadIgnoreFile: %v", err)
	}

	findings := []Finding{
		makeFinding("mcp-cmd-injection", testFile, 1),
		makeFinding("mcp-env-leakage", filepath.Join(dir, "server.py"), 5),
	}

	kept, suppressed := s.Filter(findings)
	if len(kept) != 1 {
		t.Errorf("expected 1 kept finding, got %d", len(kept))
	}
	if len(suppressed) != 1 {
		t.Errorf("expected 1 suppressed finding, got %d", len(suppressed))
	}
	if len(suppressed) > 0 && suppressed[0].Rule != "mcp-cmd-injection" {
		t.Errorf("expected suppressed rule mcp-cmd-injection, got %s", suppressed[0].Rule)
	}
}

func TestFilter_DirectoryGlob(t *testing.T) {
	dir := t.TempDir()
	testsFile := filepath.Join(dir, "tests", "helpers.py")
	if err := os.MkdirAll(filepath.Dir(testsFile), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(testsFile, []byte("x = 1\n"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	writeIgnoreFile(t, dir, "tests/**\n")
	s := newSuppressor(t)
	if err := s.LoadIgnoreFile(dir); err != nil {
		t.Fatalf("LoadIgnoreFile: %v", err)
	}

	findings := []Finding{
		makeFinding("mcp-cmd-injection", testsFile, 1),
		makeFinding("mcp-env-leakage", filepath.Join(dir, "server.py"), 5),
	}

	kept, suppressed := s.Filter(findings)
	if len(kept) != 1 {
		t.Errorf("expected 1 kept, got %d", len(kept))
	}
	if len(suppressed) != 1 {
		t.Errorf("expected 1 suppressed, got %d", len(suppressed))
	}
}

func TestFilter_RuleSuppression(t *testing.T) {
	dir := t.TempDir()
	writeIgnoreFile(t, dir, "!mcp-env-leakage\n")
	s := newSuppressor(t)
	if err := s.LoadIgnoreFile(dir); err != nil {
		t.Fatalf("LoadIgnoreFile: %v", err)
	}

	findings := []Finding{
		makeFinding("mcp-env-leakage", "server.js", 10),
		makeFinding("mcp-cmd-injection", "server.js", 20),
	}

	kept, suppressed := s.Filter(findings)
	if len(kept) != 1 {
		t.Errorf("expected 1 kept, got %d", len(kept))
	}
	if len(suppressed) != 1 {
		t.Errorf("expected 1 suppressed, got %d", len(suppressed))
	}
	if len(kept) > 0 && kept[0].Rule != "mcp-cmd-injection" {
		t.Errorf("expected kept rule mcp-cmd-injection, got %s", kept[0].Rule)
	}
}

func TestFilter_FileRuleCombo(t *testing.T) {
	dir := t.TempDir()
	serverFile := filepath.Join(dir, "server.py")
	if err := os.WriteFile(serverFile, []byte("x = 1\n"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	writeIgnoreFile(t, dir, "server.py:mcp-cmd-injection\n")
	s := newSuppressor(t)
	if err := s.LoadIgnoreFile(dir); err != nil {
		t.Fatalf("LoadIgnoreFile: %v", err)
	}

	findings := []Finding{
		// Same file, matching rule — suppressed
		makeFinding("mcp-cmd-injection", serverFile, 5),
		// Same file, different rule — kept
		makeFinding("mcp-env-leakage", serverFile, 10),
		// Different file, matching rule — kept
		makeFinding("mcp-cmd-injection", filepath.Join(dir, "other.py"), 3),
	}

	kept, suppressed := s.Filter(findings)
	if len(kept) != 2 {
		t.Errorf("expected 2 kept, got %d: %+v", len(kept), kept)
	}
	if len(suppressed) != 1 {
		t.Errorf("expected 1 suppressed, got %d", len(suppressed))
	}
}

func TestFilter_Mixed(t *testing.T) {
	dir := t.TempDir()

	// File that will be glob-suppressed
	testFile := filepath.Join(dir, "foo_test.py")
	if err := os.WriteFile(testFile, []byte("x = 1\n"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// File whose second line has an inline comment
	serverFile := filepath.Join(dir, "server.py")
	if err := os.WriteFile(serverFile, []byte("import os\nresult = os.popen(cmd)  # oxvault:ignore mcp-cmd-injection\n"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	writeIgnoreFile(t, dir, "*_test.py\n")
	s := newSuppressor(t)
	if err := s.LoadIgnoreFile(dir); err != nil {
		t.Fatalf("LoadIgnoreFile: %v", err)
	}

	findings := []Finding{
		// Suppressed by glob
		makeFinding("mcp-cmd-injection", testFile, 1),
		// Suppressed by inline comment
		{Rule: "mcp-cmd-injection", Severity: SeverityHigh, Message: "test", File: serverFile, Line: 2},
		// Kept
		{Rule: "mcp-env-leakage", Severity: SeverityHigh, Message: "test", File: serverFile, Line: 5},
	}

	kept, suppressed := s.Filter(findings)
	if len(kept) != 1 {
		t.Errorf("expected 1 kept, got %d", len(kept))
	}
	if len(suppressed) != 2 {
		t.Errorf("expected 2 suppressed, got %d", len(suppressed))
	}
	if len(kept) > 0 && kept[0].Rule != "mcp-env-leakage" {
		t.Errorf("expected kept rule mcp-env-leakage, got %s", kept[0].Rule)
	}
}

func TestFilter_AllKept(t *testing.T) {
	dir := t.TempDir()
	// No .oxvaultignore — all findings pass through
	s := newSuppressor(t)
	if err := s.LoadIgnoreFile(dir); err != nil {
		t.Fatalf("LoadIgnoreFile: %v", err)
	}

	findings := []Finding{
		makeFinding("mcp-cmd-injection", "server.py", 1),
		makeFinding("mcp-env-leakage", "server.js", 5),
	}

	kept, suppressed := s.Filter(findings)
	if len(kept) != 2 {
		t.Errorf("expected 2 kept, got %d", len(kept))
	}
	if len(suppressed) != 0 {
		t.Errorf("expected 0 suppressed, got %d", len(suppressed))
	}
}

// ── globMatch unit tests ───────────────────────────────────────────────────────

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		file    string
		want    bool
	}{
		{"base name glob", "*_test.py", "server_test.py", true},
		{"base name glob in subdir", "*_test.py", "tests/server_test.py", true},
		{"dir glob", "tests/**", "tests/helpers.py", true},
		{"dir glob nested", "tests/**", "tests/unit/helpers.py", true},
		{"dir glob no match", "tests/**", "server.py", false},
		{"exact match", "server.py", "server.py", true},
		{"no match", "*.js", "server.py", false},
		{"empty file", "*.py", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := globMatch(tt.pattern, tt.file)
			if got != tt.want {
				t.Errorf("globMatch(%q, %q) = %v, want %v", tt.pattern, tt.file, got, tt.want)
			}
		})
	}
}

// ── parseLine unit tests ───────────────────────────────────────────────────────

func TestParseLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantKind ignoreKind
		wantGlob string
		wantRule string
		wantNil  bool
	}{
		{
			name:     "rule suppression",
			line:     "!mcp-env-leakage",
			wantKind: kindRule,
			wantRule: "mcp-env-leakage",
		},
		{
			name:    "bare exclamation — ignored",
			line:    "!",
			wantNil: true,
		},
		{
			name:     "file+rule combo",
			line:     "server.py:mcp-cmd-injection",
			wantKind: kindFileRule,
			wantGlob: "server.py",
			wantRule: "mcp-cmd-injection",
		},
		{
			name:     "glob with path sep in rule part treated as glob",
			line:     "legacy/*.py:mcp-hardcoded-secret",
			wantKind: kindFileRule,
			wantGlob: "legacy/*.py",
			wantRule: "mcp-hardcoded-secret",
		},
		{
			name:     "plain glob",
			line:     "*_test.py",
			wantKind: kindGlob,
			wantGlob: "*_test.py",
		},
		{
			name:     "directory glob",
			line:     "tests/**",
			wantKind: kindGlob,
			wantGlob: "tests/**",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLine(tt.line)
			if tt.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected non-nil rule, got nil")
			}
			if got.kind != tt.wantKind {
				t.Errorf("kind = %v, want %v", got.kind, tt.wantKind)
			}
			if got.glob != tt.wantGlob {
				t.Errorf("glob = %q, want %q", got.glob, tt.wantGlob)
			}
			if got.rule != tt.wantRule {
				t.Errorf("rule = %q, want %q", got.rule, tt.wantRule)
			}
		})
	}
}

// ── NewSuppressor interface guard ─────────────────────────────────────────────

func TestNewSuppressor_ImplementsInterface(t *testing.T) {
	var _ Suppressor = NewSuppressor()
}
