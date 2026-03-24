package providers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func newSAST(t *testing.T) SASTAnalyzer {
	t.Helper()
	return NewSASTAnalyzer()
}

// writeTempFile creates a temp file with given content and returns its path.
func writeTempFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp file %s: %v", path, err)
	}
	return path
}

func findingByRule(findings []Finding, rule string) *Finding {
	for i := range findings {
		if findings[i].Rule == rule {
			return &findings[i]
		}
	}
	return nil
}

func requireFinding(t *testing.T, findings []Finding, rule string) Finding {
	t.Helper()
	f := findingByRule(findings, rule)
	if f == nil {
		rules := make([]string, len(findings))
		for i, x := range findings {
			rules[i] = x.Rule
		}
		t.Fatalf("expected finding with rule %q, got none (present: %v)", rule, rules)
	}
	return *f
}

func requireNoFinding(t *testing.T, findings []Finding, rule string) {
	t.Helper()
	if f := findingByRule(findings, rule); f != nil {
		t.Errorf("unexpected finding with rule %q: %s", rule, f.Message)
	}
}

// ── detectLanguage ────────────────────────────────────────────────────────────

func TestDetectLanguage(t *testing.T) {
	tests := []struct {
		path string
		want Language
	}{
		{"server.py", LangPython},
		{"app.js", LangJavaScript},
		{"app.mjs", LangJavaScript},
		{"app.cjs", LangJavaScript},
		{"index.ts", LangTypeScript},
		{"index.mts", LangTypeScript},
		{"main.go", LangGo},
		{"README.md", LangUnknown},
		{"Makefile", LangUnknown},
		{"data.json", LangUnknown},
		{"script.sh", LangUnknown},
		{"FILE.PY", LangPython},  // case insensitive
		{"APP.JS", LangJavaScript},
		{"MAIN.GO", LangGo},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := detectLanguage(tt.path)
			if got != tt.want {
				t.Errorf("detectLanguage(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// ── languageMatch ─────────────────────────────────────────────────────────────

func TestLanguageMatch(t *testing.T) {
	tests := []struct {
		name      string
		supported []Language
		lang      Language
		want      bool
	}{
		{"match python", []Language{LangPython}, LangPython, true},
		{"no match python", []Language{LangJavaScript}, LangPython, false},
		{"empty supported", []Language{}, LangPython, false},
		{"multi supported match", []Language{LangPython, LangJavaScript}, LangJavaScript, true},
		{"multi supported no match", []Language{LangPython, LangJavaScript}, LangGo, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := languageMatch(tt.supported, tt.lang)
			if got != tt.want {
				t.Errorf("languageMatch(%v, %v) = %v, want %v", tt.supported, tt.lang, got, tt.want)
			}
		})
	}
}

// ── AnalyzeFile — Python ──────────────────────────────────────────────────────

func TestAnalyzeFile_Python_OsPopenSystem(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name    string
		content string
		rule    string
	}{
		{
			name:    "os.popen",
			content: "import os\nresult = os.popen(user_input).read()\n",
			rule:    "mcp-cmd-injection",
		},
		{
			name:    "os.system",
			content: "import os\nos.system('ls ' + path)\n",
			rule:    "mcp-cmd-injection",
		},
	}

	s := newSAST(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempFile(t, dir, tt.name+".py", tt.content)
			findings := s.AnalyzeFile(path, LangPython)
			requireFinding(t, findings, tt.rule)
		})
	}
}

func TestAnalyzeFile_Python_SubprocessShellTrue(t *testing.T) {
	dir := t.TempDir()
	content := `import subprocess
result = subprocess.run(cmd, shell=True)
`
	path := writeTempFile(t, dir, "server.py", content)
	s := newSAST(t)
	findings := s.AnalyzeFile(path, LangPython)
	requireFinding(t, findings, "mcp-cmd-injection")
}

func TestAnalyzeFile_Python_SubprocessShellFalse_NotFlagged(t *testing.T) {
	dir := t.TempDir()
	content := `import subprocess
result = subprocess.run(["ls", path], shell=False)
`
	path := writeTempFile(t, dir, "server.py", content)
	s := newSAST(t)
	findings := s.AnalyzeFile(path, LangPython)
	requireNoFinding(t, findings, "mcp-cmd-injection")
}

func TestAnalyzeFile_Python_Eval(t *testing.T) {
	dir := t.TempDir()
	content := "result = eval(user_code)\n"
	path := writeTempFile(t, dir, "script.py", content)
	s := newSAST(t)
	findings := s.AnalyzeFile(path, LangPython)
	requireFinding(t, findings, "mcp-code-eval")
}

func TestAnalyzeFile_Python_PathTraversal(t *testing.T) {
	dir := t.TempDir()
	content := `def read(name):
    with open(base_path + name) as f:
        return f.read()
`
	path := writeTempFile(t, dir, "files.py", content)
	s := newSAST(t)
	findings := s.AnalyzeFile(path, LangPython)
	requireFinding(t, findings, "mcp-path-traversal-risk")
}

func TestAnalyzeFile_Python_HardcodedSecret(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name    string
		content string
		rule    string
	}{
		{
			name:    "api_key",
			content: `api_key = "abcdefghijklmnopqrstuvwxyz1234"`,
			rule:    "mcp-hardcoded-secret",
		},
		{
			name:    "password",
			content: `password = "SuperSecret1234567890"`,
			rule:    "mcp-hardcoded-secret",
		},
		{
			name:    "aws key",
			content: `key = "AKIAIOSFODNN7EXAMPLE"`,
			rule:    "mcp-hardcoded-aws-key",
		},
		{
			name:    "openai key",
			content: `token = "sk-abcdefghijklmnopqrstuvwxyz"`,
			rule:    "mcp-hardcoded-api-key",
		},
		{
			name:    "github pat",
			content: "token = \"ghp_" + strings.Repeat("a", 36) + "\"",
			rule:    "mcp-hardcoded-github-pat",
		},
	}

	s := newSAST(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempFile(t, dir, tt.name+".py", tt.content)
			findings := s.AnalyzeFile(path, LangPython)
			requireFinding(t, findings, tt.rule)
		})
	}
}

// ── AnalyzeFile — JavaScript/TypeScript ──────────────────────────────────────

func TestAnalyzeFile_JS_ChildProcessExec(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name    string
		content string
		ext     string
	}{
		{
			name:    "exec js",
			content: "const result = child_process.exec(userCmd, callback);\n",
			ext:     ".js",
		},
		{
			name:    "execSync ts",
			content: "const output = child_process.execSync(cmd);\n",
			ext:     ".ts",
		},
	}

	s := newSAST(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempFile(t, dir, tt.name+tt.ext, tt.content)
			lang := detectLanguage(path)
			findings := s.AnalyzeFile(path, lang)
			requireFinding(t, findings, "mcp-cmd-injection")
		})
	}
}

func TestAnalyzeFile_JS_Eval(t *testing.T) {
	dir := t.TempDir()
	content := "const result = eval(userInput);\n"
	path := writeTempFile(t, dir, "app.js", content)
	s := newSAST(t)
	findings := s.AnalyzeFile(path, LangJavaScript)
	requireFinding(t, findings, "mcp-code-eval")
}

func TestAnalyzeFile_JS_ReadFileConcatenation(t *testing.T) {
	dir := t.TempDir()
	content := `const fs = require('fs');
const data = fs.readFileSync(baseDir + userPath);
`
	path := writeTempFile(t, dir, "handler.js", content)
	s := newSAST(t)
	findings := s.AnalyzeFile(path, LangJavaScript)
	requireFinding(t, findings, "mcp-path-traversal-risk")
}

func TestAnalyzeFile_TS_HardcodedSecret(t *testing.T) {
	dir := t.TempDir()
	content := `const apiKey = "AKIAIOSFODNN7EXAMPLE";`
	path := writeTempFile(t, dir, "config.ts", content)
	s := newSAST(t)
	findings := s.AnalyzeFile(path, LangTypeScript)
	requireFinding(t, findings, "mcp-hardcoded-aws-key")
}

// ── AnalyzeFile — Go ──────────────────────────────────────────────────────────

func TestAnalyzeFile_Go_HardcodedSecret(t *testing.T) {
	dir := t.TempDir()
	content := `package main

const apiKey = "AKIAIOSFODNN7EXAMPLE"
`
	path := writeTempFile(t, dir, "main.go", content)
	s := newSAST(t)
	findings := s.AnalyzeFile(path, LangGo)
	requireFinding(t, findings, "mcp-hardcoded-aws-key")
}

func TestAnalyzeFile_Go_OpenAIKey(t *testing.T) {
	dir := t.TempDir()
	content := `package main

var token = "sk-abcdefghijklmnopqrstuvwxyz1234"
`
	path := writeTempFile(t, dir, "client.go", content)
	s := newSAST(t)
	findings := s.AnalyzeFile(path, LangGo)
	requireFinding(t, findings, "mcp-hardcoded-api-key")
}

// ── AnalyzeFile — language mismatch ──────────────────────────────────────────

func TestAnalyzeFile_PythonPatternNotTriggeredForGo(t *testing.T) {
	// os.popen is a Python pattern — should not fire when lang=Go
	dir := t.TempDir()
	content := "// os.popen(cmd) mentioned in comment\nfunc main() {}\n"
	path := writeTempFile(t, dir, "main.go", content)
	s := newSAST(t)
	findings := s.AnalyzeFile(path, LangGo)
	requireNoFinding(t, findings, "mcp-cmd-injection")
}

func TestAnalyzeFile_JSPatternNotTriggeredForPython(t *testing.T) {
	// child_process is JS — should not fire for Python files
	dir := t.TempDir()
	content := "# child_process.exec(cmd)\nresult = 1\n"
	path := writeTempFile(t, dir, "script.py", content)
	s := newSAST(t)
	findings := s.AnalyzeFile(path, LangPython)
	requireNoFinding(t, findings, "mcp-cmd-injection")
}

// ── AnalyzeFile — edge cases ──────────────────────────────────────────────────

func TestAnalyzeFile_NonExistentFile(t *testing.T) {
	s := newSAST(t)
	findings := s.AnalyzeFile("/nonexistent/path/file.py", LangPython)
	if len(findings) != 0 {
		t.Errorf("expected nil/empty findings for missing file, got %d", len(findings))
	}
}

func TestAnalyzeFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := writeTempFile(t, dir, "empty.py", "")
	s := newSAST(t)
	findings := s.AnalyzeFile(path, LangPython)
	if len(findings) != 0 {
		t.Errorf("expected no findings for empty file, got %d", len(findings))
	}
}

func TestAnalyzeFile_LineNumbers(t *testing.T) {
	dir := t.TempDir()
	content := "# line 1\n# line 2\nos.popen(cmd)\n# line 4\n"
	path := writeTempFile(t, dir, "script.py", content)
	s := newSAST(t)
	findings := s.AnalyzeFile(path, LangPython)
	f := requireFinding(t, findings, "mcp-cmd-injection")
	if f.Line != 3 {
		t.Errorf("expected Line=3, got %d", f.Line)
	}
}

func TestAnalyzeFile_FilePathInFinding(t *testing.T) {
	dir := t.TempDir()
	content := "os.system(user_input)\n"
	path := writeTempFile(t, dir, "vuln.py", content)
	s := newSAST(t)
	findings := s.AnalyzeFile(path, LangPython)
	f := requireFinding(t, findings, "mcp-cmd-injection")
	if f.File != path {
		t.Errorf("expected File=%q, got %q", path, f.File)
	}
}

func TestAnalyzeFile_MultipleFindings(t *testing.T) {
	dir := t.TempDir()
	content := `import os
os.popen(cmd)
os.system(cmd2)
eval(code)
`
	path := writeTempFile(t, dir, "multi.py", content)
	s := newSAST(t)
	findings := s.AnalyzeFile(path, LangPython)
	if len(findings) < 3 {
		t.Errorf("expected at least 3 findings, got %d", len(findings))
	}
}

func TestAnalyzeFile_LongLineTruncated(t *testing.T) {
	dir := t.TempDir()
	longLine := "os.popen(" + strings.Repeat("a", 200) + ")"
	path := writeTempFile(t, dir, "long.py", longLine+"\n")
	s := newSAST(t)
	findings := s.AnalyzeFile(path, LangPython)
	f := requireFinding(t, findings, "mcp-cmd-injection")
	if len(f.Message) > 300 {
		t.Errorf("message not truncated: len=%d", len(f.Message))
	}
}

// ── AnalyzeDirectory ──────────────────────────────────────────────────────────

func TestAnalyzeDirectory_MultipleFiles(t *testing.T) {
	dir := t.TempDir()

	writeTempFile(t, dir, "server.py", "os.popen(user_input)\n")
	writeTempFile(t, dir, "app.js", "child_process.exec(cmd);\n")
	writeTempFile(t, dir, "safe.go", "package main\nfunc main() {}\n")

	s := newSAST(t)
	findings := s.AnalyzeDirectory(dir)

	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(findings))
	}
}

func TestAnalyzeDirectory_SkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	nodeModules := filepath.Join(dir, "node_modules")
	if err := os.MkdirAll(nodeModules, 0755); err != nil {
		t.Fatal(err)
	}
	// Put a vulnerable file inside node_modules — should be skipped
	writeTempFile(t, nodeModules, "vuln.js", "child_process.exec(cmd);\n")
	// And one outside
	writeTempFile(t, dir, "clean.js", "console.log('hello');\n")

	s := newSAST(t)
	findings := s.AnalyzeDirectory(dir)
	if len(findings) != 0 {
		t.Errorf("expected no findings (node_modules skipped, clean.js has none), got %d", len(findings))
	}
}

func TestAnalyzeDirectory_SkipsGitDir(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeTempFile(t, gitDir, "hook.py", "os.popen(cmd)\n")

	s := newSAST(t)
	findings := s.AnalyzeDirectory(dir)
	if len(findings) != 0 {
		t.Errorf("expected no findings (.git skipped), got %d", len(findings))
	}
}

func TestAnalyzeDirectory_SkipsPycache(t *testing.T) {
	dir := t.TempDir()
	pycache := filepath.Join(dir, "__pycache__")
	if err := os.MkdirAll(pycache, 0755); err != nil {
		t.Fatal(err)
	}
	writeTempFile(t, pycache, "module.py", "os.popen(cmd)\n")

	s := newSAST(t)
	findings := s.AnalyzeDirectory(dir)
	if len(findings) != 0 {
		t.Errorf("expected no findings (__pycache__ skipped), got %d", len(findings))
	}
}

func TestAnalyzeDirectory_SkipsVenv(t *testing.T) {
	dir := t.TempDir()
	venv := filepath.Join(dir, ".venv")
	if err := os.MkdirAll(venv, 0755); err != nil {
		t.Fatal(err)
	}
	writeTempFile(t, venv, "vuln.py", "os.popen(cmd)\n")

	s := newSAST(t)
	findings := s.AnalyzeDirectory(dir)
	if len(findings) != 0 {
		t.Errorf("expected no findings (.venv skipped), got %d", len(findings))
	}
}

func TestAnalyzeDirectory_SkipsUnknownExtensions(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "Makefile", "exec: $(CMD)\n")
	writeTempFile(t, dir, "data.csv", "SELECT * FROM users\n")

	s := newSAST(t)
	findings := s.AnalyzeDirectory(dir)
	if len(findings) != 0 {
		t.Errorf("expected no findings for unknown extensions, got %d", len(findings))
	}
}

func TestAnalyzeDirectory_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	s := newSAST(t)
	findings := s.AnalyzeDirectory(dir)
	if len(findings) != 0 {
		t.Errorf("expected no findings for empty directory, got %d", len(findings))
	}
}

func TestAnalyzeDirectory_NestedFiles(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "src", "handlers")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	writeTempFile(t, sub, "tool.py", "os.system(cmd)\n")

	s := newSAST(t)
	findings := s.AnalyzeDirectory(dir)
	if len(findings) == 0 {
		t.Error("expected finding in nested subdirectory")
	}
}

// ── DetectEgress ──────────────────────────────────────────────────────────────

func TestDetectEgress_PythonRequests(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name    string
		content string
		method  string
	}{
		{"get", "import requests\nrequests.get(url)\n", "requests.get"},
		{"post", "requests.post(url, data=payload)\n", "requests.post"},
		{"put", "requests.put(url, json=data)\n", "requests.put"},
		{"delete", "requests.delete(endpoint)\n", "requests.delete"},
		{"patch", "requests.patch(url, data=data)\n", "requests.patch"},
	}

	s := newSAST(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempFile(t, dir, tt.name+".py", tt.content)
			_ = path
			findings := s.DetectEgress(dir)
			found := false
			for _, f := range findings {
				if f.Method == tt.method {
					found = true
					break
				}
			}
			if !found {
				methods := make([]string, len(findings))
				for i, f := range findings {
					methods[i] = f.Method
				}
				t.Errorf("expected egress method %q, got: %v", tt.method, methods)
			}
		})
	}
}

func TestDetectEgress_PythonUrllib(t *testing.T) {
	dir := t.TempDir()
	content := "import urllib.request\nurllib.request.urlopen(url)\n"
	writeTempFile(t, dir, "fetcher.py", content)
	s := newSAST(t)
	findings := s.DetectEgress(dir)
	found := false
	for _, f := range findings {
		if f.Method == "urllib.request.urlopen" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected urllib.request.urlopen egress finding")
	}
}

func TestDetectEgress_PythonHTTPClient(t *testing.T) {
	dir := t.TempDir()
	content := "import http.client\nconn = http.client.HTTPConnection('example.com')\n"
	writeTempFile(t, dir, "http_client.py", content)
	s := newSAST(t)
	findings := s.DetectEgress(dir)
	found := false
	for _, f := range findings {
		if f.Method == "http.client.HTTPConnection" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected http.client.HTTPConnection egress finding")
	}
}

func TestDetectEgress_JSFetch(t *testing.T) {
	dir := t.TempDir()
	content := "const data = await fetch(apiUrl);\n"
	writeTempFile(t, dir, "api.js", content)
	s := newSAST(t)
	findings := s.DetectEgress(dir)
	found := false
	for _, f := range findings {
		if f.Method == "fetch" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected fetch egress finding")
	}
}

func TestDetectEgress_JSAxios(t *testing.T) {
	dir := t.TempDir()
	content := "const resp = await axios.post(url, payload);\n"
	writeTempFile(t, dir, "client.ts", content)
	s := newSAST(t)
	findings := s.DetectEgress(dir)
	found := false
	for _, f := range findings {
		if f.Method == "axios.post" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected axios.post egress finding")
	}
}

func TestDetectEgress_GoHTTP(t *testing.T) {
	dir := t.TempDir()
	content := `package main

import "net/http"

func call() {
    http.Get("https://example.com")
}
`
	writeTempFile(t, dir, "client.go", content)
	s := newSAST(t)
	findings := s.DetectEgress(dir)
	found := false
	for _, f := range findings {
		if f.Method == "net/http" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected net/http egress finding")
	}
}

func TestDetectEgress_LineNumberTracked(t *testing.T) {
	dir := t.TempDir()
	content := "# line 1\n# line 2\nrequests.get(url)\n"
	writeTempFile(t, dir, "track.py", content)
	s := newSAST(t)
	findings := s.DetectEgress(dir)
	if len(findings) == 0 {
		t.Fatal("expected at least one egress finding")
	}
	if findings[0].Line != 3 {
		t.Errorf("expected Line=3, got %d", findings[0].Line)
	}
}

func TestDetectEgress_FilePathTracked(t *testing.T) {
	dir := t.TempDir()
	content := "requests.get(url)\n"
	path := writeTempFile(t, dir, "service.py", content)
	s := newSAST(t)
	findings := s.DetectEgress(dir)
	if len(findings) == 0 {
		t.Fatal("expected at least one egress finding")
	}
	if findings[0].File != path {
		t.Errorf("expected File=%q, got %q", path, findings[0].File)
	}
}

func TestDetectEgress_SkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")
	if err := os.MkdirAll(nm, 0755); err != nil {
		t.Fatal(err)
	}
	writeTempFile(t, nm, "lib.js", "fetch(url);\n")

	s := newSAST(t)
	findings := s.DetectEgress(dir)
	if len(findings) != 0 {
		t.Errorf("expected node_modules to be skipped, got %d findings", len(findings))
	}
}

func TestDetectEgress_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	s := newSAST(t)
	findings := s.DetectEgress(dir)
	if len(findings) != 0 {
		t.Errorf("expected no egress findings for empty directory, got %d", len(findings))
	}
}
