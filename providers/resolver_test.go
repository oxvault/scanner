package providers

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func newResolver(t *testing.T) Resolver {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return NewResolver(logger)
}

// ── isLocalPath ───────────────────────────────────────────────────────────────

func TestIsLocalPath(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{"dot-slash relative", "./my-server", true},
		{"parent relative", "../other-dir", true},
		{"absolute unix", "/home/user/project", true},
		{"tilde home", "~/projects/server", true},
		{"npm package", "@company/mcp-server", false},
		{"npm no scope", "mcp-server-package", false},
		{"github target", "github:user/repo", false},
		{"bare name", "some-package", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLocalPath(tt.target)
			if got != tt.want {
				t.Errorf("isLocalPath(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

// ── detectProjectLanguage ─────────────────────────────────────────────────────

func TestDetectProjectLanguage_PackageJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"test"}`), 0644); err != nil {
		t.Fatal(err)
	}
	lang := detectProjectLanguage(dir)
	if lang != LangJavaScript {
		t.Errorf("expected LangJavaScript for package.json project, got %v", lang)
	}
}

func TestDetectProjectLanguage_PyprojectToml(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte("[tool.poetry]"), 0644); err != nil {
		t.Fatal(err)
	}
	lang := detectProjectLanguage(dir)
	if lang != LangPython {
		t.Errorf("expected LangPython for pyproject.toml, got %v", lang)
	}
}

func TestDetectProjectLanguage_RequirementsTxt(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.28.0"), 0644); err != nil {
		t.Fatal(err)
	}
	lang := detectProjectLanguage(dir)
	if lang != LangPython {
		t.Errorf("expected LangPython for requirements.txt, got %v", lang)
	}
}

func TestDetectProjectLanguage_SetupPy(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "setup.py"), []byte("from setuptools import setup"), 0644); err != nil {
		t.Fatal(err)
	}
	lang := detectProjectLanguage(dir)
	if lang != LangPython {
		t.Errorf("expected LangPython for setup.py, got %v", lang)
	}
}

func TestDetectProjectLanguage_GoMod(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.21"), 0644); err != nil {
		t.Fatal(err)
	}
	lang := detectProjectLanguage(dir)
	if lang != LangGo {
		t.Errorf("expected LangGo for go.mod, got %v", lang)
	}
}

func TestDetectProjectLanguage_Unknown(t *testing.T) {
	dir := t.TempDir()
	lang := detectProjectLanguage(dir)
	if lang != LangUnknown {
		t.Errorf("expected LangUnknown for empty dir, got %v", lang)
	}
}

func TestDetectProjectLanguage_PackageJSONTakesPriority(t *testing.T) {
	// When both package.json and requirements.txt exist, JS wins
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"test"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask"), 0644); err != nil {
		t.Fatal(err)
	}
	lang := detectProjectLanguage(dir)
	if lang != LangJavaScript {
		t.Errorf("expected LangJavaScript when both package.json and requirements.txt exist, got %v", lang)
	}
}

// ── detectServerCommand ───────────────────────────────────────────────────────

func TestDetectServerCommand_JSWithPackageJSONName(t *testing.T) {
	dir := t.TempDir()
	pkgJSON := `{"name":"my-mcp-server","main":"src/index.js"}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatal(err)
	}

	cmd, args := detectServerCommand(dir, LangJavaScript)
	if cmd != "npx" {
		t.Errorf("expected cmd='npx', got %q", cmd)
	}
	if len(args) < 2 || args[1] != "my-mcp-server" {
		t.Errorf("expected args to contain package name, got %v", args)
	}
}

func TestDetectServerCommand_JSWithPackageJSONMainOnly(t *testing.T) {
	dir := t.TempDir()
	// No name, but has main
	pkgJSON := `{"main":"dist/index.js"}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatal(err)
	}

	cmd, args := detectServerCommand(dir, LangJavaScript)
	if cmd != "node" {
		t.Errorf("expected cmd='node', got %q", cmd)
	}
	if len(args) == 0 || !filepath.IsAbs(args[0]) {
		t.Errorf("expected absolute path arg, got %v", args)
	}
}

func TestDetectServerCommand_JSNoPackageJSON(t *testing.T) {
	dir := t.TempDir()
	cmd, args := detectServerCommand(dir, LangJavaScript)
	if cmd != "node" {
		t.Errorf("expected cmd='node' fallback, got %q", cmd)
	}
	if len(args) == 0 {
		t.Error("expected at least one arg for node fallback")
	}
}

func TestDetectServerCommand_JSInvalidPackageJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}
	cmd, args := detectServerCommand(dir, LangJavaScript)
	// Should fall back to node index.js
	if cmd != "node" {
		t.Errorf("expected 'node' fallback for invalid package.json, got %q", cmd)
	}
	_ = args
}

func TestDetectServerCommand_PythonServerPy(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "server.py"), []byte("# server"), 0644); err != nil {
		t.Fatal(err)
	}

	cmd, args := detectServerCommand(dir, LangPython)
	if cmd != "python3" {
		t.Errorf("expected cmd='python3', got %q", cmd)
	}
	if len(args) == 0 || !filepath.IsAbs(args[0]) {
		t.Errorf("expected absolute path to server.py, got %v", args)
	}
}

func TestDetectServerCommand_PythonMainPy(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.py"), []byte("# main"), 0644); err != nil {
		t.Fatal(err)
	}

	cmd, args := detectServerCommand(dir, LangPython)
	if cmd != "python3" {
		t.Errorf("expected cmd='python3', got %q", cmd)
	}
	if len(args) == 0 || !filepath.IsAbs(args[0]) {
		t.Errorf("expected absolute path to main.py, got %v", args)
	}
}

func TestDetectServerCommand_PythonFallback(t *testing.T) {
	dir := t.TempDir()
	cmd, args := detectServerCommand(dir, LangPython)
	if cmd != "python3" {
		t.Errorf("expected cmd='python3', got %q", cmd)
	}
	if len(args) != 2 || args[0] != "-m" {
		t.Errorf("expected python3 -m <module>, got %v", args)
	}
}

func TestDetectServerCommand_Go(t *testing.T) {
	dir := t.TempDir()
	cmd, args := detectServerCommand(dir, LangGo)
	if cmd != "go" {
		t.Errorf("expected cmd='go', got %q", cmd)
	}
	if len(args) < 2 || args[0] != "run" {
		t.Errorf("expected 'go run <dir>', got %v", args)
	}
}

func TestDetectServerCommand_Unknown(t *testing.T) {
	dir := t.TempDir()
	cmd, args := detectServerCommand(dir, LangUnknown)
	if cmd != "" {
		t.Errorf("expected empty cmd for unknown language, got %q", cmd)
	}
	if args != nil {
		t.Errorf("expected nil args for unknown language, got %v", args)
	}
}

// ── languageRuntime ───────────────────────────────────────────────────────────

func TestLanguageRuntime(t *testing.T) {
	tests := []struct {
		lang Language
		want string
	}{
		{LangPython, "python3"},
		{LangJavaScript, "node"},
		{LangTypeScript, "node"},
		{LangGo, "go"},
		{LangUnknown, ""},
	}

	for _, tt := range tests {
		t.Run(string(tt.lang), func(t *testing.T) {
			got := languageRuntime(tt.lang)
			if got != tt.want {
				t.Errorf("languageRuntime(%v) = %q, want %q", tt.lang, got, tt.want)
			}
		})
	}
}

// ── Resolve — local path ──────────────────────────────────────────────────────

func TestResolve_LocalDirectory_Exists(t *testing.T) {
	dir := t.TempDir()
	// Create a Go project
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\n\ngo 1.21"), 0644); err != nil {
		t.Fatal(err)
	}

	r := newResolver(t)
	pkg, err := r.Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve(%q) error: %v", dir, err)
	}
	if pkg.Language != LangGo {
		t.Errorf("expected LangGo, got %v", pkg.Language)
	}
	if pkg.Name != filepath.Base(dir) {
		t.Errorf("expected Name=%q, got %q", filepath.Base(dir), pkg.Name)
	}
	if pkg.Path == "" {
		t.Error("expected non-empty Path")
	}
}

func TestResolve_LocalDirectory_JSProject(t *testing.T) {
	dir := t.TempDir()
	pkgJSON := `{"name":"test-server","main":"index.js"}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatal(err)
	}

	r := newResolver(t)
	pkg, err := r.Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve(%q) error: %v", dir, err)
	}
	if pkg.Language != LangJavaScript {
		t.Errorf("expected LangJavaScript, got %v", pkg.Language)
	}
	if pkg.Command == "" {
		t.Error("expected non-empty Command for JS project")
	}
}

func TestResolve_LocalDirectory_PythonProjectServerPy(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("fastmcp"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "server.py"), []byte("# server"), 0644); err != nil {
		t.Fatal(err)
	}

	r := newResolver(t)
	pkg, err := r.Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve(%q) error: %v", dir, err)
	}
	if pkg.Language != LangPython {
		t.Errorf("expected LangPython, got %v", pkg.Language)
	}
	if pkg.Command != "python3" {
		t.Errorf("expected Command='python3', got %q", pkg.Command)
	}
}

func TestResolve_LocalFile_Python(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "server.py")
	if err := os.WriteFile(filePath, []byte("# server"), 0644); err != nil {
		t.Fatal(err)
	}

	r := newResolver(t)
	pkg, err := r.Resolve(filePath)
	if err != nil {
		t.Fatalf("Resolve(%q) error: %v", filePath, err)
	}
	if pkg.Language != LangPython {
		t.Errorf("expected LangPython, got %v", pkg.Language)
	}
	if pkg.Command != "python3" {
		t.Errorf("expected Command='python3', got %q", pkg.Command)
	}
	// For a file, path becomes the directory
	if pkg.Path != dir {
		t.Errorf("expected Path=%q (parent dir), got %q", dir, pkg.Path)
	}
	// Args should contain the file path
	if len(pkg.Args) == 0 {
		t.Error("expected Args for file target")
	}
}

func TestResolve_LocalFile_JS(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "index.js")
	if err := os.WriteFile(filePath, []byte("console.log('hi');"), 0644); err != nil {
		t.Fatal(err)
	}

	r := newResolver(t)
	pkg, err := r.Resolve(filePath)
	if err != nil {
		t.Fatalf("Resolve(%q) error: %v", filePath, err)
	}
	if pkg.Language != LangJavaScript {
		t.Errorf("expected LangJavaScript, got %v", pkg.Language)
	}
	if pkg.Command != "node" {
		t.Errorf("expected Command='node', got %q", pkg.Command)
	}
}

func TestResolve_LocalFile_Go(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "main.go")
	if err := os.WriteFile(filePath, []byte("package main\nfunc main() {}"), 0644); err != nil {
		t.Fatal(err)
	}

	r := newResolver(t)
	pkg, err := r.Resolve(filePath)
	if err != nil {
		t.Fatalf("Resolve(%q) error: %v", filePath, err)
	}
	if pkg.Language != LangGo {
		t.Errorf("expected LangGo, got %v", pkg.Language)
	}
	if pkg.Command != "go" {
		t.Errorf("expected Command='go', got %q", pkg.Command)
	}
}

func TestResolve_NonExistentPath(t *testing.T) {
	r := newResolver(t)
	_, err := r.Resolve("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Error("expected error for non-existent path")
	}
}

func TestResolve_LocalRelativePath(t *testing.T) {
	// Create a temp dir and resolve it with relative-like notation
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test"), 0644); err != nil {
		t.Fatal(err)
	}

	r := newResolver(t)
	// Use the absolute path directly — relative resolution depends on cwd
	pkg, err := r.Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if !filepath.IsAbs(pkg.Path) {
		t.Errorf("expected absolute Path, got %q", pkg.Path)
	}
}

func TestResolve_FileName(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "myserver.py")
	if err := os.WriteFile(filePath, []byte("# server"), 0644); err != nil {
		t.Fatal(err)
	}

	r := newResolver(t)
	pkg, err := r.Resolve(filePath)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if pkg.Name != "myserver.py" {
		t.Errorf("expected Name='myserver.py', got %q", pkg.Name)
	}
}

func TestResolve_DirName(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test"), 0644); err != nil {
		t.Fatal(err)
	}

	r := newResolver(t)
	pkg, err := r.Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if pkg.Name != filepath.Base(dir) {
		t.Errorf("expected Name=%q, got %q", filepath.Base(dir), pkg.Name)
	}
}

// ── Resolve — routing logic ───────────────────────────────────────────────────

func TestResolve_GitHubPrefix_ReturnsError(t *testing.T) {
	// github: prefix tries to run git clone — will fail in test env without network
	// We just verify it attempts the right route (errors without git/network are expected)
	r := newResolver(t)
	_, err := r.Resolve("github:nonexistent-user-xyz/nonexistent-repo-abc")
	// We expect an error because git clone will fail
	if err == nil {
		t.Error("expected error for invalid GitHub repo (no network or nonexistent)")
	}
}

func TestResolve_NPMPackage_ReturnsError(t *testing.T) {
	// NPM resolve tries to run npm install — will fail for nonexistent package
	r := newResolver(t)
	_, err := r.Resolve("@nonexistent-scope-xyz/nonexistent-package-abc-123")
	// We expect an error because npm install will fail
	if err == nil {
		t.Error("expected error for nonexistent NPM package")
	}
}

func TestResolve_BareNameRoutesToNPM(t *testing.T) {
	// A bare name with no "/" should route to NPM (and fail with error for nonexistent)
	r := newResolver(t)
	_, err := r.Resolve("nonexistent-package-xyz-abc-123456")
	if err == nil {
		t.Error("expected error for nonexistent npm package")
	}
}

func TestResolve_DefaultRoutesToLocal(t *testing.T) {
	// A path that doesn't match any prefix goes to resolveLocal
	// Use a non-existent path to confirm it errors as "not found"
	r := newResolver(t)
	_, err := r.Resolve("some/path/without/leading/dot")
	if err == nil {
		t.Error("expected error for non-existent local path")
	}
}

// ── detectServerCommand — TypeScript ─────────────────────────────────────────

func TestDetectServerCommand_TypeScript(t *testing.T) {
	dir := t.TempDir()
	pkgJSON := `{"name":"ts-server"}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatal(err)
	}

	// TypeScript is treated the same as JavaScript in detectServerCommand
	cmd, args := detectServerCommand(dir, LangTypeScript)
	if cmd != "npx" {
		t.Errorf("expected cmd='npx' for TypeScript, got %q", cmd)
	}
	if len(args) < 2 || args[1] != "ts-server" {
		t.Errorf("expected package name arg, got %v", args)
	}
}
