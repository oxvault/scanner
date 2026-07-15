package providers

import (
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// ── parseGitHubTarget ─────────────────────────────────────────────────────────

func TestParseGitHubTarget(t *testing.T) {
	tests := []struct {
		name        string
		target      string
		wantErr     bool
		wantOwner   string
		wantRepo    string
		wantSubpath string
		wantRef     string
	}{
		{
			name:      "repo only",
			target:    "github:oxvault/scanner",
			wantOwner: "oxvault", wantRepo: "scanner",
		},
		{
			name:      "repo only trailing slash",
			target:    "github:oxvault/scanner/",
			wantOwner: "oxvault", wantRepo: "scanner",
		},
		{
			name:        "repo with subpath",
			target:      "github:oxvault/scanner/examples/vulnerable-servers/tool-poisoning",
			wantOwner:   "oxvault",
			wantRepo:    "scanner",
			wantSubpath: "examples/vulnerable-servers/tool-poisoning",
		},
		{
			name:      "subpath trailing slash normalised",
			target:    "github:oxvault/scanner/examples/foo/",
			wantOwner: "oxvault", wantRepo: "scanner",
			wantSubpath: "examples/foo",
		},
		{
			name:      "repo with ref",
			target:    "github:oxvault/scanner@v1.2.3",
			wantOwner: "oxvault", wantRepo: "scanner", wantRef: "v1.2.3",
		},
		{
			name:      "repo with subpath and ref",
			target:    "github:oxvault/scanner/examples/foo@main",
			wantOwner: "oxvault", wantRepo: "scanner",
			wantSubpath: "examples/foo", wantRef: "main",
		},
		{
			name:    "traversal rejected",
			target:  "github:oxvault/scanner/../secret",
			wantErr: true,
		},
		{
			name:    "nested traversal rejected",
			target:  "github:oxvault/scanner/examples/../../etc/passwd",
			wantErr: true,
		},
		{
			name:    "absolute subpath rejected",
			target:  "github:oxvault/scanner//etc/passwd",
			wantErr: true,
		},
		{
			name:    "missing repo",
			target:  "github:oxvault",
			wantErr: true,
		},
		{
			name:    "empty target",
			target:  "github:",
			wantErr: true,
		},
		{
			name:    "empty ref",
			target:  "github:oxvault/scanner@",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gt, err := parseGitHubTarget(tt.target)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseGitHubTarget(%q) = %+v, want error", tt.target, gt)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseGitHubTarget(%q) unexpected error: %v", tt.target, err)
			}
			if gt.owner != tt.wantOwner {
				t.Errorf("owner = %q, want %q", gt.owner, tt.wantOwner)
			}
			if gt.repo != tt.wantRepo {
				t.Errorf("repo = %q, want %q", gt.repo, tt.wantRepo)
			}
			if gt.subpath != tt.wantSubpath {
				t.Errorf("subpath = %q, want %q", gt.subpath, tt.wantSubpath)
			}
			if gt.ref != tt.wantRef {
				t.Errorf("ref = %q, want %q", gt.ref, tt.wantRef)
			}
		})
	}
}

func TestValidateSubpath_Traversal(t *testing.T) {
	bad := []string{
		"..",
		"../etc",
		"a/../../b",
		"/etc/passwd",
		"", // becomes "." after clean
		".",
		"-flag",            // leading dash could be read as a git flag
		"examples/-inject", // leading-dash segment mid-path
	}
	for _, sp := range bad {
		t.Run(sp, func(t *testing.T) {
			if _, err := validateSubpath(sp); err == nil {
				t.Errorf("validateSubpath(%q) = nil error, want rejection", sp)
			}
		})
	}
}

func TestResolve_GitHubSubpathTraversal_NoClone(t *testing.T) {
	// A traversal target must be rejected during parsing, before any git clone
	// is attempted. This is fully hermetic (no git / network required).
	r := newResolver(t)
	_, err := r.Resolve("github:oxvault/scanner/../secret")
	if err == nil {
		t.Fatal("expected error for traversal subpath")
	}
	if !strings.Contains(err.Error(), "..") {
		t.Errorf("expected error to mention '..', got %v", err)
	}
}

// ── Resolve — github sparse checkout (hermetic, local git repo) ───────────────

// makeLocalGitRepo builds a real git repository on disk with the given files
// (map of forward-slash relative path → contents) and returns its path. Tests
// point gitHubRepoURL at this via a file:// URL so no network is used.
func makeLocalGitRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available; skipping sparse-checkout integration test")
	}

	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	git("init", "-b", "main")
	for rel, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git("add", "-A")
	git("commit", "-m", "initial")
	return dir
}

func TestResolve_GitHubSubpath_SparseCheckout(t *testing.T) {
	src := makeLocalGitRepo(t, map[string]string{
		"README.md":                         "# root",
		"examples/foo/requirements.txt":     "fastmcp",
		"examples/foo/server.py":            "# target server",
		"examples/bar/other.txt":            "sibling that must NOT be fetched",
		"examples/bar/should_not_exist.txt": "x",
	})

	orig := gitHubRepoURL
	t.Cleanup(func() { gitHubRepoURL = orig })
	gitHubRepoURL = func(owner, repo string) string { return "file://" + src }

	r := newResolver(t)
	pkg, err := r.Resolve("github:oxvault/scanner/examples/foo")
	if err != nil {
		t.Fatalf("Resolve subpath error: %v", err)
	}

	// Path must point into the requested subpath.
	if base := filepath.Base(pkg.Path); base != "foo" {
		t.Errorf("expected Path to end in /foo, got %q", pkg.Path)
	}
	if !strings.HasSuffix(filepath.ToSlash(pkg.Path), "examples/foo") {
		t.Errorf("expected Path to end in examples/foo, got %q", pkg.Path)
	}

	// The subpath's contents must be present...
	if _, err := os.Stat(filepath.Join(pkg.Path, "server.py")); err != nil {
		t.Errorf("expected server.py checked out in subpath: %v", err)
	}
	// ...and language detection must have run against the subpath.
	if pkg.Language != LangPython {
		t.Errorf("expected LangPython (from subpath requirements.txt), got %v", pkg.Language)
	}
	if pkg.Command != "python3" {
		t.Errorf("expected Command=python3, got %q", pkg.Command)
	}
	if pkg.Name != "foo" {
		t.Errorf("expected Name=foo, got %q", pkg.Name)
	}

	// Sparse checkout must NOT have materialised the sibling directory — this
	// is what proves only the subpath was fetched rather than the whole tree.
	cloneRoot := filepath.Dir(filepath.Dir(pkg.Path)) // <tmp> (parent of examples/)
	if _, err := os.Stat(filepath.Join(cloneRoot, "examples", "bar", "other.txt")); !os.IsNotExist(err) {
		t.Errorf("sibling examples/bar/other.txt should not be checked out (sparse), stat err = %v", err)
	}
}

func TestResolve_GitHubSubpath_Missing(t *testing.T) {
	src := makeLocalGitRepo(t, map[string]string{
		"README.md":              "# root",
		"examples/foo/server.py": "# server",
	})

	orig := gitHubRepoURL
	t.Cleanup(func() { gitHubRepoURL = orig })
	gitHubRepoURL = func(owner, repo string) string { return "file://" + src }

	r := newResolver(t)
	_, err := r.Resolve("github:oxvault/scanner/examples/does-not-exist")
	if err == nil {
		t.Fatal("expected error for non-existent subpath")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' error, got %v", err)
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

// ── Resolve — model artifacts (AIBOM) ────────────────────────────────────────

func TestResolve_LocalFile_PickleArtifact(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "weights.pkl")
	if err := os.WriteFile(filePath, []byte{0x80, 0x04}, 0644); err != nil {
		t.Fatal(err)
	}

	r := newResolver(t)
	pkg, err := r.Resolve(filePath)
	if err != nil {
		t.Fatalf("Resolve(%q) error: %v", filePath, err)
	}
	if pkg.Kind != KindModelArtifact {
		t.Errorf("expected Kind=KindModelArtifact, got %q", pkg.Kind)
	}
	if pkg.Name != "weights.pkl" {
		t.Errorf("expected Name='weights.pkl', got %q", pkg.Name)
	}
	if pkg.Path != dir {
		t.Errorf("expected Path=%q (parent dir), got %q", dir, pkg.Path)
	}
	if len(pkg.Args) == 0 || pkg.Args[0] != filePath {
		t.Errorf("expected Args[0]=%q, got %v", filePath, pkg.Args)
	}
}

func TestResolve_LocalFile_SafetensorsArtifact(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "model.safetensors")
	if err := os.WriteFile(filePath, []byte(`{"a":1}`), 0644); err != nil {
		t.Fatal(err)
	}

	r := newResolver(t)
	pkg, err := r.Resolve(filePath)
	if err != nil {
		t.Fatalf("Resolve(%q) error: %v", filePath, err)
	}
	if pkg.Kind != KindModelArtifact {
		t.Errorf("expected Kind=KindModelArtifact, got %q", pkg.Kind)
	}
}

func TestResolve_LocalFile_ONNXArtifact(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "graph.onnx")
	if err := os.WriteFile(filePath, []byte{0x08, 0x01}, 0644); err != nil {
		t.Fatal(err)
	}

	r := newResolver(t)
	pkg, err := r.Resolve(filePath)
	if err != nil {
		t.Fatalf("Resolve(%q) error: %v", filePath, err)
	}
	if pkg.Kind != KindModelArtifact {
		t.Errorf("expected Kind=KindModelArtifact, got %q", pkg.Kind)
	}
}

func TestResolve_LocalFile_NonModelKeepsMCPServerKind(t *testing.T) {
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
	if pkg.Kind != KindMCPServer {
		t.Errorf("expected Kind=KindMCPServer for .py file, got %q", pkg.Kind)
	}
}

func TestResolve_LocalDirectory_ModelDirectory(t *testing.T) {
	dir := t.TempDir()
	// A directory that contains model artifacts but no MCP-server markers.
	if err := os.WriteFile(filepath.Join(dir, "weights.safetensors"), []byte(`{"a":1}`), 0644); err != nil {
		t.Fatal(err)
	}

	r := newResolver(t)
	pkg, err := r.Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve(%q) error: %v", dir, err)
	}
	if pkg.Kind != KindModelDirectory {
		t.Errorf("expected Kind=KindModelDirectory, got %q", pkg.Kind)
	}
	if pkg.Name != filepath.Base(dir) {
		t.Errorf("expected Name=%q, got %q", filepath.Base(dir), pkg.Name)
	}
}

func TestResolve_LocalDirectory_MCPServerWithBundledModelStaysServer(t *testing.T) {
	// MCP servers commonly bundle sample model weights inside the repo.
	// The presence of an MCP project marker (package.json / pyproject.toml /
	// go.mod) must keep the package classified as KindMCPServer.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"my-mcp"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "weights.safetensors"), []byte(`{"a":1}`), 0644); err != nil {
		t.Fatal(err)
	}

	r := newResolver(t)
	pkg, err := r.Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve(%q) error: %v", dir, err)
	}
	if pkg.Kind != KindMCPServer {
		t.Errorf("expected Kind=KindMCPServer when MCP markers are present, got %q", pkg.Kind)
	}
}

func TestResolve_LocalDirectory_PlainProjectDefaultsToMCPServer(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test"), 0644); err != nil {
		t.Fatal(err)
	}

	r := newResolver(t)
	pkg, err := r.Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if pkg.Kind != KindMCPServer {
		t.Errorf("expected Kind=KindMCPServer for plain Go project, got %q", pkg.Kind)
	}
}

// HF resolver integration tests live in hf_resolver_test.go and use
// httptest.Server so we never touch the real HuggingFace API.

// ── isModelArtifactFile ──────────────────────────────────────────────────────

func TestIsModelArtifactFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"weights.pkl", true},
		{"weights.pickle", true},
		{"model.pt", true},
		{"model.pth", true},
		{"pytorch_model.bin", true},
		{"checkpoint.ckpt", true},
		{"graph.onnx", true},
		{"weights.safetensors", true},
		{"WEIGHTS.PKL", true}, // case-insensitive
		{"server.py", false},
		{"package.json", false},
		{"README.md", false},
		{"main.go", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isModelArtifactFile(tt.path); got != tt.want {
				t.Errorf("isModelArtifactFile(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
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
