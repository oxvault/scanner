package providers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

// gitHubRepoURL builds the HTTPS clone URL for an owner/repo. It is a package
// variable so tests can point it at a local bare repository and remain
// hermetic (no real network / github access).
var gitHubRepoURL = func(owner, repo string) string {
	return fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)
}

// githubTarget is the parsed form of a `github:` scan target.
type githubTarget struct {
	owner   string // repository owner / org
	repo    string // repository name
	subpath string // optional sub-directory to scan (cleaned, "" when absent)
	ref     string // optional branch or tag (@ref), "" when absent
}

type resolver struct {
	logger *slog.Logger
	hf     HFConfig
}

func NewResolver(logger *slog.Logger) Resolver {
	return &resolver{logger: logger}
}

func (r *resolver) Resolve(target string) (*ResolvedPackage, error) {
	r.logger.Info("resolving target", "target", target)

	switch {
	case strings.HasPrefix(target, "hf:"):
		return r.resolveHuggingFace(target)
	case isLocalPath(target):
		return r.resolveLocal(target)
	case strings.HasPrefix(target, "github:"):
		return r.resolveGitHub(target)
	case strings.HasPrefix(target, "@") || !strings.Contains(target, "/"):
		return r.resolveNPM(target)
	default:
		return r.resolveLocal(target)
	}
}

// resolveHuggingFace dispatches to the v0.4 HF download + cache implementation.
func (r *resolver) resolveHuggingFace(target string) (*ResolvedPackage, error) {
	return r.resolveHuggingFaceImpl(target)
}

func (r *resolver) resolveLocal(path string) (*ResolvedPackage, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("target not found: %w", err)
	}

	pkg := &ResolvedPackage{
		Path: absPath,
		Kind: KindMCPServer,
	}

	if info.IsDir() {
		if isModelDirectory(absPath) {
			pkg.Kind = KindModelDirectory
			pkg.Name = filepath.Base(absPath)
			r.logger.Info("resolved local model directory", "path", pkg.Path)
			return pkg, nil
		}
		pkg.Language = detectProjectLanguage(absPath)
		cmd, args := detectServerCommand(absPath, pkg.Language)
		pkg.Command = cmd
		pkg.Args = args
		pkg.Name = filepath.Base(absPath)
	} else {
		if isModelArtifactFile(absPath) {
			pkg.Kind = KindModelArtifact
			pkg.Name = filepath.Base(absPath)
			pkg.Path = filepath.Dir(absPath)
			r.logger.Info("resolved local model artifact",
				"path", pkg.Path,
				"name", pkg.Name,
			)
			// Re-attach the file path to Args so AIBOM consumers know which
			// artifact to scan. The Path field intentionally points at the
			// parent directory to mirror MCP-server behaviour.
			pkg.Args = []string{absPath}
			return pkg, nil
		}
		pkg.Language = detectLanguage(absPath)
		pkg.Command = languageRuntime(pkg.Language)
		pkg.Args = []string{absPath}
		pkg.Name = filepath.Base(absPath)
		pkg.Path = filepath.Dir(absPath)
	}

	r.logger.Info("resolved local target",
		"path", pkg.Path,
		"language", pkg.Language,
		"command", pkg.Command,
	)

	return pkg, nil
}

func (r *resolver) resolveNPM(packageName string) (*ResolvedPackage, error) {
	r.logger.Info("resolving npm package", "package", packageName)

	tmpDir, err := os.MkdirTemp("", "oxvault-scan-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	// npm install to temp directory
	cmd := exec.Command("npm", "install", "--prefix", tmpDir, packageName)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("npm install %s: %w", packageName, err)
	}

	// Find the installed package
	pkgDir := filepath.Join(tmpDir, "node_modules", packageName)
	if _, err := os.Stat(pkgDir); err != nil {
		// Scoped package — try without scope for the dir
		entries, _ := filepath.Glob(filepath.Join(tmpDir, "node_modules", "@*", "*"))
		if len(entries) > 0 {
			pkgDir = entries[0]
		}
	}

	return &ResolvedPackage{
		Path:     pkgDir,
		Command:  "npx",
		Args:     []string{"-y", packageName},
		Language: LangJavaScript,
		Name:     packageName,
	}, nil
}

func (r *resolver) resolveGitHub(target string) (*ResolvedPackage, error) {
	gt, err := parseGitHubTarget(target)
	if err != nil {
		return nil, err
	}

	r.logger.Info("cloning GitHub repo",
		"owner", gt.owner,
		"repo", gt.repo,
		"subpath", gt.subpath,
		"ref", gt.ref,
	)

	tmpDir, err := os.MkdirTemp("", "oxvault-scan-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	scanPath, err := r.cloneGitHub(tmpDir, gt)
	if err != nil {
		return nil, err
	}

	lang := detectProjectLanguage(scanPath)
	command, args := detectServerCommand(scanPath, lang)

	// Name reflects what is actually scanned: the repo, or the sub-directory
	// when a subpath was requested.
	name := gt.repo
	if gt.subpath != "" {
		name = filepath.Base(gt.subpath)
	}

	return &ResolvedPackage{
		Path:     scanPath,
		Command:  command,
		Args:     args,
		Language: lang,
		Name:     name,
	}, nil
}

// cloneGitHub clones gt into tmpDir and returns the local path that should be
// scanned. With no subpath it performs a plain shallow clone of the whole repo
// (unchanged legacy behaviour). With a subpath it attempts a blobless sparse
// checkout so only that directory is fetched, falling back to a full shallow
// clone when the installed git lacks sparse-checkout support.
func (r *resolver) cloneGitHub(tmpDir string, gt githubTarget) (string, error) {
	url := gitHubRepoURL(gt.owner, gt.repo)

	if gt.subpath == "" {
		if err := r.gitClone(tmpDir, url, gt.ref); err != nil {
			return "", fmt.Errorf("git clone %s/%s: %w", gt.owner, gt.repo, err)
		}
		return tmpDir, nil
	}

	if err := r.gitSparseClone(tmpDir, url, gt); err != nil {
		// Older git (< 2.25) lacks --sparse / sparse-checkout. Fall back to a
		// full shallow clone and simply point at the subpath afterwards.
		r.logger.Warn("sparse checkout unavailable; falling back to full clone",
			"error", err)
		if rmErr := os.RemoveAll(tmpDir); rmErr != nil {
			return "", fmt.Errorf("clean failed sparse clone: %w", rmErr)
		}
		if mkErr := os.MkdirAll(tmpDir, 0o755); mkErr != nil {
			return "", fmt.Errorf("recreate temp dir: %w", mkErr)
		}
		if cloneErr := r.gitClone(tmpDir, url, gt.ref); cloneErr != nil {
			return "", fmt.Errorf("git clone %s/%s: %w", gt.owner, gt.repo, cloneErr)
		}
	}

	scanPath := filepath.Join(tmpDir, filepath.FromSlash(gt.subpath))
	if _, err := os.Stat(scanPath); err != nil {
		return "", fmt.Errorf("subpath %q not found in %s/%s: %w",
			gt.subpath, gt.owner, gt.repo, err)
	}
	return scanPath, nil
}

// gitClone performs a plain shallow clone of url into tmpDir, optionally
// checking out a specific branch or tag ref.
func (r *resolver) gitClone(tmpDir, url, ref string) error {
	args := []string{"clone", "--depth", "1"}
	if ref != "" {
		args = append(args, "--branch", ref)
	}
	args = append(args, url, tmpDir)

	cmd := exec.Command("git", args...)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// gitSparseClone performs a blobless sparse checkout that fetches only gt.subpath:
//
//	git clone --depth 1 --filter=blob:none --sparse <url> <tmpDir>
//	git -C <tmpDir> sparse-checkout set <subpath>
//
// It returns an error (leaving tmpDir for the caller to clean) when the
// installed git does not support sparse checkout, so the caller can fall back.
func (r *resolver) gitSparseClone(tmpDir, url string, gt githubTarget) error {
	cloneArgs := []string{"clone", "--depth", "1", "--filter=blob:none", "--sparse"}
	if gt.ref != "" {
		cloneArgs = append(cloneArgs, "--branch", gt.ref)
	}
	cloneArgs = append(cloneArgs, url, tmpDir)

	clone := exec.Command("git", cloneArgs...)
	clone.Stderr = os.Stderr
	if err := clone.Run(); err != nil {
		return fmt.Errorf("sparse clone: %w", err)
	}

	set := exec.Command("git", "-C", tmpDir, "sparse-checkout", "set", gt.subpath)
	set.Stderr = os.Stderr
	if err := set.Run(); err != nil {
		return fmt.Errorf("sparse-checkout set %q: %w", gt.subpath, err)
	}
	return nil
}

// parseGitHubTarget parses a `github:` target into its owner, repo, optional
// subpath and optional @ref. Accepted forms:
//
//	github:owner/repo
//	github:owner/repo/sub/dir
//	github:owner/repo@ref
//	github:owner/repo/sub/dir@ref
//
// The subpath is validated to reject absolute paths and `..` traversal so a
// target can never escape the cloned repository root.
func parseGitHubTarget(target string) (githubTarget, error) {
	raw := strings.TrimPrefix(target, "github:")

	// Optional @ref suffix: everything after the first '@'. owner/repo/subpath
	// components never legitimately contain '@'.
	var ref string
	if at := strings.Index(raw, "@"); at >= 0 {
		ref = raw[at+1:]
		raw = raw[:at]
		if ref == "" {
			return githubTarget{}, fmt.Errorf("invalid github target %q: empty ref after '@'", target)
		}
	}

	raw = strings.Trim(raw, "/")
	if raw == "" {
		return githubTarget{}, fmt.Errorf("invalid github target %q: missing owner/repo", target)
	}

	parts := strings.Split(raw, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return githubTarget{}, fmt.Errorf("invalid github target %q: expected owner/repo", target)
	}

	gt := githubTarget{owner: parts[0], repo: parts[1], ref: ref}

	if len(parts) > 2 {
		subpath, err := validateSubpath(strings.Join(parts[2:], "/"))
		if err != nil {
			return githubTarget{}, fmt.Errorf("invalid github target %q: %w", target, err)
		}
		gt.subpath = subpath
	}

	return gt, nil
}

// validateSubpath rejects absolute paths and any `..` segment, then returns a
// cleaned, forward-slash relative path safe to join against the clone root.
func validateSubpath(subpath string) (string, error) {
	if strings.HasPrefix(subpath, "/") || filepath.IsAbs(subpath) {
		return "", fmt.Errorf("subpath %q must be relative to the repository root", subpath)
	}
	for _, seg := range strings.Split(subpath, "/") {
		if seg == ".." {
			return "", fmt.Errorf("subpath %q must not contain '..' segments", subpath)
		}
		// A leading '-' would let git interpret the segment as a flag when it
		// is passed to `sparse-checkout set`. No shell is involved (argv, not a
		// shell string), so this is defence-in-depth against argument injection.
		if strings.HasPrefix(seg, "-") {
			return "", fmt.Errorf("subpath %q must not contain a segment starting with '-'", subpath)
		}
	}
	cleaned := path.Clean(subpath)
	if cleaned == "." || cleaned == "" {
		return "", fmt.Errorf("subpath %q is empty", subpath)
	}
	return cleaned, nil
}

func isLocalPath(target string) bool {
	return strings.HasPrefix(target, "./") ||
		strings.HasPrefix(target, "../") ||
		strings.HasPrefix(target, "/") ||
		strings.HasPrefix(target, "~")
}

func detectProjectLanguage(dir string) Language {
	if _, err := os.Stat(filepath.Join(dir, "package.json")); err == nil {
		return LangJavaScript
	}
	if _, err := os.Stat(filepath.Join(dir, "pyproject.toml")); err == nil {
		return LangPython
	}
	if _, err := os.Stat(filepath.Join(dir, "requirements.txt")); err == nil {
		return LangPython
	}
	if _, err := os.Stat(filepath.Join(dir, "setup.py")); err == nil {
		return LangPython
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
		return LangGo
	}
	return LangUnknown
}

func detectServerCommand(dir string, lang Language) (string, []string) {
	switch lang {
	case LangJavaScript, LangTypeScript:
		// Check package.json for bin entry
		pkgJSON := filepath.Join(dir, "package.json")
		if data, err := os.ReadFile(pkgJSON); err == nil {
			var pkg struct {
				Bin  any    `json:"bin"`
				Main string `json:"main"`
				Name string `json:"name"`
			}
			if json.Unmarshal(data, &pkg) == nil {
				if pkg.Name != "" {
					return "npx", []string{"-y", pkg.Name}
				}
				if pkg.Main != "" {
					return "node", []string{filepath.Join(dir, pkg.Main)}
				}
			}
		}
		return "node", []string{filepath.Join(dir, "index.js")}

	case LangPython:
		mainPy := filepath.Join(dir, "server.py")
		if _, err := os.Stat(mainPy); err == nil {
			return "python3", []string{mainPy}
		}
		mainPy = filepath.Join(dir, "main.py")
		if _, err := os.Stat(mainPy); err == nil {
			return "python3", []string{mainPy}
		}
		return "python3", []string{"-m", filepath.Base(dir)}

	case LangGo:
		return "go", []string{"run", dir}

	default:
		return "", nil
	}
}

func languageRuntime(lang Language) string {
	switch lang {
	case LangPython:
		return "python3"
	case LangJavaScript, LangTypeScript:
		return "node"
	case LangGo:
		return "go"
	default:
		return ""
	}
}

// modelArtifactExtensions lists file extensions that identify model artifacts
// recognised by the AIBOM module.
var modelArtifactExtensions = map[string]struct{}{
	".pkl":         {},
	".pickle":      {},
	".pt":          {},
	".pth":         {},
	".bin":         {},
	".ckpt":        {},
	".onnx":        {},
	".safetensors": {},
}

// isModelArtifactFile returns true when path's extension matches a known
// model-artifact format. Used by the resolver to set ResolvedPackage.Kind.
func isModelArtifactFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	_, ok := modelArtifactExtensions[ext]
	return ok
}

// isModelDirectory returns true when dir contains at least one model-artifact
// file (.pkl, .pt, .onnx, .safetensors, ...) AND lacks the MCP project markers
// that would identify it as a server (package.json, pyproject.toml, etc.).
//
// The MCP-marker check is a guard rail: many MCP servers ship sample weights
// inside their repo, and we must continue to treat those as servers — not
// flip them into AIBOM mode. Explicit AIBOM scans of those models should
// target the artifact file directly.
//
// Detection is intentionally cheap: a single directory read, no recursion.
func isModelDirectory(dir string) bool {
	if detectProjectLanguage(dir) != LangUnknown {
		return false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if isModelArtifactFile(entry.Name()) {
			return true
		}
	}
	return false
}
