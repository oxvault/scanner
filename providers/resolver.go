package providers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

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
	repo := strings.TrimPrefix(target, "github:")
	r.logger.Info("cloning GitHub repo", "repo", repo)

	tmpDir, err := os.MkdirTemp("", "oxvault-scan-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	url := fmt.Sprintf("https://github.com/%s.git", repo)
	cmd := exec.Command("git", "clone", "--depth", "1", url, tmpDir)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git clone %s: %w", repo, err)
	}

	lang := detectProjectLanguage(tmpDir)
	command, args := detectServerCommand(tmpDir, lang)

	return &ResolvedPackage{
		Path:     tmpDir,
		Command:  command,
		Args:     args,
		Language: lang,
		Name:     filepath.Base(repo),
	}, nil
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
