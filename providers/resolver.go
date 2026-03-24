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
}

func NewResolver(logger *slog.Logger) Resolver {
	return &resolver{logger: logger}
}

func (r *resolver) Resolve(target string) (*ResolvedPackage, error) {
	r.logger.Info("resolving target", "target", target)

	switch {
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
	}

	if info.IsDir() {
		pkg.Language = detectProjectLanguage(absPath)
		cmd, args := detectServerCommand(absPath, pkg.Language)
		pkg.Command = cmd
		pkg.Args = args
		pkg.Name = filepath.Base(absPath)
	} else {
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
