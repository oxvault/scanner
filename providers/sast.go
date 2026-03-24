package providers

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type sastAnalyzer struct{}

func NewSASTAnalyzer() SASTAnalyzer {
	return &sastAnalyzer{}
}

// sourcePattern represents a pattern to match in source code
type sourcePattern struct {
	pattern  *regexp.Regexp
	rule     string
	severity Severity
	message  string
	langs    []Language
}

var sourcePatterns = []sourcePattern{
	// Command injection — Python
	{
		pattern:  regexp.MustCompile(`os\.(popen|system)\s*\(`),
		rule:     "mcp-cmd-injection",
		severity: SeverityCritical,
		message:  "Direct OS command execution: %s",
		langs:    []Language{LangPython},
	},
	{
		pattern:  regexp.MustCompile(`subprocess\.(run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True`),
		rule:     "mcp-cmd-injection",
		severity: SeverityCritical,
		message:  "Subprocess with shell=True: %s",
		langs:    []Language{LangPython},
	},
	{
		pattern:  regexp.MustCompile(`eval\s*\(`),
		rule:     "mcp-code-eval",
		severity: SeverityCritical,
		message:  "Dynamic code evaluation: %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript},
	},
	// Command injection — JavaScript/TypeScript
	{
		pattern:  regexp.MustCompile(`child_process\.(exec|execSync)\s*\(`),
		rule:     "mcp-cmd-injection",
		severity: SeverityCritical,
		message:  "child_process.exec with potential injection: %s",
		langs:    []Language{LangJavaScript, LangTypeScript},
	},
	// Path traversal — all languages
	{
		pattern:  regexp.MustCompile(`(?i)(open|readFile|readFileSync|writeFile|writeFileSync)\s*\([^)]*\+`),
		rule:     "mcp-path-traversal-risk",
		severity: SeverityHigh,
		message:  "File operation with concatenated path (traversal risk): %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript},
	},
	// Hardcoded credentials
	{
		pattern:  regexp.MustCompile(`(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*["'][a-zA-Z0-9+/=_-]{16,}["']`),
		rule:     "mcp-hardcoded-secret",
		severity: SeverityCritical,
		message:  "Hardcoded credential: %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
	},
	{
		pattern:  regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
		rule:     "mcp-hardcoded-aws-key",
		severity: SeverityCritical,
		message:  "Hardcoded AWS access key: %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
	},
	{
		pattern:  regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`),
		rule:     "mcp-hardcoded-api-key",
		severity: SeverityCritical,
		message:  "Hardcoded API key (OpenAI format): %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
	},
	{
		pattern:  regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
		rule:     "mcp-hardcoded-github-pat",
		severity: SeverityHigh,
		message:  "Hardcoded GitHub PAT: %s",
		langs:    []Language{LangPython, LangJavaScript, LangTypeScript, LangGo},
	},
}

// Egress detection patterns
var egressPatterns = []struct {
	pattern *regexp.Regexp
	method  string
	langs   []Language
}{
	{regexp.MustCompile(`requests\.(get|post|put|delete|patch)\s*\(`), "requests.%s", []Language{LangPython}},
	{regexp.MustCompile(`urllib\.request\.urlopen\s*\(`), "urllib.request.urlopen", []Language{LangPython}},
	{regexp.MustCompile(`http\.client\.HTTPConnection\s*\(`), "http.client.HTTPConnection", []Language{LangPython}},
	{regexp.MustCompile(`fetch\s*\(`), "fetch", []Language{LangJavaScript, LangTypeScript}},
	{regexp.MustCompile(`axios\.(get|post|put|delete|patch)\s*\(`), "axios.%s", []Language{LangJavaScript, LangTypeScript}},
	{regexp.MustCompile(`http\.Get\s*\(|http\.Post\s*\(`), "net/http", []Language{LangGo}},
}

func (s *sastAnalyzer) AnalyzeFile(path string, lang Language) []Finding {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var findings []Finding
	lines := strings.Split(string(content), "\n")

	for _, sp := range sourcePatterns {
		if !languageMatch(sp.langs, lang) {
			continue
		}

		for lineNum, line := range lines {
			matches := sp.pattern.FindStringSubmatch(line)
			if len(matches) > 0 {
				matched := strings.TrimSpace(line)
				if len(matched) > 100 {
					matched = matched[:100] + "..."
				}
				findings = append(findings, Finding{
					Rule:     sp.rule,
					Severity: sp.severity,
					Message:  fmt.Sprintf(sp.message, matched),
					File:     path,
					Line:     lineNum + 1,
				})
			}
		}
	}

	return findings
}

func (s *sastAnalyzer) AnalyzeDirectory(dir string) []Finding {
	var findings []Finding

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == "node_modules" || base == ".git" || base == "__pycache__" || base == ".venv" {
				return filepath.SkipDir
			}
			return nil
		}

		lang := detectLanguage(path)
		if lang == LangUnknown {
			return nil
		}

		fileFindings := s.AnalyzeFile(path, lang)
		findings = append(findings, fileFindings...)
		return nil
	})

	return findings
}

func (s *sastAnalyzer) DetectEgress(dir string) []EgressFinding {
	var findings []EgressFinding

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == "node_modules" || base == ".git" || base == "__pycache__" || base == ".venv" {
				return filepath.SkipDir
			}
			return nil
		}

		lang := detectLanguage(path)
		if lang == LangUnknown {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			for _, ep := range egressPatterns {
				if !languageMatch(ep.langs, lang) {
					continue
				}
				matches := ep.pattern.FindStringSubmatch(line)
				if len(matches) > 0 {
					method := ep.method
					if strings.Contains(method, "%s") && len(matches) > 1 {
						method = fmt.Sprintf(method, matches[1])
					}
					findings = append(findings, EgressFinding{
						File:   path,
						Line:   lineNum,
						Method: method,
					})
				}
			}
		}
		return nil
	})

	return findings
}

func detectLanguage(path string) Language {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".py":
		return LangPython
	case ".js", ".mjs", ".cjs":
		return LangJavaScript
	case ".ts", ".mts":
		return LangTypeScript
	case ".go":
		return LangGo
	default:
		return LangUnknown
	}
}

func languageMatch(supported []Language, lang Language) bool {
	for _, l := range supported {
		if l == lang {
			return true
		}
	}
	return false
}
