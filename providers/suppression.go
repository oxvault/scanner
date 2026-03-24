package providers

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Suppressor filters findings using .oxvaultignore rules and inline oxvault:ignore comments.
type Suppressor interface {
	// LoadIgnoreFile reads .oxvaultignore from the given directory.
	// A missing file is not an error — it simply results in no file-based rules.
	LoadIgnoreFile(dir string) error

	// Filter partitions findings into kept and suppressed slices.
	Filter(findings []Finding) (kept []Finding, suppressed []Finding)

	// IsInlineSuppressed returns true when the source line for the finding
	// contains an oxvault:ignore comment that matches the finding's rule.
	IsInlineSuppressed(finding Finding) bool
}

// ignoreRule is a parsed line from .oxvaultignore.
type ignoreRule struct {
	kind     ignoreKind
	glob     string // for kindGlob and kindFileRule
	rule     string // for kindRule and kindFileRule
}

type ignoreKind int

const (
	kindGlob     ignoreKind = iota // e.g.  *_test.py
	kindRule                       // e.g.  !mcp-env-leakage
	kindFileRule                   // e.g.  server.py:mcp-cmd-injection
)

type suppressor struct {
	rules []ignoreRule
}

// NewSuppressor returns an empty Suppressor. Call LoadIgnoreFile to populate it.
func NewSuppressor() Suppressor {
	return &suppressor{}
}

// LoadIgnoreFile reads and parses a .oxvaultignore file from dir.
// If the file does not exist the method returns nil and leaves the rule list
// unchanged (empty unless previously loaded).
func (s *suppressor) LoadIgnoreFile(dir string) error {
	path := filepath.Join(dir, ".oxvaultignore")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		rule := parseLine(line)
		if rule != nil {
			s.rules = append(s.rules, *rule)
		}
	}
	return scanner.Err()
}

// parseLine converts a single non-blank, non-comment .oxvaultignore line into
// an ignoreRule.  Returns nil when the line cannot be recognised.
func parseLine(line string) *ignoreRule {
	// Rule-global suppression: lines prefixed with !
	if strings.HasPrefix(line, "!") {
		ruleName := strings.TrimPrefix(line, "!")
		if ruleName == "" {
			return nil
		}
		return &ignoreRule{kind: kindRule, rule: ruleName}
	}

	// File+rule combo: contains a colon NOT in a glob position.
	// We detect this by checking that the part before the last colon is non-empty
	// and the part after is non-empty and looks like a rule name (no path sep).
	if idx := strings.LastIndex(line, ":"); idx > 0 && idx < len(line)-1 {
		filePart := line[:idx]
		rulePart := line[idx+1:]
		// rulePart must not contain path separators — it is a rule name, not a path.
		if !strings.ContainsAny(rulePart, "/\\") {
			return &ignoreRule{kind: kindFileRule, glob: filePart, rule: rulePart}
		}
	}

	// Everything else is a file glob.
	return &ignoreRule{kind: kindGlob, glob: line}
}

// Filter partitions findings into kept and suppressed based on both
// .oxvaultignore rules and inline oxvault:ignore comments.
func (s *suppressor) Filter(findings []Finding) ([]Finding, []Finding) {
	var kept, suppressed []Finding
	for _, f := range findings {
		if s.matchesIgnoreFile(f) || s.IsInlineSuppressed(f) {
			suppressed = append(suppressed, f)
		} else {
			kept = append(kept, f)
		}
	}
	return kept, suppressed
}

// matchesIgnoreFile reports whether a finding is suppressed by any rule loaded
// from .oxvaultignore.
func (s *suppressor) matchesIgnoreFile(f Finding) bool {
	for _, rule := range s.rules {
		switch rule.kind {
		case kindGlob:
			if globMatch(rule.glob, f.File) {
				return true
			}
		case kindRule:
			if f.Rule == rule.rule {
				return true
			}
		case kindFileRule:
			if globMatch(rule.glob, f.File) && f.Rule == rule.rule {
				return true
			}
		}
	}
	return false
}

// IsInlineSuppressed reads the source line referenced by the finding and
// checks whether it carries an oxvault:ignore comment.
//
// Supported formats:
//
//	# oxvault:ignore                  — suppresses all rules on that line
//	# oxvault:ignore mcp-cmd-injection — suppresses only that rule
//	// oxvault:ignore                  — JS/TS/Go style
//	// oxvault:ignore mcp-code-eval
func (s *suppressor) IsInlineSuppressed(finding Finding) bool {
	if finding.File == "" || finding.Line <= 0 {
		return false
	}

	line, err := readLine(finding.File, finding.Line)
	if err != nil {
		return false
	}

	return lineHasIgnore(line, finding.Rule)
}

// lineHasIgnore returns true when line contains an oxvault:ignore comment that
// matches ruleName.  If no specific rule is named in the comment the ignore
// applies to all rules.
func lineHasIgnore(line, ruleName string) bool {
	const marker = "oxvault:ignore"

	idx := strings.Index(line, marker)
	if idx < 0 {
		return false
	}

	// Everything after the marker (trimmed).
	rest := strings.TrimSpace(line[idx+len(marker):])

	// No rule specified — suppress everything on this line.
	if rest == "" {
		return true
	}

	// The rest may start with a rule name optionally followed by whitespace or
	// end-of-line.  We split on whitespace and take the first token.
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return true
	}

	return fields[0] == ruleName
}

// readLine opens path and returns the text of the 1-based line number.
func readLine(path string, lineNum int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	current := 0
	for scanner.Scan() {
		current++
		if current == lineNum {
			return scanner.Text(), nil
		}
	}
	return "", scanner.Err()
}

// globMatch applies filepath.Match against the base name and the full path so
// that patterns like `*_test.py` match both `foo_test.py` and `tests/foo_test.py`.
// Directory globs like `tests/**` are handled by checking whether the file path
// contains the directory as a path component — matching regardless of where the
// directory appears in the absolute path.
func globMatch(pattern, filePath string) bool {
	if filePath == "" {
		return false
	}

	// Normalise separators for cross-platform safety.
	pattern = filepath.ToSlash(pattern)
	filePath = filepath.ToSlash(filePath)

	// Direct match against the full path.
	if matched, _ := filepath.Match(pattern, filePath); matched {
		return true
	}

	// Match against the base name only (handles `*_test.py` matching `dir/foo_test.py`).
	base := filepath.Base(filePath)
	if matched, _ := filepath.Match(pattern, base); matched {
		return true
	}

	// Handle `dir/**` — check if the file lives anywhere inside a directory named
	// `dir`.  We look for the directory component in the file path regardless of
	// whether the path is absolute, relative, or has leading segments.
	if strings.HasSuffix(pattern, "/**") {
		dir := strings.TrimSuffix(pattern, "/**")
		// Match absolute paths: /anything/dir/file
		if strings.Contains(filePath, "/"+dir+"/") || strings.HasSuffix(filePath, "/"+dir) {
			return true
		}
		// Match relative paths that start with dir/ (e.g. tests/unit/helpers.py)
		if strings.HasPrefix(filePath, dir+"/") || filePath == dir {
			return true
		}
	}

	// Handle `dir/*` and similar path-containing patterns by trying match
	// against every suffix of the file path (split at '/').
	if strings.Contains(pattern, "/") {
		// Try matching the pattern against each trailing sub-path of filePath.
		parts := strings.Split(filePath, "/")
		for i := range parts {
			sub := strings.Join(parts[i:], "/")
			if matched, _ := filepath.Match(pattern, sub); matched {
				return true
			}
		}
	}

	return false
}
