package providers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/oxvault/scanner/patterns"
)

// DepAuditor audits dependency manifests for known vulnerable MCP packages
// and suspicious install scripts.
type DepAuditor interface {
	AuditDirectory(dir string) []Finding
}

type depAuditor struct{}

// NewDepAuditor returns a new DepAuditor implementation.
func NewDepAuditor() DepAuditor {
	return &depAuditor{}
}

// AuditDirectory walks dir and audits every package.json and requirements.txt
// it finds (skipping node_modules and .git).
func (d *depAuditor) AuditDirectory(dir string) []Finding {
	var findings []Finding

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if IsExcludedDir(filepath.Base(path)) {
				return filepath.SkipDir
			}
			return nil
		}

		base := filepath.Base(path)
		switch base {
		case "package.json":
			findings = append(findings, d.auditPackageJSON(path)...)
		case "requirements.txt":
			findings = append(findings, d.auditRequirementsTxt(path)...)
		case "pyproject.toml":
			findings = append(findings, d.auditPyprojectToml(path)...)
		}
		return nil
	})

	return findings
}

// packageJSON is the subset of package.json that we parse.
type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	Scripts         map[string]string `json:"scripts"`
}

func (d *depAuditor) auditPackageJSON(path string) []Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return []Finding{{
			Rule:     "dep-audit-parse-error",
			Severity: SeverityWarning,
			Message:  fmt.Sprintf("Failed to parse package.json: %v", err),
			File:     path,
		}}
	}

	var findings []Finding

	// Merge dependencies + devDependencies into one map for scanning.
	allDeps := make(map[string]string, len(pkg.Dependencies)+len(pkg.DevDependencies))
	for name, ver := range pkg.Dependencies {
		allDeps[name] = ver
	}
	for name, ver := range pkg.DevDependencies {
		allDeps[name] = ver
	}

	for name, rawVersion := range allDeps {
		findings = append(findings, checkNPMDep(name, rawVersion, path)...)
	}

	// Scan lifecycle scripts for suspicious patterns.
	for _, hook := range patterns.LifecycleScripts {
		script, ok := pkg.Scripts[hook]
		if !ok {
			continue
		}
		for _, re := range patterns.SuspiciousScriptPatterns {
			if re.MatchString(script) {
				findings = append(findings, Finding{
					Rule:     "dep-suspicious-install-script",
					Severity: SeverityHigh,
					Message: fmt.Sprintf(
						"package.json scripts.%s contains suspicious pattern %q: %s",
						hook, re.String(), truncate(script, 120),
					),
					File: path,
				})
				break // one finding per hook is enough
			}
		}
	}

	return findings
}

// checkNPMDep checks a single npm dependency against the vulnerability database.
func checkNPMDep(name, rawVersion, file string) []Finding {
	var findings []Finding

	for _, vuln := range patterns.KnownVulnerablePackages {
		if vuln.Name != name {
			continue
		}

		// Strip npm range prefixes: ^, ~, >=, <=, >, <, =, whitespace.
		version := stripVersionPrefix(rawVersion)

		if version == "" || version == "*" || version == "latest" {
			// Cannot determine — warn for manual review.
			findings = append(findings, Finding{
				Rule:     "dep-audit-unknown-version",
				Severity: SeverityWarning,
				Message: fmt.Sprintf(
					"%s: version %q is unpinned — cannot verify against %s (CVSS %.1f): %s",
					name, rawVersion, vuln.CVE, vuln.CVSS, vuln.Description,
				),
				File: file,
				Fix:  fmt.Sprintf("Pin to a version > %s to avoid %s", vuln.MaxAffected, vuln.CVE),
			})
			continue
		}

		if semverLE(version, vuln.MaxAffected) {
			findings = append(findings, Finding{
				Rule:     "dep-audit-vulnerable",
				Severity: vuln.Severity,
				Message: fmt.Sprintf(
					"%s@%s is vulnerable (%s, CVSS %.1f): %s",
					name, version, vuln.CVE, vuln.CVSS, vuln.Description,
				),
				File:       file,
				Fix:        fmt.Sprintf("Upgrade %s above %s to fix %s", name, vuln.MaxAffected, vuln.CVE),
				CWE:        "CWE-1395",
				References: []string{vuln.CVE},
			})
		}
	}

	return findings
}

// auditRequirementsTxt parses a pip requirements.txt file.
// Each line may be: <package>[==|>=|<=|~=|!=]<version> [; markers] [# comment]
func (d *depAuditor) auditRequirementsTxt(path string) []Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var findings []Finding
	lines := strings.Split(string(data), "\n")

	for lineNum, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		// Strip inline comments.
		if idx := strings.Index(line, " #"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		// Strip environment markers: "package>=1.0 ; python_version>='3.8'"
		if idx := strings.Index(line, ";"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		name, version := parseRequirementsLine(line)
		if name == "" {
			continue
		}

		for _, vuln := range patterns.KnownVulnerablePackages {
			if !strings.EqualFold(vuln.Name, name) {
				continue
			}
			if version == "" {
				findings = append(findings, Finding{
					Rule:     "dep-audit-unknown-version",
					Severity: SeverityWarning,
					Message: fmt.Sprintf(
						"%s: version unknown — manual check required against %s (CVSS %.1f): %s",
						name, vuln.CVE, vuln.CVSS, vuln.Description,
					),
					File: path,
					Line: lineNum + 1,
					Fix:  fmt.Sprintf("Pin %s to a version > %s to avoid %s", name, vuln.MaxAffected, vuln.CVE),
				})
			} else if semverLE(version, vuln.MaxAffected) {
				findings = append(findings, Finding{
					Rule:     "dep-audit-vulnerable",
					Severity: vuln.Severity,
					Message: fmt.Sprintf(
						"%s==%s is vulnerable (%s, CVSS %.1f): %s",
						name, version, vuln.CVE, vuln.CVSS, vuln.Description,
					),
					File:       path,
					Line:       lineNum + 1,
					Fix:        fmt.Sprintf("Upgrade %s above %s to fix %s", name, vuln.MaxAffected, vuln.CVE),
					CWE:        "CWE-1395",
					References: []string{vuln.CVE},
				})
			}
		}
	}

	return findings
}

// auditPyprojectToml performs a best-effort string scan of pyproject.toml for
// known vulnerable package names. Full TOML parsing is avoided to keep the
// binary dependency-free.
func (d *depAuditor) auditPyprojectToml(path string) []Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var findings []Finding
	lines := strings.Split(string(data), "\n")

	for lineNum, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Strip inline comments.
		if idx := strings.Index(line, " #"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		// Strip surrounding quotes and brackets that appear in TOML arrays.
		line = strings.Trim(line, `"',[]`)

		name, version := parseRequirementsLine(line)
		if name == "" {
			continue
		}

		for _, vuln := range patterns.KnownVulnerablePackages {
			if !strings.EqualFold(vuln.Name, name) {
				continue
			}
			if version == "" {
				findings = append(findings, Finding{
					Rule:     "dep-audit-unknown-version",
					Severity: SeverityWarning,
					Message: fmt.Sprintf(
						"%s: version unknown in pyproject.toml — manual check required against %s (CVSS %.1f): %s",
						name, vuln.CVE, vuln.CVSS, vuln.Description,
					),
					File: path,
					Line: lineNum + 1,
					Fix:  fmt.Sprintf("Pin %s to a version > %s to avoid %s", name, vuln.MaxAffected, vuln.CVE),
				})
			} else if semverLE(version, vuln.MaxAffected) {
				findings = append(findings, Finding{
					Rule:     "dep-audit-vulnerable",
					Severity: vuln.Severity,
					Message: fmt.Sprintf(
						"%s==%s in pyproject.toml is vulnerable (%s, CVSS %.1f): %s",
						name, version, vuln.CVE, vuln.CVSS, vuln.Description,
					),
					File:       path,
					Line:       lineNum + 1,
					Fix:        fmt.Sprintf("Upgrade %s above %s to fix %s", name, vuln.MaxAffected, vuln.CVE),
					CWE:        "CWE-1395",
					References: []string{vuln.CVE},
				})
			}
		}
	}

	return findings
}

// parseRequirementsLine extracts (name, version) from a pip requirement string
// such as "requests==2.28.0", "flask>=2.0", "django~=4.0".
// Returns ("", "") when the line cannot be parsed as a package specifier.
func parseRequirementsLine(line string) (name, version string) {
	// Split on any version operator: ==, >=, <=, ~=, !=, >, <
	ops := []string{"===", "~=", "!=", "==", ">=", "<=", ">", "<"}
	for _, op := range ops {
		if idx := strings.Index(line, op); idx != -1 {
			n := strings.TrimSpace(line[:idx])
			v := strings.TrimSpace(line[idx+len(op):])
			// Version may have extras like "1.2.3,<2.0" — take only the first segment.
			if comma := strings.Index(v, ","); comma != -1 {
				v = strings.TrimSpace(v[:comma])
			}
			return normalizePkgName(n), v
		}
	}
	// No operator — the whole line is a bare package name with no version.
	n := strings.TrimSpace(line)
	if n == "" {
		return "", ""
	}
	return normalizePkgName(n), ""
}

// normalizePkgName lower-cases and replaces underscores/hyphens uniformly so
// that "Requests" == "requests" and "my-pkg" == "my_pkg".
func normalizePkgName(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, "_", "-"))
}

// stripVersionPrefix removes npm semver range prefixes (^, ~, =, >=, <=, >, <).
func stripVersionPrefix(v string) string {
	v = strings.TrimSpace(v)
	// Handle common range operators at the start.
	for _, pfx := range []string{">=", "<=", "~=", "!=", "==", "^", "~", "=", ">", "<"} {
		if strings.HasPrefix(v, pfx) {
			v = strings.TrimSpace(v[len(pfx):])
			break
		}
	}
	// In case of a range like "^1.0.0 || ^2.0.0", take the first token.
	if idx := strings.IndexAny(v, " \t|,"); idx != -1 {
		v = v[:idx]
	}
	return v
}

// semverLE returns true when version a is less than or equal to version b.
// It handles standard semver (1.2.3), date-style versions (2025.12.17), and
// simple integer version strings. Non-parseable segments are compared as
// strings, which gives a reasonable approximation for the CVE database here.
func semverLE(a, b string) bool {
	return semverCompare(a, b) <= 0
}

// semverCompare returns -1, 0, or 1 for a < b, a == b, a > b respectively.
func semverCompare(a, b string) int {
	aParts := splitVersion(a)
	bParts := splitVersion(b)

	// Pad to equal length.
	for len(aParts) < len(bParts) {
		aParts = append(aParts, "0")
	}
	for len(bParts) < len(aParts) {
		bParts = append(bParts, "0")
	}

	for i := range aParts {
		ai, aErr := strconv.Atoi(aParts[i])
		bi, bErr := strconv.Atoi(bParts[i])

		if aErr == nil && bErr == nil {
			if ai < bi {
				return -1
			}
			if ai > bi {
				return 1
			}
		} else {
			// Fall back to lexicographic comparison.
			if aParts[i] < bParts[i] {
				return -1
			}
			if aParts[i] > bParts[i] {
				return 1
			}
		}
	}
	return 0
}

// splitVersion splits a version string on dots and strips pre-release suffixes
// (e.g. "1.2.3-beta" -> ["1", "2", "3"]).
func splitVersion(v string) []string {
	// Strip pre-release/build metadata after a hyphen if the segment begins with a digit.
	if idx := strings.Index(v, "-"); idx != -1 {
		// Only strip if the character after the dash is non-numeric (pre-release label).
		rest := v[idx+1:]
		if len(rest) > 0 {
			if _, err := strconv.Atoi(string(rest[0])); err != nil {
				v = v[:idx]
			}
		}
	}
	parts := strings.Split(v, ".")
	// Trim any trailing empty parts.
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
