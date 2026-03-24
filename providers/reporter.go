package providers

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type reporter struct{}

func NewReporter() Reporter {
	return &reporter{}
}

func (r *reporter) Report(findings []Finding, format OutputFormat) ([]byte, error) {
	switch format {
	case FormatTerminal:
		return r.reportTerminal(findings)
	case FormatJSON:
		return r.reportJSON(findings)
	case FormatSARIF:
		return r.reportSARIF(findings)
	default:
		return r.reportTerminal(findings)
	}
}

func (r *reporter) reportTerminal(findings []Finding) ([]byte, error) {
	if len(findings) == 0 {
		return []byte("\n  ✓ No security findings.\n\n"), nil
	}

	// Sort by severity (critical first)
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Severity > findings[j].Severity
	})

	// Group by category
	var b strings.Builder

	// Count by severity
	counts := map[Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	// Source code findings
	var sourceFindings, descFindings, credFindings, otherFindings []Finding
	for _, f := range findings {
		switch {
		case strings.HasPrefix(f.Rule, "mcp-cmd-") || strings.HasPrefix(f.Rule, "mcp-code-") ||
			strings.HasPrefix(f.Rule, "mcp-path-traversal-risk"):
			sourceFindings = append(sourceFindings, f)
		case strings.HasPrefix(f.Rule, "mcp-tool-") || strings.HasPrefix(f.Rule, "mcp-sensitive-path") ||
			strings.HasPrefix(f.Rule, "mcp-secrecy") || strings.HasPrefix(f.Rule, "mcp-prompt-") ||
			strings.HasPrefix(f.Rule, "mcp-exfiltration") || strings.HasPrefix(f.Rule, "mcp-credential-access") ||
			strings.HasPrefix(f.Rule, "mcp-unicode"):
			descFindings = append(descFindings, f)
		case strings.HasPrefix(f.Rule, "mcp-hardcoded"):
			credFindings = append(credFindings, f)
		default:
			otherFindings = append(otherFindings, f)
		}
	}

	if len(sourceFindings) > 0 {
		b.WriteString("\n  ── Source Code Analysis ──────────────────────────────────\n\n")
		for _, f := range sourceFindings {
			writeFinding(&b, f)
		}
	}

	if len(descFindings) > 0 {
		b.WriteString("\n  ── Tool Description Analysis ─────────────────────────────\n\n")
		for _, f := range descFindings {
			writeFinding(&b, f)
		}
	}

	if len(credFindings) > 0 {
		b.WriteString("\n  ── Credential Analysis ───────────────────────────────────\n\n")
		for _, f := range credFindings {
			writeFinding(&b, f)
		}
	}

	if len(otherFindings) > 0 {
		b.WriteString("\n  ── Other Findings ────────────────────────────────────────\n\n")
		for _, f := range otherFindings {
			writeFinding(&b, f)
		}
	}

	// Summary
	b.WriteString("\n  ── Summary ───────────────────────────────────────────────\n\n")
	b.WriteString(fmt.Sprintf("  %d CRITICAL · %d HIGH · %d WARNING · %d INFO\n\n",
		counts[SeverityCritical], counts[SeverityHigh], counts[SeverityWarning], counts[SeverityInfo]))

	if counts[SeverityCritical] > 0 || counts[SeverityHigh] > 0 {
		b.WriteString("  This server is NOT SAFE to install.\n\n")
	} else if counts[SeverityWarning] > 0 {
		b.WriteString("  Review warnings before installing.\n\n")
	} else {
		b.WriteString("  No critical issues found.\n\n")
	}

	return []byte(b.String()), nil
}

func writeFinding(b *strings.Builder, f Finding) {
	b.WriteString(fmt.Sprintf("  %-8s  %s\n", f.Severity, f.Rule))
	if f.File != "" {
		if f.Line > 0 {
			b.WriteString(fmt.Sprintf("  %s:%d\n", f.File, f.Line))
		} else {
			b.WriteString(fmt.Sprintf("  %s\n", f.File))
		}
	}
	b.WriteString(fmt.Sprintf("  %s\n", f.Message))
	if f.Fix != "" {
		b.WriteString(fmt.Sprintf("  Fix: %s\n", f.Fix))
	}
	b.WriteString("\n")
}

func (r *reporter) reportJSON(findings []Finding) ([]byte, error) {
	return json.MarshalIndent(findings, "", "  ")
}

// SARIF 2.1.0 output for CI/CD integration
func (r *reporter) reportSARIF(findings []Finding) ([]byte, error) {
	type sarifMessage struct {
		Text string `json:"text"`
	}
	type sarifLocation struct {
		PhysicalLocation *struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region *struct {
				StartLine int `json:"startLine"`
			} `json:"region,omitempty"`
		} `json:"physicalLocation,omitempty"`
	}
	type sarifResult struct {
		RuleID    string          `json:"ruleId"`
		Level     string          `json:"level"`
		Message   sarifMessage    `json:"message"`
		Locations []sarifLocation `json:"locations,omitempty"`
	}
	type sarifRun struct {
		Tool struct {
			Driver struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"driver"`
		} `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type sarifReport struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}

	var results []sarifResult
	for _, f := range findings {
		result := sarifResult{
			RuleID:  f.Rule,
			Level:   severityToSARIF(f.Severity),
			Message: sarifMessage{Text: f.Message},
		}
		if f.File != "" {
			loc := sarifLocation{}
			loc.PhysicalLocation = &struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
				Region *struct {
					StartLine int `json:"startLine"`
				} `json:"region,omitempty"`
			}{}
			loc.PhysicalLocation.ArtifactLocation.URI = f.File
			if f.Line > 0 {
				loc.PhysicalLocation.Region = &struct {
					StartLine int `json:"startLine"`
				}{StartLine: f.Line}
			}
			result.Locations = []sarifLocation{loc}
		}
		results = append(results, result)
	}

	report := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
	}
	run := sarifRun{Results: results}
	run.Tool.Driver.Name = "oxvault"
	run.Tool.Driver.Version = "0.1.0"
	report.Runs = []sarifRun{run}

	return json.MarshalIndent(report, "", "  ")
}

func severityToSARIF(s Severity) string {
	switch s {
	case SeverityCritical:
		return "error"
	case SeverityHigh:
		return "error"
	case SeverityWarning:
		return "warning"
	case SeverityInfo:
		return "note"
	default:
		return "none"
	}
}
