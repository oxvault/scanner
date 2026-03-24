package providers

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/fatih/color"
)

// Color and style definitions — declared as package-level vars so tests can
// call color.NoColor = true before constructing a reporter and get plain text.
var (
	colorCritical = color.New(color.FgRed, color.Bold)
	colorHigh     = color.New(color.FgYellow, color.Bold)
	colorWarning  = color.New(color.FgMagenta)
	colorInfo     = color.New(color.FgCyan)
	colorPass     = color.New(color.FgGreen)
	colorDim      = color.New(color.Faint)
	colorBold     = color.New(color.Bold)
	colorHeader   = color.New(color.Bold)
	colorFix      = color.New(color.FgGreen, color.Faint)
)

// severityIcon maps a Severity to its Unicode icon.
func severityIcon(s Severity) string {
	switch s {
	case SeverityCritical:
		return colorCritical.Sprint("✗")
	case SeverityHigh:
		return colorHigh.Sprint("⚠")
	case SeverityWarning:
		return colorWarning.Sprint("●")
	case SeverityInfo:
		return colorInfo.Sprint("ℹ")
	default:
		return "·"
	}
}

// severityLabel returns a colored, fixed-width severity badge.
func severityLabel(s Severity) string {
	switch s {
	case SeverityCritical:
		return colorCritical.Sprintf("%-8s", "CRITICAL")
	case SeverityHigh:
		return colorHigh.Sprintf("%-8s", "HIGH")
	case SeverityWarning:
		return colorWarning.Sprintf("%-8s", "WARNING")
	case SeverityInfo:
		return colorInfo.Sprintf("%-8s", "INFO")
	default:
		return fmt.Sprintf("%-8s", s.String())
	}
}

// sectionDivider renders a colored section header line.
// e.g. "  ── Source Code ──────────────────────────────────────────"
func sectionDivider(title string) string {
	const totalWidth = 60
	prefix := "  ── "
	suffix := " "
	fill := strings.Repeat("─", totalWidth-len(prefix)-len(title)-len(suffix))
	return colorHeader.Sprintf("%s%s%s%s", prefix, title, suffix, fill)
}

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
		line := fmt.Sprintf("\n  %s No security findings.\n\n", colorPass.Sprint("✓"))
		return []byte(line), nil
	}

	// Sort by severity (critical first)
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Severity > findings[j].Severity
	})

	var b strings.Builder

	// Count by severity
	counts := map[Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	// Group by category
	var sourceFindings, hookFindings, descFindings, credFindings, otherFindings []Finding
	for _, f := range findings {
		switch {
		case strings.HasPrefix(f.Rule, "mcp-cmd-") || strings.HasPrefix(f.Rule, "mcp-code-") ||
			strings.HasPrefix(f.Rule, "mcp-path-traversal-risk"):
			sourceFindings = append(sourceFindings, f)
		case strings.HasPrefix(f.Rule, "mcp-install-hook-"):
			hookFindings = append(hookFindings, f)
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
		b.WriteString("\n")
		b.WriteString(sectionDivider("Source Code Analysis"))
		b.WriteString("\n\n")
		for _, f := range sourceFindings {
			writeFinding(&b, f)
		}
	}

	if len(hookFindings) > 0 {
		b.WriteString("\n")
		b.WriteString(sectionDivider("Install Hook Analysis"))
		b.WriteString("\n\n")
		for _, f := range hookFindings {
			writeFinding(&b, f)
		}
	}

	if len(descFindings) > 0 {
		b.WriteString("\n")
		b.WriteString(sectionDivider("Tool Description Analysis"))
		b.WriteString("\n\n")
		for _, f := range descFindings {
			writeFinding(&b, f)
		}
	}

	if len(credFindings) > 0 {
		b.WriteString("\n")
		b.WriteString(sectionDivider("Credential Analysis"))
		b.WriteString("\n\n")
		for _, f := range credFindings {
			writeFinding(&b, f)
		}
	}

	if len(otherFindings) > 0 {
		b.WriteString("\n")
		b.WriteString(sectionDivider("Other Findings"))
		b.WriteString("\n\n")
		for _, f := range otherFindings {
			writeFinding(&b, f)
		}
	}

	// Summary section
	b.WriteString("\n")
	b.WriteString(sectionDivider("Summary"))
	b.WriteString("\n\n")

	summaryParts := []string{
		colorCritical.Sprintf("%d CRITICAL", counts[SeverityCritical]),
		colorHigh.Sprintf("%d HIGH", counts[SeverityHigh]),
		colorWarning.Sprintf("%d WARNING", counts[SeverityWarning]),
		colorInfo.Sprintf("%d INFO", counts[SeverityInfo]),
	}
	b.WriteString("  " + strings.Join(summaryParts, colorDim.Sprint(" · ")) + "\n\n")

	if counts[SeverityCritical] > 0 || counts[SeverityHigh] > 0 {
		fmt.Fprintf(&b, "  %s %s\n\n",
			colorCritical.Sprint("✗"),
			colorCritical.Sprint("This server is NOT SAFE to install."))
	} else if counts[SeverityWarning] > 0 {
		fmt.Fprintf(&b, "  %s %s\n\n",
			colorWarning.Sprint("●"),
			colorWarning.Sprint("Review warnings before installing."))
	} else {
		fmt.Fprintf(&b, "  %s %s\n\n",
			colorPass.Sprint("✓"),
			colorPass.Sprint("No critical issues found."))
	}

	return []byte(b.String()), nil
}

// writeFinding writes a single colored finding block to the builder.
func writeFinding(b *strings.Builder, f Finding) {
	// Icon + severity badge + rule name (+ CWE when available)
	icon := severityIcon(f.Severity)
	badge := severityLabel(f.Severity)
	ruleName := f.Rule
	if f.CWE != "" {
		ruleName = f.Rule + " (" + f.CWE + ")"
	}
	rule := colorBold.Sprint(ruleName)
	fmt.Fprintf(b, "  %s %s %s\n", icon, badge, rule)

	// File location
	if f.File != "" {
		if f.Line > 0 {
			fmt.Fprintf(b, "    %s\n", colorDim.Sprintf("%s:%d", f.File, f.Line))
		} else {
			fmt.Fprintf(b, "    %s\n", colorDim.Sprint(f.File))
		}
	}

	// Tool name (for description findings)
	if f.Tool != "" && f.File == "" {
		fmt.Fprintf(b, "    %s\n", colorDim.Sprintf("Tool: %s", f.Tool))
	}

	// Message
	fmt.Fprintf(b, "    %s\n", f.Message)

	// Fix hint
	if f.Fix != "" {
		fmt.Fprintf(b, "    %s %s\n", colorFix.Sprint("Fix:"), colorFix.Sprint(f.Fix))
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
	type sarifProperties struct {
		CWE string `json:"cwe,omitempty"`
	}
	type sarifResult struct {
		RuleID      string          `json:"ruleId"`
		Level       string          `json:"level"`
		Message     sarifMessage    `json:"message"`
		Locations   []sarifLocation `json:"locations,omitempty"`
		Properties  *sarifProperties `json:"properties,omitempty"`
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
		if f.CWE != "" {
			result.Properties = &sarifProperties{CWE: f.CWE}
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
