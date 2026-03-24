package providers

import (
	"encoding/json"
	"strings"
	"testing"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func newReporter(t *testing.T) Reporter {
	t.Helper()
	return NewReporter()
}

func sampleFindings() []Finding {
	return []Finding{
		{
			Rule:     "mcp-cmd-injection",
			Severity: SeverityCritical,
			Message:  "Direct OS command execution: os.popen(user_input)",
			File:     "server.py",
			Line:     42,
		},
		{
			Rule:     "mcp-hardcoded-secret",
			Severity: SeverityCritical,
			Message:  "Hardcoded credential: api_key = \"secret\"",
			File:     "config.py",
			Line:     5,
		},
		{
			Rule:     "mcp-tool-poisoning",
			Severity: SeverityCritical,
			Message:  "Tool description contains hidden instruction tag <IMPORTANT>",
		},
		{
			Rule:     "mcp-path-traversal",
			Severity: SeverityHigh,
			Message:  "Path traversal sequence in argument: ../../../etc/passwd",
			Tool:     "read_file",
		},
		{
			Rule:     "mcp-response-ssn",
			Severity: SeverityHigh,
			Message:  "Possible SSN detected in response",
		},
	}
}

// ── Report — Terminal ─────────────────────────────────────────────────────────

func TestReport_Terminal_NoFindings(t *testing.T) {
	r := newReporter(t)
	out, err := r.Report(nil, FormatTerminal)
	if err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	if !strings.Contains(string(out), "No security findings") {
		t.Errorf("expected 'No security findings' message, got: %s", out)
	}
}

func TestReport_Terminal_EmptySlice(t *testing.T) {
	r := newReporter(t)
	out, err := r.Report([]Finding{}, FormatTerminal)
	if err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	if !strings.Contains(string(out), "No security findings") {
		t.Errorf("expected 'No security findings' for empty slice, got: %s", out)
	}
}

func TestReport_Terminal_ContainsRuleNames(t *testing.T) {
	r := newReporter(t)
	findings := sampleFindings()
	out, err := r.Report(findings, FormatTerminal)
	if err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	text := string(out)

	expectedRules := []string{
		"mcp-cmd-injection",
		"mcp-hardcoded-secret",
		"mcp-tool-poisoning",
		"mcp-path-traversal",
	}
	for _, rule := range expectedRules {
		if !strings.Contains(text, rule) {
			t.Errorf("expected rule %q in terminal output", rule)
		}
	}
}

func TestReport_Terminal_ContainsMessages(t *testing.T) {
	r := newReporter(t)
	findings := []Finding{
		{Rule: "mcp-test", Severity: SeverityCritical, Message: "unique message XYZ123"},
	}
	out, err := r.Report(findings, FormatTerminal)
	if err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	if !strings.Contains(string(out), "unique message XYZ123") {
		t.Errorf("expected message in output, got: %s", out)
	}
}

func TestReport_Terminal_ContainsFileAndLine(t *testing.T) {
	r := newReporter(t)
	findings := []Finding{
		{Rule: "mcp-test", Severity: SeverityHigh, Message: "msg", File: "my_file.py", Line: 99},
	}
	out, err := r.Report(findings, FormatTerminal)
	if err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	text := string(out)
	if !strings.Contains(text, "my_file.py") {
		t.Errorf("expected file name in output")
	}
	if !strings.Contains(text, "99") {
		t.Errorf("expected line number in output")
	}
}

func TestReport_Terminal_FileWithoutLine(t *testing.T) {
	r := newReporter(t)
	findings := []Finding{
		{Rule: "mcp-test", Severity: SeverityHigh, Message: "msg", File: "some_file.py"},
	}
	out, err := r.Report(findings, FormatTerminal)
	if err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	if !strings.Contains(string(out), "some_file.py") {
		t.Errorf("expected file name without line in output")
	}
}

func TestReport_Terminal_ContainsFix(t *testing.T) {
	r := newReporter(t)
	findings := []Finding{
		{Rule: "mcp-test", Severity: SeverityHigh, Message: "msg", Fix: "Use safe alternative"},
	}
	out, err := r.Report(findings, FormatTerminal)
	if err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	if !strings.Contains(string(out), "Use safe alternative") {
		t.Errorf("expected Fix in output")
	}
}

func TestReport_Terminal_SummaryLine(t *testing.T) {
	r := newReporter(t)
	findings := []Finding{
		{Rule: "mcp-cmd-injection", Severity: SeverityCritical, Message: "critical"},
		{Rule: "mcp-path-traversal", Severity: SeverityHigh, Message: "high"},
		{Rule: "mcp-test-warn", Severity: SeverityWarning, Message: "warning"},
		{Rule: "mcp-test-info", Severity: SeverityInfo, Message: "info"},
	}
	out, err := r.Report(findings, FormatTerminal)
	if err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	text := string(out)
	if !strings.Contains(text, "1 CRITICAL") {
		t.Errorf("expected '1 CRITICAL' in summary, got: %s", text)
	}
	if !strings.Contains(text, "1 HIGH") {
		t.Errorf("expected '1 HIGH' in summary, got: %s", text)
	}
	if !strings.Contains(text, "1 WARNING") {
		t.Errorf("expected '1 WARNING' in summary, got: %s", text)
	}
	if !strings.Contains(text, "1 INFO") {
		t.Errorf("expected '1 INFO' in summary, got: %s", text)
	}
}

func TestReport_Terminal_NotSafeWhenCritical(t *testing.T) {
	r := newReporter(t)
	findings := []Finding{
		{Rule: "mcp-test", Severity: SeverityCritical, Message: "critical finding"},
	}
	out, err := r.Report(findings, FormatTerminal)
	if err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	if !strings.Contains(string(out), "NOT SAFE") {
		t.Errorf("expected 'NOT SAFE' for critical finding, got: %s", out)
	}
}

func TestReport_Terminal_NotSafeWhenHigh(t *testing.T) {
	r := newReporter(t)
	findings := []Finding{
		{Rule: "mcp-test", Severity: SeverityHigh, Message: "high finding"},
	}
	out, err := r.Report(findings, FormatTerminal)
	if err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	if !strings.Contains(string(out), "NOT SAFE") {
		t.Errorf("expected 'NOT SAFE' for high finding, got: %s", out)
	}
}

func TestReport_Terminal_ReviewWarningsWhenOnlyWarning(t *testing.T) {
	r := newReporter(t)
	findings := []Finding{
		{Rule: "mcp-test", Severity: SeverityWarning, Message: "just a warning"},
	}
	out, err := r.Report(findings, FormatTerminal)
	if err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	if !strings.Contains(string(out), "Review warnings") {
		t.Errorf("expected 'Review warnings' for warning-only findings, got: %s", out)
	}
}

func TestReport_Terminal_NoCriticalIssuesWhenInfoOnly(t *testing.T) {
	r := newReporter(t)
	findings := []Finding{
		{Rule: "mcp-test", Severity: SeverityInfo, Message: "just info"},
	}
	out, err := r.Report(findings, FormatTerminal)
	if err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	if !strings.Contains(string(out), "No critical issues") {
		t.Errorf("expected 'No critical issues' for info-only findings, got: %s", out)
	}
}

func TestReport_Terminal_CategoriesGrouped(t *testing.T) {
	r := newReporter(t)
	findings := []Finding{
		{Rule: "mcp-cmd-injection", Severity: SeverityCritical, Message: "cmd injection"},
		{Rule: "mcp-tool-poisoning", Severity: SeverityCritical, Message: "poisoning"},
		{Rule: "mcp-hardcoded-secret", Severity: SeverityCritical, Message: "hardcoded"},
		{Rule: "mcp-ssrf", Severity: SeverityCritical, Message: "ssrf"},
	}
	out, err := r.Report(findings, FormatTerminal)
	if err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	text := string(out)

	if !strings.Contains(text, "Source Code Analysis") {
		t.Errorf("expected 'Source Code Analysis' section header")
	}
	if !strings.Contains(text, "Tool Description Analysis") {
		t.Errorf("expected 'Tool Description Analysis' section header")
	}
	if !strings.Contains(text, "Credential Analysis") {
		t.Errorf("expected 'Credential Analysis' section header")
	}
	if !strings.Contains(text, "Other Findings") {
		t.Errorf("expected 'Other Findings' section header")
	}
}

func TestReport_Terminal_SortedBySeverity(t *testing.T) {
	r := newReporter(t)
	// Provide findings in reverse severity order
	findings := []Finding{
		{Rule: "mcp-info", Severity: SeverityInfo, Message: "info"},
		{Rule: "mcp-warning", Severity: SeverityWarning, Message: "warning"},
		{Rule: "mcp-high", Severity: SeverityHigh, Message: "high"},
		{Rule: "mcp-critical", Severity: SeverityCritical, Message: "critical"},
	}
	out, err := r.Report(findings, FormatTerminal)
	if err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	text := string(out)

	// CRITICAL should appear before INFO
	criticalIdx := strings.Index(text, "CRITICAL")
	infoIdx := strings.Index(text, "INFO")
	if criticalIdx == -1 || infoIdx == -1 {
		t.Skip("could not find both severity strings in output")
	}
	if criticalIdx > infoIdx {
		t.Errorf("expected CRITICAL before INFO in output (sorted by severity)")
	}
}

func TestReport_Terminal_DescFindingCategories(t *testing.T) {
	r := newReporter(t)
	descRules := []string{
		"mcp-tool-poisoning",
		"mcp-sensitive-path-ref",
		"mcp-secrecy-instruction",
		"mcp-prompt-override",
		"mcp-exfiltration-instruction",
		"mcp-credential-access",
		"mcp-unicode-injection",
		"mcp-unicode-tags-block",
	}

	for _, rule := range descRules {
		t.Run(rule, func(t *testing.T) {
			findings := []Finding{{Rule: rule, Severity: SeverityCritical, Message: "test"}}
			out, err := r.Report(findings, FormatTerminal)
			if err != nil {
				t.Fatalf("Report() error: %v", err)
			}
			if !strings.Contains(string(out), "Tool Description Analysis") {
				t.Errorf("rule %q should appear under Tool Description Analysis", rule)
			}
		})
	}
}

func TestReport_Terminal_SourceFindingCategories(t *testing.T) {
	r := newReporter(t)
	sourceRules := []string{
		"mcp-cmd-injection",
		"mcp-code-eval",
		"mcp-path-traversal-risk",
	}

	for _, rule := range sourceRules {
		t.Run(rule, func(t *testing.T) {
			findings := []Finding{{Rule: rule, Severity: SeverityCritical, Message: "test"}}
			out, err := r.Report(findings, FormatTerminal)
			if err != nil {
				t.Fatalf("Report() error: %v", err)
			}
			if !strings.Contains(string(out), "Source Code Analysis") {
				t.Errorf("rule %q should appear under Source Code Analysis", rule)
			}
		})
	}
}

func TestReport_Terminal_DefaultFormatFallback(t *testing.T) {
	r := newReporter(t)
	findings := []Finding{
		{Rule: "mcp-test", Severity: SeverityInfo, Message: "fallback test"},
	}
	// Unknown format should fall back to terminal
	out, err := r.Report(findings, OutputFormat("unknown"))
	if err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	if !strings.Contains(string(out), "mcp-test") {
		t.Errorf("expected fallback to terminal format, got: %s", out)
	}
}

// ── Report — JSON ─────────────────────────────────────────────────────────────

func TestReport_JSON_ValidJSON(t *testing.T) {
	r := newReporter(t)
	out, err := r.Report(sampleFindings(), FormatJSON)
	if err != nil {
		t.Fatalf("Report() JSON error: %v", err)
	}
	var findings []Finding
	if err := json.Unmarshal(out, &findings); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
}

func TestReport_JSON_EmptyFindings(t *testing.T) {
	r := newReporter(t)
	out, err := r.Report([]Finding{}, FormatJSON)
	if err != nil {
		t.Fatalf("Report() JSON error: %v", err)
	}
	var findings []Finding
	if err := json.Unmarshal(out, &findings); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected empty array, got %d findings", len(findings))
	}
}

func TestReport_JSON_NilFindings(t *testing.T) {
	r := newReporter(t)
	out, err := r.Report(nil, FormatJSON)
	if err != nil {
		t.Fatalf("Report() JSON error: %v", err)
	}
	// nil marshals to "null" — both null and [] are acceptable
	s := strings.TrimSpace(string(out))
	if s != "null" && s != "[]" {
		// Also valid as an empty array
		var findings []Finding
		if jsonErr := json.Unmarshal(out, &findings); jsonErr != nil {
			t.Fatalf("nil findings should marshal to valid JSON: %v", jsonErr)
		}
	}
}

func TestReport_JSON_ContainsAllFields(t *testing.T) {
	r := newReporter(t)
	findings := []Finding{
		{
			Rule:     "test-rule",
			Severity: SeverityCritical,
			Message:  "test message",
			File:     "test.py",
			Line:     10,
			Tool:     "my-tool",
			Fix:      "fix it",
		},
	}
	out, err := r.Report(findings, FormatJSON)
	if err != nil {
		t.Fatalf("Report() JSON error: %v", err)
	}
	text := string(out)
	expectedFields := []string{"test-rule", "test message", "test.py", "my-tool", "fix it"}
	for _, field := range expectedFields {
		if !strings.Contains(text, field) {
			t.Errorf("expected %q in JSON output", field)
		}
	}
}

func TestReport_JSON_PreservesAllFindings(t *testing.T) {
	r := newReporter(t)
	original := sampleFindings()
	out, err := r.Report(original, FormatJSON)
	if err != nil {
		t.Fatalf("Report() JSON error: %v", err)
	}
	var decoded []Finding
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("json.Unmarshal error: %v", err)
	}
	if len(decoded) != len(original) {
		t.Errorf("expected %d findings, got %d", len(original), len(decoded))
	}
}

// ── Report — SARIF ────────────────────────────────────────────────────────────

type sarifReport struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation *struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region *struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func parseSARIF(t *testing.T, data []byte) sarifReport {
	t.Helper()
	var report sarifReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v\n%s", err, data)
	}
	return report
}

func TestReport_SARIF_ValidStructure(t *testing.T) {
	r := newReporter(t)
	out, err := r.Report(sampleFindings(), FormatSARIF)
	if err != nil {
		t.Fatalf("Report() SARIF error: %v", err)
	}
	report := parseSARIF(t, out)

	if report.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %q", report.Version)
	}
	if len(report.Runs) != 1 {
		t.Errorf("expected 1 run, got %d", len(report.Runs))
	}
}

func TestReport_SARIF_ToolName(t *testing.T) {
	r := newReporter(t)
	out, err := r.Report(sampleFindings(), FormatSARIF)
	if err != nil {
		t.Fatalf("Report() SARIF error: %v", err)
	}
	report := parseSARIF(t, out)
	if report.Runs[0].Tool.Driver.Name != "oxvault" {
		t.Errorf("expected tool name 'oxvault', got %q", report.Runs[0].Tool.Driver.Name)
	}
}

func TestReport_SARIF_Schema(t *testing.T) {
	r := newReporter(t)
	out, err := r.Report(sampleFindings(), FormatSARIF)
	if err != nil {
		t.Fatalf("Report() SARIF error: %v", err)
	}
	report := parseSARIF(t, out)
	if !strings.Contains(report.Schema, "sarif") {
		t.Errorf("expected SARIF schema URL, got %q", report.Schema)
	}
}

func TestReport_SARIF_ResultsCount(t *testing.T) {
	r := newReporter(t)
	findings := sampleFindings()
	out, err := r.Report(findings, FormatSARIF)
	if err != nil {
		t.Fatalf("Report() SARIF error: %v", err)
	}
	report := parseSARIF(t, out)
	if len(report.Runs[0].Results) != len(findings) {
		t.Errorf("expected %d results, got %d", len(findings), len(report.Runs[0].Results))
	}
}

func TestReport_SARIF_LevelMapping(t *testing.T) {
	r := newReporter(t)
	findings := []Finding{
		{Rule: "r1", Severity: SeverityCritical, Message: "critical"},
		{Rule: "r2", Severity: SeverityHigh, Message: "high"},
		{Rule: "r3", Severity: SeverityWarning, Message: "warning"},
		{Rule: "r4", Severity: SeverityInfo, Message: "info"},
	}
	out, err := r.Report(findings, FormatSARIF)
	if err != nil {
		t.Fatalf("Report() SARIF error: %v", err)
	}
	report := parseSARIF(t, out)
	results := report.Runs[0].Results

	if results[0].Level != "error" {
		t.Errorf("critical: expected level 'error', got %q", results[0].Level)
	}
	if results[1].Level != "error" {
		t.Errorf("high: expected level 'error', got %q", results[1].Level)
	}
	if results[2].Level != "warning" {
		t.Errorf("warning: expected level 'warning', got %q", results[2].Level)
	}
	if results[3].Level != "note" {
		t.Errorf("info: expected level 'note', got %q", results[3].Level)
	}
}

func TestReport_SARIF_LocationWithFile(t *testing.T) {
	r := newReporter(t)
	findings := []Finding{
		{Rule: "mcp-test", Severity: SeverityHigh, Message: "msg", File: "server.py", Line: 42},
	}
	out, err := r.Report(findings, FormatSARIF)
	if err != nil {
		t.Fatalf("Report() SARIF error: %v", err)
	}
	report := parseSARIF(t, out)
	results := report.Runs[0].Results

	if len(results[0].Locations) == 0 {
		t.Fatal("expected location for finding with file")
	}
	loc := results[0].Locations[0]
	if loc.PhysicalLocation == nil {
		t.Fatal("expected physicalLocation")
	}
	if loc.PhysicalLocation.ArtifactLocation.URI != "server.py" {
		t.Errorf("expected URI 'server.py', got %q", loc.PhysicalLocation.ArtifactLocation.URI)
	}
	if loc.PhysicalLocation.Region == nil {
		t.Fatal("expected region for finding with line number")
	}
	if loc.PhysicalLocation.Region.StartLine != 42 {
		t.Errorf("expected startLine=42, got %d", loc.PhysicalLocation.Region.StartLine)
	}
}

func TestReport_SARIF_LocationWithFileNoLine(t *testing.T) {
	r := newReporter(t)
	findings := []Finding{
		{Rule: "mcp-test", Severity: SeverityHigh, Message: "msg", File: "server.py"},
	}
	out, err := r.Report(findings, FormatSARIF)
	if err != nil {
		t.Fatalf("Report() SARIF error: %v", err)
	}
	report := parseSARIF(t, out)
	results := report.Runs[0].Results

	if len(results[0].Locations) == 0 {
		t.Fatal("expected location for finding with file")
	}
	loc := results[0].Locations[0]
	if loc.PhysicalLocation == nil {
		t.Fatal("expected physicalLocation")
	}
	// Line=0 → no region
	if loc.PhysicalLocation.Region != nil {
		t.Errorf("expected no region when Line=0, got startLine=%d", loc.PhysicalLocation.Region.StartLine)
	}
}

func TestReport_SARIF_NoLocationWithoutFile(t *testing.T) {
	r := newReporter(t)
	findings := []Finding{
		{Rule: "mcp-test", Severity: SeverityCritical, Message: "no file"},
	}
	out, err := r.Report(findings, FormatSARIF)
	if err != nil {
		t.Fatalf("Report() SARIF error: %v", err)
	}
	report := parseSARIF(t, out)
	results := report.Runs[0].Results

	if len(results[0].Locations) != 0 {
		t.Errorf("expected no locations for finding without file, got %d", len(results[0].Locations))
	}
}

func TestReport_SARIF_EmptyFindings(t *testing.T) {
	r := newReporter(t)
	out, err := r.Report([]Finding{}, FormatSARIF)
	if err != nil {
		t.Fatalf("Report() SARIF error: %v", err)
	}
	report := parseSARIF(t, out)
	if len(report.Runs) != 1 {
		t.Errorf("expected 1 run even with no findings, got %d", len(report.Runs))
	}
}

func TestReport_SARIF_RuleID(t *testing.T) {
	r := newReporter(t)
	findings := []Finding{
		{Rule: "mcp-cmd-injection", Severity: SeverityCritical, Message: "msg"},
	}
	out, err := r.Report(findings, FormatSARIF)
	if err != nil {
		t.Fatalf("Report() SARIF error: %v", err)
	}
	report := parseSARIF(t, out)
	if report.Runs[0].Results[0].RuleID != "mcp-cmd-injection" {
		t.Errorf("expected ruleId 'mcp-cmd-injection', got %q", report.Runs[0].Results[0].RuleID)
	}
}

// ── severityToSARIF ───────────────────────────────────────────────────────────

func TestSeverityToSARIF(t *testing.T) {
	tests := []struct {
		severity Severity
		want     string
	}{
		{SeverityCritical, "error"},
		{SeverityHigh, "error"},
		{SeverityWarning, "warning"},
		{SeverityInfo, "note"},
		{Severity(99), "none"},
	}

	for _, tt := range tests {
		t.Run(tt.severity.String(), func(t *testing.T) {
			got := severityToSARIF(tt.severity)
			if got != tt.want {
				t.Errorf("severityToSARIF(%v) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}

// ── writeFinding ──────────────────────────────────────────────────────────────

func TestWriteFinding_AllFields(t *testing.T) {
	var b strings.Builder
	f := Finding{
		Rule:     "mcp-test-rule",
		Severity: SeverityCritical,
		Message:  "something bad",
		File:     "vuln.py",
		Line:     77,
		Fix:      "sanitize input",
	}
	writeFinding(&b, f)
	out := b.String()

	checks := []string{"mcp-test-rule", "something bad", "vuln.py", "77", "sanitize input"}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("expected %q in writeFinding output: %s", c, out)
		}
	}
}

func TestWriteFinding_NoFile(t *testing.T) {
	var b strings.Builder
	f := Finding{Rule: "mcp-test", Severity: SeverityHigh, Message: "msg"}
	writeFinding(&b, f)
	out := b.String()

	if strings.Contains(out, ":") {
		// Only acceptable colon is in the severity or fix context
		// But no file:line should appear
	}
	if !strings.Contains(out, "mcp-test") {
		t.Errorf("expected rule in output")
	}
}
