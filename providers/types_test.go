package providers

import (
	"testing"
)

func TestSeverityString(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		want     string
	}{
		{"info", SeverityInfo, "INFO"},
		{"warning", SeverityWarning, "WARNING"},
		{"high", SeverityHigh, "HIGH"},
		{"critical", SeverityCritical, "CRITICAL"},
		{"unknown negative", Severity(-1), "UNKNOWN"},
		{"unknown out of range", Severity(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.severity.String()
			if got != tt.want {
				t.Errorf("Severity(%d).String() = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}

func TestSeverityOrdering(t *testing.T) {
	// SeverityCritical must be the highest value (used for sort order in reporter)
	if SeverityCritical <= SeverityHigh {
		t.Error("SeverityCritical must be > SeverityHigh")
	}
	if SeverityHigh <= SeverityWarning {
		t.Error("SeverityHigh must be > SeverityWarning")
	}
	if SeverityWarning <= SeverityInfo {
		t.Error("SeverityWarning must be > SeverityInfo")
	}
}

func TestRiskTierString(t *testing.T) {
	tests := []struct {
		name string
		tier RiskTier
		want string
	}{
		{"low", RiskTierLow, "LOW"},
		{"medium", RiskTierMedium, "MEDIUM"},
		{"high", RiskTierHigh, "HIGH"},
		{"critical", RiskTierCritical, "CRITICAL"},
		{"unknown negative", RiskTier(-1), "UNKNOWN"},
		{"unknown out of range", RiskTier(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tier.String()
			if got != tt.want {
				t.Errorf("RiskTier(%d).String() = %q, want %q", tt.tier, got, tt.want)
			}
		})
	}
}

func TestOutputFormatConstants(t *testing.T) {
	if FormatTerminal != "terminal" {
		t.Errorf("FormatTerminal = %q, want %q", FormatTerminal, "terminal")
	}
	if FormatSARIF != "sarif" {
		t.Errorf("FormatSARIF = %q, want %q", FormatSARIF, "sarif")
	}
	if FormatJSON != "json" {
		t.Errorf("FormatJSON = %q, want %q", FormatJSON, "json")
	}
}

func TestLanguageConstants(t *testing.T) {
	langs := []struct {
		lang Language
		want string
	}{
		{LangPython, "python"},
		{LangJavaScript, "javascript"},
		{LangTypeScript, "typescript"},
		{LangGo, "go"},
		{LangUnknown, "unknown"},
	}
	for _, tt := range langs {
		if string(tt.lang) != tt.want {
			t.Errorf("Language constant = %q, want %q", tt.lang, tt.want)
		}
	}
}

func TestFindingStruct(t *testing.T) {
	f := Finding{
		Rule:     "mcp-test-rule",
		Severity: SeverityCritical,
		Message:  "test message",
		File:     "test.py",
		Line:     42,
		Tool:     "my-tool",
		Fix:      "remove it",
	}

	if f.Rule != "mcp-test-rule" {
		t.Errorf("unexpected Rule: %s", f.Rule)
	}
	if f.Severity != SeverityCritical {
		t.Errorf("unexpected Severity: %v", f.Severity)
	}
	if f.Line != 42 {
		t.Errorf("unexpected Line: %d", f.Line)
	}
}

func TestMCPToolStruct(t *testing.T) {
	tool := MCPTool{
		Name:        "search",
		Title:       "Search Tool",
		Description: "Searches files",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{"type": "string"},
			},
		},
		Annotations: map[string]any{
			"author": "test",
		},
	}

	if tool.Name != "search" {
		t.Errorf("unexpected Name: %s", tool.Name)
	}
	if tool.InputSchema == nil {
		t.Error("InputSchema should not be nil")
	}
}

func TestPinDiffStruct(t *testing.T) {
	pd := PinDiff{
		ToolName:    "my-tool",
		OldHash:     "abc123",
		NewHash:     "def456",
		Changed:     true,
		Description: "something changed",
	}

	if !pd.Changed {
		t.Error("PinDiff.Changed should be true")
	}
	if pd.OldHash == pd.NewHash {
		t.Error("OldHash and NewHash should differ")
	}
}

func TestEgressFindingStruct(t *testing.T) {
	ef := EgressFinding{
		File:        "server.py",
		Line:        10,
		Destination: "http://evil.example.com",
		Method:      "requests.post",
		ToolName:    "exfil-tool",
	}

	if ef.File != "server.py" {
		t.Errorf("unexpected File: %s", ef.File)
	}
	if ef.Line != 10 {
		t.Errorf("unexpected Line: %d", ef.Line)
	}
}
