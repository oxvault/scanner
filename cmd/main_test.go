package main

import (
	"reflect"
	"testing"

	"github.com/oxvault/scanner/providers"
)

// TestArtifactTypeFor pins the resolver-kind → dashboard-artifact-type
// mapping. Regressions here ship as "every model tagged MCP on the
// dashboard" — silent until someone notices the inventory list.
func TestArtifactTypeFor(t *testing.T) {
	tests := []struct {
		name string
		pkg  *providers.ResolvedPackage
		want string
	}{
		{name: "nil package defaults to mcp", pkg: nil, want: "mcp"},
		{name: "zero-value Kind defaults to mcp", pkg: &providers.ResolvedPackage{}, want: "mcp"},
		{name: "explicit MCPServer", pkg: &providers.ResolvedPackage{Kind: providers.KindMCPServer}, want: "mcp"},
		{name: "ModelArtifact (single file)", pkg: &providers.ResolvedPackage{Kind: providers.KindModelArtifact}, want: "model"},
		{name: "ModelDirectory (HF download)", pkg: &providers.ResolvedPackage{Kind: providers.KindModelDirectory}, want: "model"},
		{name: "RAGCorpus", pkg: &providers.ResolvedPackage{Kind: providers.KindRAGCorpus}, want: "rag"},
		{name: "unknown future kind falls back to mcp", pkg: &providers.ResolvedPackage{Kind: providers.PackageKind("future-unknown")}, want: "mcp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := artifactTypeFor(tt.pkg)
			if got != tt.want {
				t.Errorf("artifactTypeFor(%+v) = %q, want %q", tt.pkg, got, tt.want)
			}
		})
	}
}

func TestSplitAndTrimCSV(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "empty", in: "", want: nil},
		{name: "whitespace only", in: "   ", want: nil},
		{name: "single", in: "https://accounts.google.com", want: []string{"https://accounts.google.com"}},
		{name: "multi", in: "a,b,c", want: []string{"a", "b", "c"}},
		{name: "trim each", in: " a , b , c ", want: []string{"a", "b", "c"}},
		{name: "leading comma", in: ",https://oidc.example", want: []string{"https://oidc.example"}},
		{name: "trailing comma", in: "https://oidc.example,", want: []string{"https://oidc.example"}},
		{name: "double comma", in: "a,,b", want: []string{"a", "b"}},
		{name: "all empty entries", in: " , ,  ,", want: nil},
		{name: "real-world issuers", in: "https://accounts.google.com, https://token.actions.githubusercontent.com", want: []string{"https://accounts.google.com", "https://token.actions.githubusercontent.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitAndTrimCSV(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitAndTrimCSV(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestDeriveArtifactName: remote-scheme targets keep their scheme (it's the agent's rescan key); local paths reduce to basename.
func TestDeriveArtifactName(t *testing.T) {
	tests := map[string]string{
		"github:oxvault/scanner": "github:oxvault/scanner",
		"github:oxvault/scanner/examples/vulnerable-servers/tool-poisoning": "github:oxvault/scanner/examples/vulnerable-servers/tool-poisoning",
		"github:owner/repo@v1.2.3": "github:owner/repo@v1.2.3",
		"hf:org/model":             "hf:org/model",
		"@company/mcp-server":      "@company/mcp-server",
		"./node_modules/asana-mcp": "asana-mcp",
		"/tmp/models/model.pkl":    "model.pkl",
	}
	for target, want := range tests {
		if got := deriveArtifactName(target); got != want {
			t.Errorf("deriveArtifactName(%q) = %q; want %q", target, got, want)
		}
	}
}
