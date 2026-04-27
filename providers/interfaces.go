package providers

import "time"

// Resolver downloads/clones MCP server packages to a local path.
// Supports: local paths, npm packages, GitHub repos.
type Resolver interface {
	Resolve(target string) (*ResolvedPackage, error)
}

// NetProbe spawns an MCP server in a network-monitored environment and
// detects actual outbound connections made during a live tool-call session.
type NetProbe interface {
	Probe(cmd string, args []string, timeout time.Duration) ([]NetActivity, error)
}

// MCPClient connects to MCP servers via JSON-RPC over stdio.
type MCPClient interface {
	Connect(cmd string, args []string) (*MCPSession, error)
	ListTools(session *MCPSession) ([]MCPTool, error)
	Close(session *MCPSession) error
}

// RuleMatcher scans text for security patterns.
// Used by both scanner (scan-time) and gateway (runtime).
type RuleMatcher interface {
	ScanDescription(description string) []Finding
	ScanArguments(args map[string]any) []Finding
	ScanResponse(response string) []Finding
	ClassifyTool(tool MCPTool, sourceCode string) RiskTier
}

// SASTAnalyzer performs static analysis on MCP server source code.
type SASTAnalyzer interface {
	AnalyzeFile(path string, lang Language) []Finding
	AnalyzeDirectory(dir string) []Finding
	DetectEgress(dir string) []EgressFinding
}

// HookAnalyzer scans npm/PyPI package install scripts for malicious patterns.
// It provides precise, severity-graded findings for install lifecycle hooks
// (preinstall, install, postinstall, prepare) and their referenced script files.
type HookAnalyzer interface {
	AnalyzeDirectory(dir string) []Finding
}

// Reporter formats findings for output.
type Reporter interface {
	Report(findings []Finding, format OutputFormat) ([]byte, error)
}

// PinStore persists and compares tool description hashes.
type PinStore interface {
	Pin(tools []MCPTool) error
	Check(tools []MCPTool) ([]PinDiff, error)
	Load() (map[string]string, error)
}

// ── AIBOM (AI Bill of Materials) interfaces ──────────────────────────────────
//
// These contracts power the AIBOM module: ML model artifacts (pickle, ONNX,
// safetensors, model cards, signatures) are inspected for unsafe deserialization,
// malformed graphs, missing provenance, and unsigned artifacts. The AIBOMComposer
// orchestrates the sub-providers by dispatching files to the correct analyzer
// based on ArtifactFormat.

// PickleAnalyzer inspects Python pickle artifacts (.pkl, .pt, .pth, .bin)
// for unsafe opcodes (REDUCE / GLOBAL / BUILD) and known-malicious payloads.
type PickleAnalyzer interface {
	// AnalyzeFile inspects a single pickle file at path.
	AnalyzeFile(path string) []Finding
	// AnalyzeDirectory walks dir and analyzes every pickle file it finds.
	AnalyzeDirectory(dir string) []Finding
}

// ONNXValidator verifies the structural integrity of ONNX protobuf graphs
// and flags suspicious operators or external-data references.
type ONNXValidator interface {
	// ValidateFile inspects a single .onnx file at path.
	ValidateFile(path string) []Finding
	// ValidateDirectory walks dir and validates every .onnx file it finds.
	ValidateDirectory(dir string) []Finding
}

// SafetensorsValidator verifies the header structure of safetensors files
// and flags malformed offsets, oversized headers, or shape mismatches.
type SafetensorsValidator interface {
	// ValidateFile inspects a single .safetensors file at path.
	ValidateFile(path string) []Finding
	// ValidateDirectory walks dir and validates every .safetensors file.
	ValidateDirectory(dir string) []Finding
}

// ModelCardChecker inspects model cards (README.md, MODEL_CARD.md) for the
// presence of provenance, license, intended-use, and bias-evaluation sections.
type ModelCardChecker interface {
	// CheckFile inspects a single model card file at path.
	CheckFile(path string) []Finding
	// CheckDirectory walks dir and checks every model card it finds.
	CheckDirectory(dir string) []Finding
}

// SignatureVerifier verifies sigstore / cosign signatures for model artifacts
// and flags unsigned or invalidly-signed artifacts.
type SignatureVerifier interface {
	// VerifyArtifact verifies the signature for a single artifact at path.
	VerifyArtifact(path string) []Finding
	// VerifyDirectory walks dir and verifies every signed artifact it finds.
	VerifyDirectory(dir string) []Finding
}

// AIBOMComposer is the top-level entry point for the AIBOM module. It walks
// a target path and dispatches each file to the correct sub-provider based
// on its detected ArtifactFormat.
type AIBOMComposer interface {
	// Scan inspects a model file or directory and returns all AIBOM findings.
	Scan(path string) []Finding
}
