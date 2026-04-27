// Package aibom implements the AI Bill of Materials (AIBOM) scanner module.
//
// AIBOM analyzes machine-learning model artifacts — pickle files, ONNX graphs,
// safetensors weights, model cards, and sigstore signatures — for security
// risks such as unsafe deserialization, malformed graphs, missing provenance,
// and unsigned artifacts.
//
// The package follows the same layered architecture as the rest of the
// scanner: each sub-provider is a small, single-responsibility interface, and
// the AIBOMComposer orchestrates them by dispatching files to the correct
// analyzer based on ArtifactFormat.
package aibom

import "github.com/oxvault/scanner/providers"

// PickleAnalyzer inspects Python pickle artifacts (.pkl, .pt, .pth, .bin)
// for unsafe opcodes (REDUCE / GLOBAL / BUILD) and known-malicious payloads.
type PickleAnalyzer interface {
	// AnalyzeFile inspects a single pickle file at path.
	AnalyzeFile(path string) []providers.Finding
	// AnalyzeDirectory walks dir and analyzes every pickle file it finds.
	AnalyzeDirectory(dir string) []providers.Finding
}

// ONNXValidator verifies the structural integrity of ONNX protobuf graphs
// and flags suspicious operators or external-data references.
type ONNXValidator interface {
	// ValidateFile inspects a single .onnx file at path.
	ValidateFile(path string) []providers.Finding
	// ValidateDirectory walks dir and validates every .onnx file it finds.
	ValidateDirectory(dir string) []providers.Finding
}

// SafetensorsValidator verifies the header structure of safetensors files
// and flags malformed offsets, oversized headers, or shape mismatches.
type SafetensorsValidator interface {
	// ValidateFile inspects a single .safetensors file at path.
	ValidateFile(path string) []providers.Finding
	// ValidateDirectory walks dir and validates every .safetensors file.
	ValidateDirectory(dir string) []providers.Finding
}

// ModelCardChecker inspects model cards (README.md, MODEL_CARD.md) for the
// presence of provenance, license, intended-use, and bias-evaluation sections.
type ModelCardChecker interface {
	// CheckFile inspects a single model card file at path.
	CheckFile(path string) []providers.Finding
	// CheckDirectory walks dir and checks every model card it finds.
	CheckDirectory(dir string) []providers.Finding
}

// SignatureVerifier verifies sigstore / cosign signatures for model artifacts
// and flags unsigned or invalidly-signed artifacts.
type SignatureVerifier interface {
	// VerifyArtifact verifies the signature for a single artifact at path.
	VerifyArtifact(path string) []providers.Finding
	// VerifyDirectory walks dir and verifies every signed artifact it finds.
	VerifyDirectory(dir string) []providers.Finding
}

// AIBOMComposer is the top-level entry point for the AIBOM module. It walks
// a target path and dispatches each file to the correct sub-provider based
// on its detected ArtifactFormat.
type AIBOMComposer interface {
	// Scan inspects a model file or directory and returns all AIBOM findings.
	Scan(path string) []providers.Finding
}
