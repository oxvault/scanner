package providers

import (
	"os"
	"path/filepath"
)

// composer is the concrete AIBOMComposer. It walks the target path and
// dispatches each file to the correct sub-provider based on its detected
// ArtifactFormat.
type composer struct {
	pickle      PickleAnalyzer
	onnx        ONNXValidator
	safetensors SafetensorsValidator
	modelCard   ModelCardChecker
	signature   SignatureVerifier
}

// ComposerOption is a functional option for configuring the AIBOMComposer.
//
// Options follow the same pattern as app/app.go: nil-safe defaults are
// installed by NewComposer, and any sub-provider passed via WithXxx
// overrides the default. This keeps the composer easy to mock in tests.
type ComposerOption func(*composer)

// WithPickleAnalyzer overrides the default PickleAnalyzer.
func WithPickleAnalyzer(p PickleAnalyzer) ComposerOption {
	return func(c *composer) { c.pickle = p }
}

// WithONNXValidator overrides the default ONNXValidator.
func WithONNXValidator(o ONNXValidator) ComposerOption {
	return func(c *composer) { c.onnx = o }
}

// WithSafetensorsValidator overrides the default SafetensorsValidator.
func WithSafetensorsValidator(s SafetensorsValidator) ComposerOption {
	return func(c *composer) { c.safetensors = s }
}

// WithModelCardChecker overrides the default ModelCardChecker.
func WithModelCardChecker(m ModelCardChecker) ComposerOption {
	return func(c *composer) { c.modelCard = m }
}

// WithSignatureVerifier overrides the default SignatureVerifier.
func WithSignatureVerifier(s SignatureVerifier) ComposerOption {
	return func(c *composer) { c.signature = s }
}

// NewComposer returns an AIBOMComposer wired with the supplied options.
// Any sub-provider not supplied is replaced with its production default.
func NewComposer(opts ...ComposerOption) AIBOMComposer {
	c := &composer{}
	for _, opt := range opts {
		opt(c)
	}
	if c.pickle == nil {
		c.pickle = NewPickleAnalyzer()
	}
	if c.onnx == nil {
		c.onnx = NewONNXValidator()
	}
	if c.safetensors == nil {
		c.safetensors = NewSafetensorsValidator()
	}
	if c.modelCard == nil {
		c.modelCard = NewModelCardChecker()
	}
	if c.signature == nil {
		c.signature = NewSignatureVerifier()
	}
	return c
}

// Scan inspects a model file or directory and returns all AIBOM findings.
//
// For a file, Scan dispatches to a single sub-provider based on the
// detected ArtifactFormat. For a directory, Scan walks the tree once and
// dispatches each file individually — sub-providers' AnalyzeDirectory /
// ValidateDirectory / CheckDirectory methods are NOT called from here so
// that the walk and exclusion rules are owned by the composer.
//
// Cross-file aggregation happens here, NOT in sub-providers:
//
//   - aibom-modelcard-missing fires per directory that contains a model
//     artifact (.pkl/.pt/.onnx/.safetensors) but no model card alongside it.
//     The composer tracks artifact + card directories during the walk and
//     emits the missing-card finding once the walk completes.
//   - Signature verification runs on every model artifact (single file
//     OR directory walk). For a single-file scan, aibom-signature-missing
//     is filtered out — the user is targeting an artifact in isolation,
//     not declaring "this directory should have a signature" — but every
//     other signature finding (hash mismatch, untrusted issuer, malformed
//     manifest) is preserved so the canonical sign-then-tamper attack is
//     detected on `oxvault scan ./tampered.pkl`.
func (c *composer) Scan(path string) []Finding {
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}

	if !info.IsDir() {
		findings := c.dispatch(path)
		// Single-file branch must also run signature verification so the
		// canonical sign-then-tamper attack fires on a single-file scan
		// (without this, `oxvault scan ./tampered.pkl` with a sibling
		// manifest declaring the wrong hash would be silent). The
		// aibom-signature-missing rule is filtered — it only makes sense
		// in directory aggregation where the user is declaring "this
		// directory IS the model".
		if isModelArtifactPath(path) {
			sigFindings := c.signature.VerifyArtifact(path)
			for _, f := range sigFindings {
				if f.Rule == RuleSignatureMissing {
					continue
				}
				findings = append(findings, f)
			}
		}
		return findings
	}

	var findings []Finding
	// Cross-file aggregation: track which directories contain a model
	// artifact and which contain a model card. After the walk we emit one
	// aibom-modelcard-missing per artifact directory without a card, and
	// one signature-missing (or hash-match / hash-mismatch / etc.) per
	// artifact via the SignatureVerifier. The per-directory CheckDirectory
	// / VerifyDirectory entry points are NOT called — the composer owns
	// the aggregation so the rules fire on every real
	// `oxvault scan ./model-dir` invocation, not just direct
	// CheckDirectory / VerifyDirectory callers.
	hasArtifact := map[string]bool{}
	hasCard := map[string]bool{}
	var artifactPaths []string

	// Reuse the shared walker so directory/file exclusion stays consistent
	// across providers (SAST, dep-audit, AIBOM). Symlinks are not followed.
	_ = WalkScanFiles(path, func(p string) {
		switch DetectArtifactFormat(p) {
		case FormatPickle, FormatONNX, FormatSafetensors:
			hasArtifact[filepath.Dir(p)] = true
			artifactPaths = append(artifactPaths, p)
		case FormatModelCard:
			hasCard[filepath.Dir(p)] = true
		}
		findings = append(findings, c.dispatch(p)...)
	})

	findings = append(findings, missingCardFindings(hasArtifact, hasCard)...)
	findings = append(findings, signatureFindings(c.signature, artifactPaths)...)
	return findings
}

// isModelArtifactPath returns true when path's detected ArtifactFormat is
// one of the model-artifact families (pickle, ONNX, safetensors). Used by
// the single-file Scan branch to decide whether to run signature
// verification.
func isModelArtifactPath(path string) bool {
	switch DetectArtifactFormat(path) {
	case FormatPickle, FormatONNX, FormatSafetensors:
		return true
	default:
		return false
	}
}

// dispatch routes a single file to the sub-provider matching its
// ArtifactFormat. Files of FormatUnknown are skipped silently.
//
// FormatSignature files (.sigstore, .sig, .pem, .cert) are also dispatched
// to SignatureVerifier so the verifier can short-circuit (carriers are
// evaluated FROM the artifact's perspective, not the signature file's).
// Cross-file aggregation in Scan() handles the actual per-artifact
// verification.
func (c *composer) dispatch(path string) []Finding {
	switch DetectArtifactFormat(path) {
	case FormatPickle:
		return c.pickle.AnalyzeFile(path)
	case FormatONNX:
		return c.onnx.ValidateFile(path)
	case FormatSafetensors:
		return c.safetensors.ValidateFile(path)
	case FormatModelCard:
		return c.modelCard.CheckFile(path)
	case FormatSignature:
		return c.signature.VerifyArtifact(path)
	case FormatUnknown:
		fallthrough
	default:
		return nil
	}
}
