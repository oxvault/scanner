package aibom

import (
	"os"
	"path/filepath"

	"github.com/oxvault/scanner/providers"
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
func (c *composer) Scan(path string) []providers.Finding {
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}

	if !info.IsDir() {
		return c.dispatch(path)
	}

	var findings []providers.Finding
	_ = filepath.Walk(path, func(p string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if fi.IsDir() {
			if providers.IsExcludedDir(filepath.Base(p)) {
				return filepath.SkipDir
			}
			return nil
		}
		if providers.IsExcludedFile(filepath.Base(p)) {
			return nil
		}
		findings = append(findings, c.dispatch(p)...)
		return nil
	})
	return findings
}

// dispatch routes a single file to the sub-provider matching its
// ArtifactFormat. Files of FormatUnknown are skipped silently.
func (c *composer) dispatch(path string) []providers.Finding {
	switch DetectArtifactFormat(path) {
	case providers.FormatPickle:
		return c.pickle.AnalyzeFile(path)
	case providers.FormatONNX:
		return c.onnx.ValidateFile(path)
	case providers.FormatSafetensors:
		return c.safetensors.ValidateFile(path)
	case providers.FormatModelCard:
		return c.modelCard.CheckFile(path)
	case providers.FormatSignature:
		return c.signature.VerifyArtifact(path)
	case providers.FormatUnknown:
		fallthrough
	default:
		return nil
	}
}
