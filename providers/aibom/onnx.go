package aibom

import "github.com/oxvault/scanner/providers"

// onnxValidator is the Day-1 skeleton implementation. The real protobuf
// validator lands in Day 3 of the v0.4 AIBOM milestone.
type onnxValidator struct{}

// NewONNXValidator returns an ONNXValidator.
func NewONNXValidator() ONNXValidator {
	return &onnxValidator{}
}

// ValidateFile is a no-op skeleton. Real logic arrives in Day 3.
func (o *onnxValidator) ValidateFile(_ string) []providers.Finding {
	return nil
}

// ValidateDirectory is a no-op skeleton. Real logic arrives in Day 3.
func (o *onnxValidator) ValidateDirectory(_ string) []providers.Finding {
	return nil
}
