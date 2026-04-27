package aibom

import "github.com/oxvault/scanner/providers"

// safetensorsValidator is the Day-1 skeleton implementation. The real header
// validator lands in Day 4 of the v0.4 AIBOM milestone.
type safetensorsValidator struct{}

// NewSafetensorsValidator returns a SafetensorsValidator.
func NewSafetensorsValidator() SafetensorsValidator {
	return &safetensorsValidator{}
}

// ValidateFile is a no-op skeleton. Real logic arrives in Day 4.
func (s *safetensorsValidator) ValidateFile(_ string) []providers.Finding {
	return nil
}

// ValidateDirectory is a no-op skeleton. Real logic arrives in Day 4.
func (s *safetensorsValidator) ValidateDirectory(_ string) []providers.Finding {
	return nil
}
