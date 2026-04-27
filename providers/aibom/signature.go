package aibom

import "github.com/oxvault/scanner/providers"

// signatureVerifier is the Day-1 skeleton implementation. The real sigstore /
// cosign verifier lands in Day 6 of the v0.4 AIBOM milestone.
type signatureVerifier struct{}

// NewSignatureVerifier returns a SignatureVerifier.
func NewSignatureVerifier() SignatureVerifier {
	return &signatureVerifier{}
}

// VerifyArtifact is a no-op skeleton. Real logic arrives in Day 6.
func (s *signatureVerifier) VerifyArtifact(_ string) []providers.Finding {
	return nil
}

// VerifyDirectory is a no-op skeleton. Real logic arrives in Day 6.
func (s *signatureVerifier) VerifyDirectory(_ string) []providers.Finding {
	return nil
}
