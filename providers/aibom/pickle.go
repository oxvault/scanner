package aibom

import "github.com/oxvault/scanner/providers"

// pickleAnalyzer is the Day-1 skeleton implementation. The real opcode-walker
// lands in Day 2 of the v0.4 AIBOM milestone.
type pickleAnalyzer struct{}

// NewPickleAnalyzer returns a PickleAnalyzer.
func NewPickleAnalyzer() PickleAnalyzer {
	return &pickleAnalyzer{}
}

// AnalyzeFile is a no-op skeleton. Real logic arrives in Day 2.
func (p *pickleAnalyzer) AnalyzeFile(_ string) []providers.Finding {
	return nil
}

// AnalyzeDirectory is a no-op skeleton. Real logic arrives in Day 2.
func (p *pickleAnalyzer) AnalyzeDirectory(_ string) []providers.Finding {
	return nil
}
