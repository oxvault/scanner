package config

import (
	"os"
	"path/filepath"

	"github.com/oxvault/scanner/providers"
)

// Config holds all scanner configuration
type Config struct {
	// Output
	OutputFormat providers.OutputFormat
	FailOn       string // Severity threshold for non-zero exit: critical, high, warning, info
	Verbose      bool
	NoColor      bool // Disable ANSI color output (for CI / pipe-friendly output)

	// Paths
	PinDir string // Directory for pin storage (default: .oxvault/)

	// Scan options
	SkipSAST       bool
	SkipManifest   bool
	SkipEgress     bool
	ProbeNetwork   bool // Run runtime network probe after static scan
	ShowSuppressed bool // Print suppressed findings in a separate section

	// Hugging Face resolver (v0.4 AIBOM)
	HF HFOptions
}

// HFOptions configure the Hugging Face resolver. All fields are optional —
// providers.HFConfig.applyDefaults() fills in sensible values.
type HFOptions struct {
	Token         string // HF_TOKEN env override; empty = anonymous
	Revision      string // default: "main"
	CacheDir      string // default: ~/.cache/oxvault/hf
	MaxFileBytes  int64  // default: 4 GiB
	MaxCacheBytes int64  // default: 16 GiB
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		OutputFormat: providers.FormatTerminal,
		FailOn:       providers.RiskTierCritical.String(),
		PinDir:       defaultPinDir(),
		HF: HFOptions{
			Token:    os.Getenv("HF_TOKEN"),
			Revision: "main",
		},
	}
}

func defaultPinDir() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ".oxvault"
	}
	return filepath.Join(cwd, ".oxvault")
}
