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
	SkipSAST     bool
	SkipManifest bool
	SkipEgress   bool
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		OutputFormat: providers.FormatTerminal,
		FailOn:       "critical",
		PinDir:       defaultPinDir(),
	}
}

func defaultPinDir() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ".oxvault"
	}
	return filepath.Join(cwd, ".oxvault")
}
