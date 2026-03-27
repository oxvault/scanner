package patterns

import "regexp"

// Confidence levels for findings.
type Confidence int

const (
	ConfidenceLow    Confidence = 1
	ConfidenceMedium Confidence = 2
	ConfidenceHigh   Confidence = 3
)

// String returns the human-readable label for a confidence level.
func (c Confidence) String() string {
	switch c {
	case ConfidenceLow:
		return "low"
	case ConfidenceMedium:
		return "medium"
	case ConfidenceHigh:
		return "high"
	default:
		return "unknown"
	}
}

// Severity levels for findings.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARNING"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// RiskTier classifies tool exposure level.
type RiskTier int

const (
	RiskTierLow    RiskTier = iota // Compute-only, data transformation
	RiskTierMedium                 // Network requests, messaging
	RiskTierHigh                   // Filesystem, database, infrastructure
	RiskTierCritical               // Shell execution, code eval
)

func (t RiskTier) String() string {
	switch t {
	case RiskTierLow:
		return "LOW"
	case RiskTierMedium:
		return "MEDIUM"
	case RiskTierHigh:
		return "HIGH"
	case RiskTierCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Language for source code analysis.
type Language string

const (
	LangPython     Language = "python"
	LangJavaScript Language = "javascript"
	LangTypeScript Language = "typescript"
	LangGo         Language = "go"
	LangJSON       Language = "json"
	LangUnknown    Language = "unknown"
)

// SourcePattern represents a pattern to match in source code.
type SourcePattern struct {
	Pattern         *regexp.Regexp
	Rule            string
	Severity        Severity
	Confidence      Confidence       // How certain is this finding?
	Message         string
	Langs           []Language
	CWE             string
	IsSecretRule    bool             // Enables placeholder/self-assignment exclusions
	ExcludePatterns []*regexp.Regexp // Skip finding when any exclusion matches the line
}

// EgressPattern represents a pattern for detecting outbound network calls.
type EgressPattern struct {
	Pattern *regexp.Regexp
	Method  string
	Langs   []Language
}

// DescriptionPattern represents a pattern for detecting tool description poisoning.
type DescriptionPattern struct {
	Pattern    *regexp.Regexp
	Rule       string
	Severity   Severity
	Confidence Confidence
	Message    string
	CWE        string
}

// ArgumentPattern represents a pattern for detecting argument injection.
type ArgumentPattern struct {
	Pattern  *regexp.Regexp
	Rule     string
	Severity Severity
	Message  string
	CWE      string
}

// ResponsePattern represents a pattern for detecting sensitive data in responses.
type ResponsePattern struct {
	Pattern  *regexp.Regexp
	Rule     string
	Severity Severity
	Message  string
	CWE      string
}

// HookPattern represents a single malicious pattern to match in install scripts.
type HookPattern struct {
	Pattern  *regexp.Regexp
	Rule     string
	Severity Severity
	Message  string
	CWE      string
}

// VulnerablePackage describes a known-vulnerable package version range.
type VulnerablePackage struct {
	Name        string
	MaxAffected string // inclusive upper bound -- versions <= this are affected
	CVE         string
	CVSS        float64
	Severity    Severity
	Description string
}
