// Package lastscan persists the most recent scan to ~/.oxvault/last-scan.json
// so that `oxvault push` can upload it without re-running the scanner.
//
// Schema mirrors what the platform's POST /api/v1/scans expects (see
// oxvault/platform/models/scans.go: IngestScanRequest + ScanFindingIn). When
// the platform contract changes, both this file AND the platform DTO must
// move together.
package lastscan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/oxvault/scanner/providers"
)

// File is the on-disk schema for ~/.oxvault/last-scan.json. Field names are
// snake_case and match the platform IngestScanRequest 1:1 — push reads this
// file and POSTs it as-is.
type File struct {
	ArtifactName   string    `json:"artifact_name"`
	ArtifactType   string    `json:"artifact_type"`
	Source         Source    `json:"source"`
	ScannerVersion string    `json:"scanner_version"`
	StartedAt      time.Time `json:"started_at"`
	CompletedAt    time.Time `json:"completed_at"`
	Findings       []Finding `json:"findings"`
}

// Source describes where the scanned artifact came from. Stored as a JSON
// object on the artifact row — useful for debugging and for the future
// "discover" feature.
type Source struct {
	Target string `json:"target"`         // raw scanner target (path, npm pkg, github URL)
	Path   string `json:"path,omitempty"` // resolved local path
}

// Finding is the on-disk schema for a single finding. Mirrors the platform
// ScanFindingIn struct.
type Finding struct {
	RuleID    string          `json:"rule_id"`
	Severity  string          `json:"severity"` // critical | high | warning | info
	Category  string          `json:"category,omitempty"`
	Evidence  json.RawMessage `json:"evidence"`
	FilePath  *string         `json:"file_path,omitempty"`
	LineRange *string         `json:"line_range,omitempty"`
	DiffKey   string          `json:"diff_key"` // empty → platform synthesizes
}

// Path returns the absolute path to ~/.oxvault/last-scan.json, expanding the
// home directory.
func Path() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("lastscan: locate home dir: %w", err)
	}
	return filepath.Join(home, ".oxvault", "last-scan.json"), nil
}

// Save writes the file to ~/.oxvault/last-scan.json (creating the directory
// if needed). Atomic — writes to a temp file then renames.
func Save(f *File) error {
	if f == nil {
		return errors.New("lastscan: nil file")
	}
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("lastscan: mkdir: %w", err)
	}

	body, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("lastscan: marshal: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), "last-scan-*.json")
	if err != nil {
		return fmt.Errorf("lastscan: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // safe — Rename below leaves no temp

	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("lastscan: write: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("lastscan: chmod: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("lastscan: close: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("lastscan: rename: %w", err)
	}
	return nil
}

// Load reads ~/.oxvault/last-scan.json. Returns (nil, nil) if the file
// doesn't exist (push prints a friendly "run a scan first" message).
func Load() (*File, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("lastscan: read: %w", err)
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("lastscan: parse: %w", err)
	}
	return &f, nil
}

// FromReport builds a File from a scanner report + target metadata. Used by
// the scan command to persist after every successful scan.
//
// artifactType is "mcp" for MCP server scans, "model" for AIBOM, "rag" for
// RAG (v0.5). The caller decides — scan can derive it from the resolver.
func FromReport(target, artifactName, artifactType string, started, completed time.Time, scannerVersion string, findings []providers.Finding) *File {
	out := &File{
		ArtifactName:   artifactName,
		ArtifactType:   artifactType,
		Source:         Source{Target: target},
		ScannerVersion: scannerVersion,
		StartedAt:      started,
		CompletedAt:    completed,
		Findings:       make([]Finding, 0, len(findings)),
	}
	for _, f := range findings {
		out.Findings = append(out.Findings, projectFinding(f))
	}
	return out
}

func projectFinding(f providers.Finding) Finding {
	out := Finding{
		RuleID:   f.Rule,
		Severity: severityToString(f.Severity),
		Category: f.CWE,
		DiffKey:  "", // platform synthesizes when empty
	}

	// Evidence — collapse the rich Finding into a compact JSON object so the
	// platform can store it verbatim.
	evidence := map[string]any{}
	if f.Message != "" {
		evidence["message"] = f.Message
	}
	if f.Tool != "" {
		evidence["tool"] = f.Tool
	}
	if f.Fix != "" {
		evidence["fix"] = f.Fix
	}
	if len(f.References) > 0 {
		evidence["references"] = f.References
	}
	if f.Confidence > 0 {
		evidence["confidence"] = f.ConfidenceLabel
	}
	body, err := json.Marshal(evidence)
	if err != nil || string(body) == "null" {
		body = []byte("{}")
	}
	out.Evidence = body

	if f.File != "" {
		fp := f.File
		out.FilePath = &fp
	}
	if f.Line > 0 {
		lr := fmt.Sprintf("%d", f.Line)
		out.LineRange = &lr
	}
	return out
}

func severityToString(s providers.Severity) string {
	switch int(s) {
	case 3:
		return "critical"
	case 2:
		return "high"
	case 1:
		return "warning"
	default:
		return "info"
	}
}
