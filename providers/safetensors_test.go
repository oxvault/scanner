package providers_test

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/oxvault/scanner/providers"
)

// safetensorsFixture writes a minimal safetensors-format file at path with
// the supplied header dict and payload bytes. headerLenOverride lets tests
// emit truncated / oversized prefixes to exercise the validator's bounds
// checking.
func safetensorsFixture(t *testing.T, path string, header map[string]any, payload []byte, headerLenOverride int64) {
	t.Helper()

	body, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	declaredLen := uint64(len(body))
	if headerLenOverride >= 0 {
		declaredLen = uint64(headerLenOverride)
	}

	prefix := make([]byte, 8)
	binary.LittleEndian.PutUint64(prefix, declaredLen)

	out := append([]byte{}, prefix...)
	out = append(out, body...)
	out = append(out, payload...)

	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

// findRule returns true when findings contains at least one entry whose Rule
// matches the given id.
func findRule(findings []providers.Finding, rule string) bool {
	for _, f := range findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

// findRuleAndSeverity returns true when findings contains at least one entry
// matching BOTH the rule id and severity.
func findRuleAndSeverity(findings []providers.Finding, rule string, sev providers.Severity) bool {
	for _, f := range findings {
		if f.Rule == rule && f.Severity == sev {
			return true
		}
	}
	return false
}

// ── repo fixture suite ──────────────────────────────────────────────────────
//
// These tests exercise the static fixtures emitted by
// scripts/gen_aibom_fixtures.py. Each fixture is paired with an expected rule
// id so that any regression in the validator is loud and obvious.

func TestSafetensorsValidator_Fixtures(t *testing.T) {
	tests := []struct {
		name         string
		fixture      string
		wantRule     string
		wantSeverity providers.Severity
	}{
		{
			name:         "clean file emits clean INFO",
			fixture:      "safe/clean.safetensors",
			wantRule:     "aibom-safetensors-clean",
			wantSeverity: providers.SeverityInfo,
		},
		{
			name:         "header_overflow flagged CRITICAL",
			fixture:      "malicious/header_overflow.safetensors",
			wantRule:     "aibom-safetensors-header-overflow",
			wantSeverity: providers.SeverityCritical,
		},
		{
			name:         "empty_header flagged WARNING",
			fixture:      "malicious/empty_header.safetensors",
			wantRule:     "aibom-safetensors-empty-header",
			wantSeverity: providers.SeverityWarning,
		},
		{
			name:         "malformed_json flagged HIGH",
			fixture:      "malicious/malformed_json.safetensors",
			wantRule:     "aibom-safetensors-malformed-json",
			wantSeverity: providers.SeverityHigh,
		},
		{
			name:         "tensor_overflow flagged HIGH",
			fixture:      "malicious/tensor_overflow.safetensors",
			wantRule:     "aibom-safetensors-tensor-overflow",
			wantSeverity: providers.SeverityHigh,
		},
		{
			name:         "overlapping flagged HIGH",
			fixture:      "malicious/overlapping.safetensors",
			wantRule:     "aibom-safetensors-overlapping-tensors",
			wantSeverity: providers.SeverityHigh,
		},
		{
			name:         "poisoned_metadata flagged WARNING",
			fixture:      "malicious/poisoned_metadata.safetensors",
			wantRule:     "aibom-safetensors-suspicious-metadata",
			wantSeverity: providers.SeverityWarning,
		},
		{
			name:         "invalid_dtype flagged WARNING",
			fixture:      "malicious/invalid_dtype.safetensors",
			wantRule:     "aibom-safetensors-invalid-dtype",
			wantSeverity: providers.SeverityWarning,
		},
	}

	v := providers.NewSafetensorsValidator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join("..", "testdata", "aibom", "safetensors", tt.fixture)
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("missing fixture %s: %v (run scripts/gen_aibom_fixtures.py)", tt.fixture, err)
			}

			findings := v.ValidateFile(path)
			if !findRuleAndSeverity(findings, tt.wantRule, tt.wantSeverity) {
				t.Errorf("expected rule %q at severity %v, got %d findings: %+v",
					tt.wantRule, tt.wantSeverity, len(findings), findings)
			}
		})
	}
}

// TestSafetensorsValidator_CleanIsExclusive ensures the clean fixture emits
// exactly one INFO finding and never a violation.
func TestSafetensorsValidator_CleanIsExclusive(t *testing.T) {
	path := filepath.Join("..", "testdata", "aibom", "safetensors", "safe", "clean.safetensors")
	v := providers.NewSafetensorsValidator()
	findings := v.ValidateFile(path)

	if len(findings) != 1 {
		t.Fatalf("clean fixture: expected exactly 1 finding, got %d (%+v)", len(findings), findings)
	}
	if findings[0].Rule != "aibom-safetensors-clean" {
		t.Errorf("clean fixture: rule = %q, want aibom-safetensors-clean", findings[0].Rule)
	}
	if findings[0].Severity != providers.SeverityInfo {
		t.Errorf("clean fixture: severity = %v, want INFO", findings[0].Severity)
	}
}

// ── synthesised edge-case suite ─────────────────────────────────────────────
//
// These tests build their own files with t.TempDir() so they run without any
// external script. They cover the byte-level edge cases that fixtures cannot
// express cleanly.

func TestSafetensorsValidator_TooSmallFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tiny.safetensors")
	// 4 bytes — cannot even hold the 8-byte length prefix.
	if err := os.WriteFile(path, []byte{0x00, 0x00, 0x00, 0x00}, 0o644); err != nil {
		t.Fatal(err)
	}

	v := providers.NewSafetensorsValidator()
	findings := v.ValidateFile(path)

	if !findRuleAndSeverity(findings, "aibom-safetensors-header-overflow", providers.SeverityCritical) {
		t.Errorf("expected header-overflow CRITICAL on sub-8-byte file, got: %+v", findings)
	}
}

func TestSafetensorsValidator_HeaderLenMatchingFileNoBody(t *testing.T) {
	// File contains the prefix + an exactly-fitting JSON header but no
	// tensor body. Tensors that claim 0-byte ranges should still be valid;
	// tensors that claim ANY bytes should overflow.
	dir := t.TempDir()
	path := filepath.Join(dir, "no_body.safetensors")
	header := map[string]any{
		"a": map[string]any{
			"dtype":        "F32",
			"shape":        []int{0},
			"data_offsets": []int{0, 0},
		},
	}
	safetensorsFixture(t, path, header, nil, -1)

	v := providers.NewSafetensorsValidator()
	findings := v.ValidateFile(path)

	if !findRule(findings, "aibom-safetensors-clean") {
		t.Errorf("zero-length tensor with no body should be clean; got: %+v", findings)
	}
}

func TestSafetensorsValidator_NegativeOffsetEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "neg_offsets.safetensors")
	header := map[string]any{
		"a": map[string]any{
			"dtype":        "F32",
			"shape":        []int{1},
			"data_offsets": []int{16, 4}, // end < start
		},
	}
	safetensorsFixture(t, path, header, []byte{0x00, 0x00, 0x00, 0x00}, -1)

	v := providers.NewSafetensorsValidator()
	findings := v.ValidateFile(path)

	if !findRuleAndSeverity(findings, "aibom-safetensors-tensor-overflow", providers.SeverityHigh) {
		t.Errorf("expected tensor-overflow HIGH for inverted offsets, got: %+v", findings)
	}
}

func TestSafetensorsValidator_NegativeShapeDimension(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "neg_shape.safetensors")
	header := map[string]any{
		"a": map[string]any{
			"dtype":        "F32",
			"shape":        []int{-1},
			"data_offsets": []int{0, 4},
		},
	}
	safetensorsFixture(t, path, header, []byte{0x00, 0x00, 0x00, 0x00}, -1)

	v := providers.NewSafetensorsValidator()
	findings := v.ValidateFile(path)

	if !findRuleAndSeverity(findings, "aibom-safetensors-malformed-json", providers.SeverityHigh) {
		t.Errorf("expected malformed-json HIGH for negative shape, got: %+v", findings)
	}
}

func TestSafetensorsValidator_MetadataNotStringMap(t *testing.T) {
	// __metadata__ value is an int, not a map — should fire malformed-json.
	dir := t.TempDir()
	path := filepath.Join(dir, "bad_meta.safetensors")
	header := map[string]any{
		"a": map[string]any{
			"dtype":        "F32",
			"shape":        []int{1},
			"data_offsets": []int{0, 4},
		},
		"__metadata__": 42,
	}
	safetensorsFixture(t, path, header, []byte{0x00, 0x00, 0x00, 0x00}, -1)

	v := providers.NewSafetensorsValidator()
	findings := v.ValidateFile(path)

	if !findRuleAndSeverity(findings, "aibom-safetensors-malformed-json", providers.SeverityHigh) {
		t.Errorf("expected malformed-json HIGH for non-map __metadata__, got: %+v", findings)
	}
}

func TestSafetensorsValidator_ShellMetadataFlagged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shell_meta.safetensors")
	header := map[string]any{
		"a": map[string]any{
			"dtype":        "F32",
			"shape":        []int{1},
			"data_offsets": []int{0, 4},
		},
		"__metadata__": map[string]any{
			"hint": "rm -rf /; echo done",
		},
	}
	safetensorsFixture(t, path, header, []byte{0x00, 0x00, 0x00, 0x00}, -1)

	v := providers.NewSafetensorsValidator()
	findings := v.ValidateFile(path)

	if !findRule(findings, "aibom-safetensors-suspicious-metadata") {
		t.Errorf("expected suspicious-metadata for shell metachar, got: %+v", findings)
	}
}

func TestSafetensorsValidator_URLMetadataFlagged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "url_meta.safetensors")
	header := map[string]any{
		"a": map[string]any{
			"dtype":        "F32",
			"shape":        []int{1},
			"data_offsets": []int{0, 4},
		},
		"__metadata__": map[string]any{
			"callback": "https://attacker.example.com/exfil",
		},
	}
	safetensorsFixture(t, path, header, []byte{0x00, 0x00, 0x00, 0x00}, -1)

	v := providers.NewSafetensorsValidator()
	findings := v.ValidateFile(path)

	if !findRule(findings, "aibom-safetensors-suspicious-metadata") {
		t.Errorf("expected suspicious-metadata for URL, got: %+v", findings)
	}
}

func TestSafetensorsValidator_PickleMagicInMetadataFlagged(t *testing.T) {
	// JSON cannot encode raw 0x80 (invalid UTF-8), so a real attacker
	// smuggling pickle bytes into a safetensors header must use \uXXXX
	// escapes. We hand-craft a header containing the escaped form and
	// expect the pre-decode raw-header sweep to flag it.
	dir := t.TempDir()
	path := filepath.Join(dir, "pickle_meta.safetensors")

	body := []byte(`{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]},"__metadata__":{"smuggled":"\u0080\u0004prelude"}}`)

	prefix := make([]byte, 8)
	binary.LittleEndian.PutUint64(prefix, uint64(len(body)))

	out := append([]byte{}, prefix...)
	out = append(out, body...)
	out = append(out, []byte{0x00, 0x00, 0x00, 0x00}...)

	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}

	v := providers.NewSafetensorsValidator()
	findings := v.ValidateFile(path)

	if !findRule(findings, "aibom-safetensors-suspicious-metadata") {
		t.Errorf("expected suspicious-metadata for pickle magic bytes, got: %+v", findings)
	}
}

// ── ValidateDirectory ───────────────────────────────────────────────────────

func TestSafetensorsValidator_ValidateDirectory_WalksAllFiles(t *testing.T) {
	dir := t.TempDir()

	// Two clean safetensors and one decoy non-safetensors that must be ignored.
	clean := func(name string) {
		path := filepath.Join(dir, name)
		header := map[string]any{
			"a": map[string]any{
				"dtype":        "F32",
				"shape":        []int{1},
				"data_offsets": []int{0, 4},
			},
		}
		safetensorsFixture(t, path, header, []byte{0x00, 0x00, 0x00, 0x00}, -1)
	}
	clean("a.safetensors")
	clean("b.safetensors")

	// Decoy — should be ignored by ValidateDirectory.
	if err := os.WriteFile(filepath.Join(dir, "decoy.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	v := providers.NewSafetensorsValidator()
	findings := v.ValidateDirectory(dir)

	clean_count := 0
	for _, f := range findings {
		if f.Rule == "aibom-safetensors-clean" {
			clean_count++
		}
	}
	if clean_count != 2 {
		t.Errorf("expected 2 clean findings, got %d (%+v)", clean_count, findings)
	}
}

func TestSafetensorsValidator_NonexistentFile(t *testing.T) {
	v := providers.NewSafetensorsValidator()
	findings := v.ValidateFile("/no/such/file/anywhere")
	if findings != nil {
		t.Errorf("expected nil for missing file, got %+v", findings)
	}
}
