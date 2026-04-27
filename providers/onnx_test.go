package providers_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/oxvault/scanner/providers"
)

// ── wire-format helpers (test-only) ─────────────────────────────────────────
//
// These mirror the helpers in scripts/gen_aibom_fixtures.py so each test can
// build its own ModelProto inline without touching the on-disk fixtures.

const (
	wireVarint   = 0
	wireLenDelim = 2
)

func writeVarint(buf *bytes.Buffer, n uint64) {
	for {
		b := byte(n & 0x7F)
		n >>= 7
		if n == 0 {
			buf.WriteByte(b)
			return
		}
		buf.WriteByte(b | 0x80)
	}
}

func writeTag(buf *bytes.Buffer, fieldNum uint32, wireType uint8) {
	writeVarint(buf, uint64(fieldNum<<3)|uint64(wireType))
}

func writeStringField(buf *bytes.Buffer, fieldNum uint32, value string) {
	writeTag(buf, fieldNum, wireLenDelim)
	writeVarint(buf, uint64(len(value)))
	buf.WriteString(value)
}

func writeVarintField(buf *bytes.Buffer, fieldNum uint32, value uint64) {
	writeTag(buf, fieldNum, wireVarint)
	writeVarint(buf, value)
}

func writeMessageField(buf *bytes.Buffer, fieldNum uint32, body []byte) {
	writeTag(buf, fieldNum, wireLenDelim)
	writeVarint(buf, uint64(len(body)))
	buf.Write(body)
}

// buildNode emits NodeProto bytes (op_type + optional domain).
func buildNode(opType, domain string) []byte {
	var n bytes.Buffer
	writeStringField(&n, 4, opType)
	if domain != "" {
		writeStringField(&n, 7, domain)
	}
	return n.Bytes()
}

// buildTensor emits TensorProto bytes with the given dims (unpacked) and an
// optional external_data location entry.
func buildTensor(dims []uint64, externalLoc string) []byte {
	var t bytes.Buffer
	for _, d := range dims {
		writeVarintField(&t, 1, d)
	}
	if externalLoc != "" {
		var entry bytes.Buffer
		writeStringField(&entry, 1, "location")
		writeStringField(&entry, 2, externalLoc)
		writeMessageField(&t, 13, entry.Bytes())
	}
	return t.Bytes()
}

// buildGraph emits GraphProto bytes from the supplied nodes and initializers.
func buildGraph(nodes [][]byte, initializers [][]byte) []byte {
	var g bytes.Buffer
	for _, n := range nodes {
		writeMessageField(&g, 1, n)
	}
	for _, t := range initializers {
		writeMessageField(&g, 5, t)
	}
	return g.Bytes()
}

// buildModel emits a top-level ModelProto.
func buildModel(irVersion uint64, producerName string, graph []byte) []byte {
	var m bytes.Buffer
	writeVarintField(&m, 1, irVersion)
	if producerName != "" {
		writeStringField(&m, 2, producerName)
	}
	if graph != nil {
		writeMessageField(&m, 7, graph)
	}
	return m.Bytes()
}

// writeOnnxFile writes body at dir/name.
func writeOnnxFile(t *testing.T, dir, name string, body []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// ── repo fixture suite ──────────────────────────────────────────────────────
//
// These tests exercise the static fixtures emitted by
// scripts/gen_aibom_fixtures.py. Each fixture is paired with an expected rule
// id so that any regression in the validator is loud and obvious.

func TestONNXValidator_Fixtures(t *testing.T) {
	tests := []struct {
		name         string
		fixture      string
		wantRule     string
		wantSeverity providers.Severity
	}{
		{
			name:         "clean minimal emits clean INFO (and missing-producer INFO)",
			fixture:      "safe/clean_minimal.onnx",
			wantRule:     "aibom-onnx-missing-producer",
			wantSeverity: providers.SeverityInfo,
		},
		{
			name:         "with_producer emits clean INFO",
			fixture:      "safe/with_producer.onnx",
			wantRule:     "aibom-onnx-clean",
			wantSeverity: providers.SeverityInfo,
		},
		{
			name:         "empty file flagged HIGH malformed-protobuf",
			fixture:      "malicious/empty.onnx",
			wantRule:     "aibom-onnx-malformed-protobuf",
			wantSeverity: providers.SeverityHigh,
		},
		{
			name:         "truncated message flagged HIGH malformed-protobuf",
			fixture:      "malicious/truncated.onnx",
			wantRule:     "aibom-onnx-malformed-protobuf",
			wantSeverity: providers.SeverityHigh,
		},
		{
			name:         "garbage bytes flagged HIGH malformed-protobuf",
			fixture:      "malicious/garbage.onnx",
			wantRule:     "aibom-onnx-malformed-protobuf",
			wantSeverity: providers.SeverityHigh,
		},
		{
			name:         "custom domain flagged WARNING custom-operator",
			fixture:      "malicious/custom_domain.onnx",
			wantRule:     "aibom-onnx-custom-operator",
			wantSeverity: providers.SeverityWarning,
		},
		{
			name:         "external_data path traversal flagged WARNING",
			fixture:      "malicious/external_data_traversal.onnx",
			wantRule:     "aibom-onnx-external-data",
			wantSeverity: providers.SeverityWarning,
		},
		{
			name:         "external_data URL flagged WARNING",
			fixture:      "malicious/external_data_url.onnx",
			wantRule:     "aibom-onnx-external-data",
			wantSeverity: providers.SeverityWarning,
		},
		{
			name:         "oversized tensor flagged WARNING",
			fixture:      "malicious/oversized_tensor.onnx",
			wantRule:     "aibom-onnx-oversized-tensor",
			wantSeverity: providers.SeverityWarning,
		},
	}

	v := providers.NewONNXValidator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join("..", "testdata", "aibom", "onnx", tt.fixture)
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

// TestONNXValidator_CleanFixtureExclusive ensures the with_producer fixture
// emits exactly one INFO finding and nothing more.
func TestONNXValidator_CleanFixtureExclusive(t *testing.T) {
	path := filepath.Join("..", "testdata", "aibom", "onnx", "safe", "with_producer.onnx")
	v := providers.NewONNXValidator()
	findings := v.ValidateFile(path)

	if len(findings) != 1 {
		t.Fatalf("with_producer fixture: expected exactly 1 finding, got %d (%+v)", len(findings), findings)
	}
	if findings[0].Rule != "aibom-onnx-clean" {
		t.Errorf("with_producer fixture: rule = %q, want aibom-onnx-clean", findings[0].Rule)
	}
	if findings[0].Severity != providers.SeverityInfo {
		t.Errorf("with_producer fixture: severity = %v, want INFO", findings[0].Severity)
	}
}

// TestONNXValidator_CleanMinimalAlsoMissingProducer ensures that the safe
// minimal model (no producer) emits BOTH the missing-producer and the
// fixture-specific behaviour without firing any violations.
func TestONNXValidator_CleanMinimalAlsoMissingProducer(t *testing.T) {
	path := filepath.Join("..", "testdata", "aibom", "onnx", "safe", "clean_minimal.onnx")
	v := providers.NewONNXValidator()
	findings := v.ValidateFile(path)

	if !findRuleAndSeverity(findings, "aibom-onnx-missing-producer", providers.SeverityInfo) {
		t.Errorf("expected missing-producer INFO, got: %+v", findings)
	}
	// No violation severity should be present.
	for _, f := range findings {
		if f.Severity > providers.SeverityInfo {
			t.Errorf("clean_minimal fixture must not contain any violation; got %+v", f)
		}
	}
}

// ── synthesised edge-case suite ─────────────────────────────────────────────
//
// These tests build their own ONNX bytes inline so they run without any
// external fixture script. They cover wire-level edge cases that fixtures
// cannot express cleanly.

func TestONNXValidator_NonexistentFile(t *testing.T) {
	v := providers.NewONNXValidator()
	findings := v.ValidateFile("/no/such/file/anywhere.onnx")
	if findings != nil {
		t.Errorf("expected nil for missing file, got %+v", findings)
	}
}

func TestONNXValidator_StandardDomainEmitsClean(t *testing.T) {
	dir := t.TempDir()
	graph := buildGraph(
		[][]byte{
			buildNode("Add", ""),
			buildNode("Conv", "ai.onnx"),
			buildNode("LinearClassifier", "ai.onnx.ml"),
		},
		nil,
	)
	body := buildModel(7, "oxvault-test", graph)
	path := writeOnnxFile(t, dir, "model.onnx", body)

	v := providers.NewONNXValidator()
	findings := v.ValidateFile(path)

	if len(findings) != 1 || findings[0].Rule != "aibom-onnx-clean" {
		t.Errorf("expected exactly 1 clean INFO finding, got: %+v", findings)
	}
}

func TestONNXValidator_HTTPDomainFiresSuspiciousOp(t *testing.T) {
	dir := t.TempDir()
	graph := buildGraph(
		[][]byte{buildNode("Op", "https://attacker.example.com/op")},
		nil,
	)
	body := buildModel(7, "oxvault-test", graph)
	path := writeOnnxFile(t, dir, "model.onnx", body)

	v := providers.NewONNXValidator()
	findings := v.ValidateFile(path)

	if !findRuleAndSeverity(findings, "aibom-onnx-suspicious-op", providers.SeverityHigh) {
		t.Errorf("expected suspicious-op HIGH for URL domain, got: %+v", findings)
	}
}

func TestONNXValidator_SlashedDomainFiresSuspiciousOp(t *testing.T) {
	dir := t.TempDir()
	graph := buildGraph(
		[][]byte{buildNode("Op", "vendor/private/op")},
		nil,
	)
	body := buildModel(7, "oxvault-test", graph)
	path := writeOnnxFile(t, dir, "model.onnx", body)

	v := providers.NewONNXValidator()
	findings := v.ValidateFile(path)

	if !findRuleAndSeverity(findings, "aibom-onnx-suspicious-op", providers.SeverityHigh) {
		t.Errorf("expected suspicious-op HIGH for slashed domain, got: %+v", findings)
	}
}

func TestONNXValidator_AbsolutePathExternalData(t *testing.T) {
	dir := t.TempDir()
	tensor := buildTensor([]uint64{4, 4}, "/etc/shadow")
	graph := buildGraph(
		[][]byte{buildNode("Add", "")},
		[][]byte{tensor},
	)
	body := buildModel(7, "oxvault-test", graph)
	path := writeOnnxFile(t, dir, "model.onnx", body)

	v := providers.NewONNXValidator()
	findings := v.ValidateFile(path)

	if !findRuleAndSeverity(findings, "aibom-onnx-external-data", providers.SeverityWarning) {
		t.Errorf("expected external-data WARNING for absolute path, got: %+v", findings)
	}
}

func TestONNXValidator_WindowsAbsolutePathExternalData(t *testing.T) {
	dir := t.TempDir()
	tensor := buildTensor([]uint64{4, 4}, "C:\\Windows\\System32\\config\\SAM")
	graph := buildGraph(
		[][]byte{buildNode("Add", "")},
		[][]byte{tensor},
	)
	body := buildModel(7, "oxvault-test", graph)
	path := writeOnnxFile(t, dir, "model.onnx", body)

	v := providers.NewONNXValidator()
	findings := v.ValidateFile(path)

	if !findRuleAndSeverity(findings, "aibom-onnx-external-data", providers.SeverityWarning) {
		t.Errorf("expected external-data WARNING for Windows absolute path, got: %+v", findings)
	}
}

func TestONNXValidator_RelativeExternalDataIsClean(t *testing.T) {
	dir := t.TempDir()
	tensor := buildTensor([]uint64{4, 4}, "weights.bin")
	graph := buildGraph(
		[][]byte{buildNode("Add", "")},
		[][]byte{tensor},
	)
	body := buildModel(7, "oxvault-test", graph)
	path := writeOnnxFile(t, dir, "model.onnx", body)

	v := providers.NewONNXValidator()
	findings := v.ValidateFile(path)

	if len(findings) != 1 || findings[0].Rule != "aibom-onnx-clean" {
		t.Errorf("expected clean INFO for safe relative external_data, got: %+v", findings)
	}
}

func TestONNXValidator_PackedDimsEncoding(t *testing.T) {
	// Build a TensorProto whose dims are encoded in PACKED form (length-
	// delimited list of varints, not one tag-per-element). Both forms are
	// permitted on the wire — the validator must support both.
	dir := t.TempDir()

	var packed bytes.Buffer
	writeVarint(&packed, 4)
	writeVarint(&packed, 4)

	var t1 bytes.Buffer
	writeMessageField(&t1, 1, packed.Bytes())

	graph := buildGraph(
		[][]byte{buildNode("Add", "")},
		[][]byte{t1.Bytes()},
	)
	body := buildModel(7, "oxvault-test", graph)
	path := writeOnnxFile(t, dir, "model.onnx", body)

	v := providers.NewONNXValidator()
	findings := v.ValidateFile(path)

	if len(findings) != 1 || findings[0].Rule != "aibom-onnx-clean" {
		t.Errorf("expected clean INFO with packed dims encoding, got: %+v", findings)
	}
}

func TestONNXValidator_PackedOversizedDims(t *testing.T) {
	dir := t.TempDir()

	var packed bytes.Buffer
	writeVarint(&packed, 100_000_000)
	writeVarint(&packed, 100_000_000)

	var t1 bytes.Buffer
	writeMessageField(&t1, 1, packed.Bytes())

	graph := buildGraph(
		[][]byte{buildNode("Add", "")},
		[][]byte{t1.Bytes()},
	)
	body := buildModel(7, "oxvault-test", graph)
	path := writeOnnxFile(t, dir, "model.onnx", body)

	v := providers.NewONNXValidator()
	findings := v.ValidateFile(path)

	if !findRuleAndSeverity(findings, "aibom-onnx-oversized-tensor", providers.SeverityWarning) {
		t.Errorf("expected oversized-tensor WARNING for packed huge dims, got: %+v", findings)
	}
}

func TestONNXValidator_DimsOverflowUint64(t *testing.T) {
	// Three dims each at 2^63 would overflow uint64 during multiplication —
	// the validator must clamp safely and still emit oversized-tensor.
	dir := t.TempDir()

	huge := uint64(1) << 63
	tensor := buildTensor([]uint64{huge, huge, huge}, "")
	graph := buildGraph(
		[][]byte{buildNode("Add", "")},
		[][]byte{tensor},
	)
	body := buildModel(7, "oxvault-test", graph)
	path := writeOnnxFile(t, dir, "model.onnx", body)

	v := providers.NewONNXValidator()
	findings := v.ValidateFile(path)

	if !findRuleAndSeverity(findings, "aibom-onnx-oversized-tensor", providers.SeverityWarning) {
		t.Errorf("expected oversized-tensor WARNING on uint64-overflow, got: %+v", findings)
	}
}

func TestONNXValidator_ExternalDataDotDotInMiddle(t *testing.T) {
	// "weights/../../etc/passwd" — traversal segment in the middle of the
	// path. Validator must catch it after filepath.Clean as well.
	dir := t.TempDir()
	tensor := buildTensor([]uint64{4}, "weights/../../etc/passwd")
	graph := buildGraph(
		[][]byte{buildNode("Add", "")},
		[][]byte{tensor},
	)
	body := buildModel(7, "oxvault-test", graph)
	path := writeOnnxFile(t, dir, "model.onnx", body)

	v := providers.NewONNXValidator()
	findings := v.ValidateFile(path)

	if !findRuleAndSeverity(findings, "aibom-onnx-external-data", providers.SeverityWarning) {
		t.Errorf("expected external-data WARNING for embedded traversal, got: %+v", findings)
	}
}

func TestONNXValidator_ExternalDataLocationOnlyKey(t *testing.T) {
	// An external_data entry whose key is NOT "location" must NOT trigger
	// the path-traversal check (other keys are length, offset, checksum…).
	dir := t.TempDir()

	var entry bytes.Buffer
	writeStringField(&entry, 1, "checksum")
	writeStringField(&entry, 2, "../../../malicious/looking")

	var tensor bytes.Buffer
	writeVarintField(&tensor, 1, 4)
	writeMessageField(&tensor, 13, entry.Bytes())

	graph := buildGraph(
		[][]byte{buildNode("Add", "")},
		[][]byte{tensor.Bytes()},
	)
	body := buildModel(7, "oxvault-test", graph)
	path := writeOnnxFile(t, dir, "model.onnx", body)

	v := providers.NewONNXValidator()
	findings := v.ValidateFile(path)

	for _, f := range findings {
		if f.Rule == "aibom-onnx-external-data" {
			t.Errorf("non-location external_data entry must not trigger external-data rule; got %+v", f)
		}
	}
}

// ── malformed-protobuf coverage ─────────────────────────────────────────────

func TestONNXValidator_OverlongVarint(t *testing.T) {
	// 11 consecutive 0x80 bytes — varint that exceeds the 10-byte cap. The
	// walker must emit malformed-protobuf rather than spin.
	dir := t.TempDir()
	body := bytes.Repeat([]byte{0x80}, 11)
	path := writeOnnxFile(t, dir, "model.onnx", body)

	v := providers.NewONNXValidator()
	findings := v.ValidateFile(path)

	if !findRuleAndSeverity(findings, "aibom-onnx-malformed-protobuf", providers.SeverityHigh) {
		t.Errorf("expected malformed-protobuf HIGH for overlong varint, got: %+v", findings)
	}
}

func TestONNXValidator_LengthDelimOverflow(t *testing.T) {
	// Field 7 (graph) declared with a length-prefix that runs off the end
	// of the buffer.
	dir := t.TempDir()

	var body bytes.Buffer
	writeVarintField(&body, 1, 7) // ir_version
	writeTag(&body, 7, wireLenDelim)
	writeVarint(&body, 999_999) // declared length
	body.Write([]byte{0x00, 0x00, 0x00})

	path := writeOnnxFile(t, dir, "model.onnx", body.Bytes())
	v := providers.NewONNXValidator()
	findings := v.ValidateFile(path)

	if !findRuleAndSeverity(findings, "aibom-onnx-malformed-protobuf", providers.SeverityHigh) {
		t.Errorf("expected malformed-protobuf HIGH for over-declared length, got: %+v", findings)
	}
}

func TestONNXValidator_OversizedFile(t *testing.T) {
	// Use a sparse file declared at 5 GiB. The validator's pre-read size
	// check must reject it without ever reading the body.
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.onnx")
	f, err := os.Create(path) //nolint:gosec // test-only path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	// Touch first byte so something is on disk.
	if _, err := f.Write([]byte{0x08, 0x07}); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	target := int64(5) * 1024 * 1024 * 1024 // 5 GiB > 4 GiB cap
	if err := f.Truncate(target); err != nil {
		_ = f.Close()
		t.Skipf("filesystem rejected sparse 5 GiB file: %v", err)
	}
	_ = f.Close()

	v := providers.NewONNXValidator()
	findings := v.ValidateFile(path)

	if !findRuleAndSeverity(findings, "aibom-onnx-malformed-protobuf", providers.SeverityHigh) {
		t.Errorf("expected malformed-protobuf HIGH for oversized file, got: %+v", findings)
	}
}

// ── ValidateDirectory ───────────────────────────────────────────────────────

func TestONNXValidator_ValidateDirectory_WalksAllFiles(t *testing.T) {
	dir := t.TempDir()
	graph := buildGraph(
		[][]byte{buildNode("Add", "")},
		nil,
	)
	body := buildModel(7, "oxvault-test", graph)

	writeOnnxFile(t, dir, "a.onnx", body)
	writeOnnxFile(t, dir, "b.onnx", body)
	// Decoy non-onnx file — must be ignored by ValidateDirectory.
	writeOnnxFile(t, dir, "decoy.txt", []byte("hello"))

	v := providers.NewONNXValidator()
	findings := v.ValidateDirectory(dir)

	cleanCount := 0
	for _, f := range findings {
		if f.Rule == "aibom-onnx-clean" {
			cleanCount++
		}
	}
	if cleanCount != 2 {
		t.Errorf("expected 2 clean findings, got %d (%+v)", cleanCount, findings)
	}
}

func TestONNXValidator_ValidateDirectory_SkipsExcludedDirs(t *testing.T) {
	dir := t.TempDir()
	excluded := filepath.Join(dir, "node_modules")
	if err := os.Mkdir(excluded, 0o755); err != nil {
		t.Fatal(err)
	}

	graph := buildGraph([][]byte{buildNode("Add", "")}, nil)
	body := buildModel(7, "oxvault-test", graph)
	writeOnnxFile(t, excluded, "hidden.onnx", body)
	writeOnnxFile(t, dir, "visible.onnx", body)

	v := providers.NewONNXValidator()
	findings := v.ValidateDirectory(dir)

	cleanCount := 0
	for _, f := range findings {
		if f.Rule == "aibom-onnx-clean" {
			cleanCount++
		}
	}
	if cleanCount != 1 {
		t.Errorf("expected exactly the visible onnx to be validated, got %d clean (%+v)", cleanCount, findings)
	}
}

// ── varint round-trip sanity ────────────────────────────────────────────────
//
// Catches accidental endian swaps in the local helpers — if writeVarint is
// wrong, every other test silently produces malformed fixtures.

func TestONNXTestHelpers_VarintRoundTrip(t *testing.T) {
	tests := []uint64{0, 1, 127, 128, 255, 256, 16383, 16384, 1 << 32, 1 << 63}
	for _, n := range tests {
		var buf bytes.Buffer
		writeVarint(&buf, n)

		// Decode using the same logic providers/onnx.go uses internally.
		var got uint64
		var shift uint
		ok := false
		for _, b := range buf.Bytes() {
			got |= uint64(b&0x7F) << shift
			if b < 0x80 {
				ok = true
				break
			}
			shift += 7
		}
		if !ok {
			t.Errorf("varint %d did not terminate", n)
			continue
		}
		if got != n {
			t.Errorf("varint round-trip: wrote %d, decoded %d", n, got)
		}
	}
}

// Belt-and-braces sanity: the test helpers must not silently go big-endian on
// some future Go release (they shouldn't — varint is independent of host
// endianness — but readers benefit from an explicit check).
func TestONNXTestHelpers_NotBigEndian(t *testing.T) {
	var buf bytes.Buffer
	writeVarint(&buf, 0x80)
	got := buf.Bytes()
	want := []byte{0x80, 0x01} // varint encoding of 128 is two bytes: 0x80 0x01
	if !bytes.Equal(got, want) {
		t.Errorf("writeVarint(128) = %x, want %x", got, want)
	}
	// Also ensure the binary package agrees on uint64 little-endian for fixed
	// fields in case we ever add fixed64 emission.
	var fb [8]byte
	binary.LittleEndian.PutUint64(fb[:], 1)
	if fb[0] != 1 {
		t.Errorf("LittleEndian PutUint64 unexpected: %x", fb)
	}
}
