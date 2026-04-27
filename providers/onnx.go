package providers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/oxvault/scanner/patterns"
)

// ONNX structural validator — pure-Go protobuf wire walker.
//
// The validator parses ONNX models AT THE WIRE LEVEL — it does NOT vendor the
// onnx.proto schema or generate Go bindings. We only reach for the handful of
// fields we need for security validation:
//
//   ModelProto:
//     1  ir_version       (int64,   varint)
//     2  producer_name    (string,  length-delimited)
//     7  graph            (message, length-delimited)
//
//   GraphProto:
//     1  node             (repeated NodeProto)
//     5  initializer      (repeated TensorProto)
//
//   NodeProto:
//     4  op_type          (string)
//     7  domain           (string)
//
//   TensorProto:
//     1  dims             (repeated int64; both packed and unpacked tolerated)
//     13 external_data    (repeated StringStringEntryProto)
//
//   StringStringEntryProto:
//     1  key              (string)
//     2  value            (string)
//
// The walker enforces strict bounds — it never trusts a length-prefix without
// checking the remaining buffer, and it caps the file size at maxOnnxFileBytes
// to refuse pathologically large inputs. A malformed wire encoding emits a
// single aibom-onnx-malformed-protobuf finding and stops walking that subtree.

// ── protobuf wire-format primitives ─────────────────────────────────────────

// Wire types per https://protobuf.dev/programming-guides/encoding/
const (
	wireVarint     = 0
	wireFixed64    = 1
	wireLenDelim   = 2
	wireStartGroup = 3
	wireEndGroup   = 4
	wireFixed32    = 5
)

// readVarint decodes a base-128 varint from buf at pos. Returns the value and
// the new position. An EOF or a varint longer than 10 bytes returns an error.
func readVarint(buf []byte, pos int) (uint64, int, error) {
	var v uint64
	var shift uint
	start := pos
	for i := 0; i < 10; i++ {
		if pos >= len(buf) {
			return 0, start, io.ErrUnexpectedEOF
		}
		b := buf[pos]
		pos++
		v |= uint64(b&0x7F) << shift
		if b < 0x80 {
			return v, pos, nil
		}
		shift += 7
	}
	return 0, start, errors.New("varint exceeds 10 bytes")
}

// readTag splits a varint-encoded tag into its (field_number, wire_type) pair.
func readTag(buf []byte, pos int) (fieldNum uint32, wireType uint8, newPos int, err error) {
	tag, np, err := readVarint(buf, pos)
	if err != nil {
		return 0, 0, pos, err
	}
	return uint32(tag >> 3), uint8(tag & 0x07), np, nil
}

// readLenDelim returns a slice referencing the bytes for a length-delimited
// field at pos and the position immediately after.
func readLenDelim(buf []byte, pos int) ([]byte, int, error) {
	n, np, err := readVarint(buf, pos)
	if err != nil {
		return nil, pos, err
	}
	end := np + int(n)
	if int(n) < 0 || end < np || end > len(buf) {
		return nil, pos, fmt.Errorf("length-delimited field out of bounds (len=%d, remaining=%d)", n, len(buf)-np)
	}
	return buf[np:end], end, nil
}

// skipField advances past a single field of the given wire type.
func skipField(buf []byte, pos int, wireType uint8) (int, error) {
	switch wireType {
	case wireVarint:
		_, np, err := readVarint(buf, pos)
		return np, err
	case wireFixed64:
		if pos+8 > len(buf) {
			return pos, io.ErrUnexpectedEOF
		}
		return pos + 8, nil
	case wireLenDelim:
		_, np, err := readLenDelim(buf, pos)
		return np, err
	case wireFixed32:
		if pos+4 > len(buf) {
			return pos, io.ErrUnexpectedEOF
		}
		return pos + 4, nil
	case wireStartGroup, wireEndGroup:
		// Groups are deprecated in proto3 and never appear in real ONNX.
		// Refuse rather than try to balance them.
		return pos, fmt.Errorf("groups not supported")
	default:
		return pos, fmt.Errorf("unknown wire type %d", wireType)
	}
}

// ── validator ───────────────────────────────────────────────────────────────

// onnxValidator is the production ONNXValidator. Stateless — every call to
// ValidateFile / ValidateDirectory works against a fresh byte buffer.
type onnxValidator struct{}

// NewONNXValidator returns an ONNXValidator.
func NewONNXValidator() ONNXValidator {
	return &onnxValidator{}
}

// ValidateFile inspects a single .onnx file at path. Returns one Finding per
// rule violation, plus an aibom-onnx-clean INFO finding when every check
// passes.
func (o *onnxValidator) ValidateFile(path string) []Finding {
	return validateOnnxFile(path)
}

// ValidateDirectory walks dir and validates every *.onnx file found.
//
// In production the AIBOMComposer owns directory walking, so this method is
// rarely called — but keeping it functional satisfies the interface and
// makes the validator usable standalone.
func (o *onnxValidator) ValidateDirectory(dir string) []Finding {
	var findings []Finding
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if info.IsDir() {
			if IsExcludedDir(filepath.Base(path)) {
				return filepath.SkipDir
			}
			return nil
		}
		if DetectArtifactFormat(path) != FormatONNX {
			return nil
		}
		findings = append(findings, validateOnnxFile(path)...)
		return nil
	})
	return findings
}

// onnxScan accumulates the state extracted while walking one ModelProto.
type onnxScan struct {
	path string

	hasIRVersion bool
	producerName string

	findings []Finding
}

// emit appends a Finding with the standard ConfidenceLabel populated.
func (s *onnxScan) emit(f Finding) {
	if f.ConfidenceLabel == "" {
		f.ConfidenceLabel = f.Confidence.String()
	}
	if f.File == "" {
		f.File = s.path
	}
	s.findings = append(s.findings, f)
}

// validateOnnxFile is the shared entry point for both ValidateFile and
// ValidateDirectory. It performs all checks in a single pass.
func validateOnnxFile(path string) []Finding {
	f, err := os.Open(path) //nolint:gosec // path comes from filesystem walks scoped to the scan target.
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		return nil
	}
	fileSize := stat.Size()

	// Reject pathologically large files before reading them. ONNX models
	// can be large but >4 GiB is unrealistic and a hostile producer that
	// declares a multi-TB file would otherwise force us into a huge alloc.
	if fileSize > patterns.MaxOnnxFileBytes {
		return []Finding{{
			Rule:            "aibom-onnx-malformed-protobuf",
			Severity:        SeverityHigh,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message: fmt.Sprintf(
				"onnx file is %d bytes — exceeds the %d-byte safety cap",
				fileSize, patterns.MaxOnnxFileBytes),
			CWE: "CWE-1284",
		}}
	}

	// Reject empty files outright — they cannot be valid protobuf.
	if fileSize == 0 {
		return []Finding{{
			Rule:            "aibom-onnx-malformed-protobuf",
			Severity:        SeverityHigh,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message:         "onnx file is empty",
			CWE:             "CWE-1284",
		}}
	}

	// Bounded read: peek one extra byte so we can distinguish a clean read
	// from one that hit the cap mid-stream (matches pickle.go's pattern).
	limited := io.LimitReader(f, patterns.MaxOnnxFileBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return []Finding{{
			Rule:            "aibom-onnx-malformed-protobuf",
			Severity:        SeverityHigh,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message:         "could not read onnx file: " + err.Error(),
			CWE:             "CWE-1284",
		}}
	}
	if int64(len(data)) > patterns.MaxOnnxFileBytes {
		return []Finding{{
			Rule:            "aibom-onnx-malformed-protobuf",
			Severity:        SeverityHigh,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message: fmt.Sprintf(
				"onnx file exceeds %d-byte safety cap during read",
				patterns.MaxOnnxFileBytes),
			CWE: "CWE-1284",
		}}
	}

	scan := &onnxScan{path: path}

	// Defensive: a malformed wire encoding must NEVER take down the scanner.
	// Wire walkers are bounds-checked, but a recover keeps us safe against
	// any unforeseen edge case (e.g. a future stdlib bug).
	defer func() {
		if r := recover(); r != nil {
			scan.emit(Finding{
				Rule:       "aibom-onnx-malformed-protobuf",
				Severity:   SeverityHigh,
				Confidence: ConfidenceHigh,
				Message:    fmt.Sprintf("panic during onnx walk: %v", r),
				CWE:        "CWE-1284",
			})
		}
	}()

	if err := walkModelProto(scan, data); err != nil {
		scan.emit(Finding{
			Rule:       "aibom-onnx-malformed-protobuf",
			Severity:   SeverityHigh,
			Confidence: ConfidenceHigh,
			Message:    "onnx wire format is malformed: " + err.Error(),
			CWE:        "CWE-1284",
		})
		return scan.findings
	}

	// Producer name absence is informational — not every producer sets it.
	missingProducer := strings.TrimSpace(scan.producerName) == ""
	if missingProducer {
		scan.emit(Finding{
			Rule:       "aibom-onnx-missing-producer",
			Severity:   SeverityInfo,
			Confidence: ConfidenceHigh,
			Message:    "onnx model declares no producer_name — provenance is missing",
		})
	}

	// Surface a clean INFO when neither a violation NOR the missing-producer
	// signal fired, so reports are not silent on safe files (mirrors the
	// safetensors validator's clean rule).
	if !hasViolation(scan.findings) && !missingProducer {
		scan.emit(Finding{
			Rule:       "aibom-onnx-clean",
			Severity:   SeverityInfo,
			Confidence: ConfidenceHigh,
			Message:    "onnx model is structurally well-formed",
		})
	}

	return scan.findings
}

// hasViolation returns true when at least one finding has Severity > Info.
func hasViolation(findings []Finding) bool {
	for _, f := range findings {
		if f.Severity > SeverityInfo {
			return true
		}
	}
	return false
}

// ── ModelProto walker ───────────────────────────────────────────────────────

// walkModelProto walks the top-level ModelProto fields. Unknown fields are
// skipped — onnx adds new top-level fields over time and an unknown field is
// not by itself a security issue.
func walkModelProto(scan *onnxScan, buf []byte) error {
	pos := 0
	for pos < len(buf) {
		fieldNum, wireType, np, err := readTag(buf, pos)
		if err != nil {
			return err
		}
		pos = np

		switch fieldNum {
		case 1: // ir_version (int64 varint)
			if wireType != wireVarint {
				if pos, err = skipField(buf, pos, wireType); err != nil {
					return err
				}
				continue
			}
			_, np, err := readVarint(buf, pos)
			if err != nil {
				return err
			}
			scan.hasIRVersion = true
			pos = np

		case 2: // producer_name (string)
			if wireType != wireLenDelim {
				if pos, err = skipField(buf, pos, wireType); err != nil {
					return err
				}
				continue
			}
			s, np, err := readLenDelim(buf, pos)
			if err != nil {
				return err
			}
			scan.producerName = string(s)
			pos = np

		case 7: // graph (GraphProto, length-delimited)
			if wireType != wireLenDelim {
				if pos, err = skipField(buf, pos, wireType); err != nil {
					return err
				}
				continue
			}
			s, np, err := readLenDelim(buf, pos)
			if err != nil {
				return err
			}
			if err := walkGraphProto(scan, s); err != nil {
				return err
			}
			pos = np

		default:
			if pos, err = skipField(buf, pos, wireType); err != nil {
				return err
			}
		}
	}
	return nil
}

// ── GraphProto walker ───────────────────────────────────────────────────────

// walkGraphProto walks GraphProto.node[*] and GraphProto.initializer[*].
// All other fields are skipped.
func walkGraphProto(scan *onnxScan, buf []byte) error {
	pos := 0
	for pos < len(buf) {
		fieldNum, wireType, np, err := readTag(buf, pos)
		if err != nil {
			return err
		}
		pos = np

		switch fieldNum {
		case 1: // node (NodeProto)
			if wireType != wireLenDelim {
				if pos, err = skipField(buf, pos, wireType); err != nil {
					return err
				}
				continue
			}
			s, np, err := readLenDelim(buf, pos)
			if err != nil {
				return err
			}
			if err := walkNodeProto(scan, s); err != nil {
				return err
			}
			pos = np

		case 5: // initializer (TensorProto)
			if wireType != wireLenDelim {
				if pos, err = skipField(buf, pos, wireType); err != nil {
					return err
				}
				continue
			}
			s, np, err := readLenDelim(buf, pos)
			if err != nil {
				return err
			}
			if err := walkTensorProto(scan, s); err != nil {
				return err
			}
			pos = np

		default:
			if pos, err = skipField(buf, pos, wireType); err != nil {
				return err
			}
		}
	}
	return nil
}

// ── NodeProto walker ────────────────────────────────────────────────────────

// walkNodeProto extracts op_type (field 4) and domain (field 7), then emits
// custom-operator / suspicious-op findings as appropriate.
func walkNodeProto(scan *onnxScan, buf []byte) error {
	var opType, domain string
	pos := 0
	for pos < len(buf) {
		fieldNum, wireType, np, err := readTag(buf, pos)
		if err != nil {
			return err
		}
		pos = np

		switch fieldNum {
		case 4: // op_type (string)
			if wireType != wireLenDelim {
				if pos, err = skipField(buf, pos, wireType); err != nil {
					return err
				}
				continue
			}
			s, np, err := readLenDelim(buf, pos)
			if err != nil {
				return err
			}
			opType = string(s)
			pos = np

		case 7: // domain (string)
			if wireType != wireLenDelim {
				if pos, err = skipField(buf, pos, wireType); err != nil {
					return err
				}
				continue
			}
			s, np, err := readLenDelim(buf, pos)
			if err != nil {
				return err
			}
			domain = string(s)
			pos = np

		default:
			if pos, err = skipField(buf, pos, wireType); err != nil {
				return err
			}
		}
	}

	classifyOnnxOperator(scan, opType, domain)
	return nil
}

// classifyOnnxOperator emits findings for a single (op_type, domain) pair.
//
//   - If domain matches a known-suspicious substring (URL, slash, contrib.malicious),
//     emit aibom-onnx-suspicious-op at HIGH.
//   - Else if domain is non-standard, emit aibom-onnx-custom-operator at WARNING.
//   - Else emit nothing — the operator is from a standard ONNX domain.
func classifyOnnxOperator(scan *onnxScan, opType, domain string) {
	lower := strings.ToLower(domain)
	for _, sub := range patterns.ONNXSuspiciousDomainSubstrings {
		if strings.Contains(lower, sub) {
			scan.emit(Finding{
				Rule:       "aibom-onnx-suspicious-op",
				Severity:   SeverityHigh,
				Confidence: ConfidenceMedium,
				Message: fmt.Sprintf(
					"operator %q references suspicious domain %q (matched %q)",
					opType, domain, sub),
				CWE: "CWE-829",
			})
			return
		}
	}
	if !patterns.ONNXStandardDomains[domain] {
		scan.emit(Finding{
			Rule:       "aibom-onnx-custom-operator",
			Severity:   SeverityWarning,
			Confidence: ConfidenceMedium,
			Message: fmt.Sprintf(
				"operator %q uses non-standard domain %q — runtime requires custom kernel",
				opType, domain),
			CWE: "CWE-829",
		})
	}
}

// ── TensorProto walker ──────────────────────────────────────────────────────

// walkTensorProto extracts dims (field 1) and external_data (field 13). Dims
// can be encoded packed (preferred for proto3 repeated scalars) or unpacked
// (legacy form), so we honour both.
func walkTensorProto(scan *onnxScan, buf []byte) error {
	var dimProduct uint64 = 1
	var hasDims bool
	var overflow bool

	pos := 0
	for pos < len(buf) {
		fieldNum, wireType, np, err := readTag(buf, pos)
		if err != nil {
			return err
		}
		pos = np

		switch fieldNum {
		case 1: // dims — packed (length-delimited) or unpacked (varint per entry)
			switch wireType {
			case wireVarint:
				v, np, err := readVarint(buf, pos)
				if err != nil {
					return err
				}
				hasDims = true
				dimProduct, overflow = mulOverflow(dimProduct, v, overflow)
				pos = np
			case wireLenDelim:
				s, np, err := readLenDelim(buf, pos)
				if err != nil {
					return err
				}
				hasDims = true
				inner := 0
				for inner < len(s) {
					v, ni, err := readVarint(s, inner)
					if err != nil {
						return err
					}
					dimProduct, overflow = mulOverflow(dimProduct, v, overflow)
					inner = ni
				}
				pos = np
			default:
				if pos, err = skipField(buf, pos, wireType); err != nil {
					return err
				}
			}

		case 13: // external_data (StringStringEntryProto)
			if wireType != wireLenDelim {
				if pos, err = skipField(buf, pos, wireType); err != nil {
					return err
				}
				continue
			}
			s, np, err := readLenDelim(buf, pos)
			if err != nil {
				return err
			}
			if err := walkExternalDataEntry(scan, s); err != nil {
				return err
			}
			pos = np

		default:
			if pos, err = skipField(buf, pos, wireType); err != nil {
				return err
			}
		}
	}

	if hasDims && (overflow || dimProduct > patterns.MaxOnnxTensorElements) {
		scan.emit(Finding{
			Rule:       "aibom-onnx-oversized-tensor",
			Severity:   SeverityWarning,
			Confidence: ConfidenceMedium,
			Message: fmt.Sprintf(
				"initializer declares %s elements (cap %d) — possible DoS or hostile inflate",
				formatDimProduct(dimProduct, overflow), patterns.MaxOnnxTensorElements),
			CWE: "CWE-400",
		})
	}
	return nil
}

// mulOverflow multiplies acc by v and reports whether the running product has
// overflowed uint64 at any point. Once overflow is set it remains set.
func mulOverflow(acc, v uint64, alreadyOverflowed bool) (uint64, bool) {
	if alreadyOverflowed {
		return acc, true
	}
	if v == 0 {
		return 0, false
	}
	if acc > (^uint64(0))/v {
		return acc, true
	}
	return acc * v, false
}

// formatDimProduct renders the dim product, marking saturated values clearly.
func formatDimProduct(p uint64, overflow bool) string {
	if overflow {
		return ">2^64 (overflow)"
	}
	return fmt.Sprintf("%d", p)
}

// walkExternalDataEntry walks a StringStringEntryProto. We only care when
// key == "location" — that's the value an inference runtime would use to
// fopen() the external tensor data.
func walkExternalDataEntry(scan *onnxScan, buf []byte) error {
	var key, value string
	pos := 0
	for pos < len(buf) {
		fieldNum, wireType, np, err := readTag(buf, pos)
		if err != nil {
			return err
		}
		pos = np

		switch fieldNum {
		case 1: // key
			if wireType != wireLenDelim {
				if pos, err = skipField(buf, pos, wireType); err != nil {
					return err
				}
				continue
			}
			s, np, err := readLenDelim(buf, pos)
			if err != nil {
				return err
			}
			key = string(s)
			pos = np

		case 2: // value
			if wireType != wireLenDelim {
				if pos, err = skipField(buf, pos, wireType); err != nil {
					return err
				}
				continue
			}
			s, np, err := readLenDelim(buf, pos)
			if err != nil {
				return err
			}
			value = string(s)
			pos = np

		default:
			if pos, err = skipField(buf, pos, wireType); err != nil {
				return err
			}
		}
	}

	if key != "location" || value == "" {
		return nil
	}
	if isUnsafeExternalLocation(value) {
		scan.emit(Finding{
			Rule:       "aibom-onnx-external-data",
			Severity:   SeverityWarning,
			Confidence: ConfidenceHigh,
			Message: fmt.Sprintf(
				"initializer external_data location %q escapes the model directory or references a remote scheme",
				value),
			CWE: "CWE-22",
		})
	}
	return nil
}

// isUnsafeExternalLocation returns true when the value would resolve outside
// the model directory or to a remote resource.
//
// Per the ONNX spec the location field MUST be a relative path resolved
// against the model file's directory. Anything else — absolute paths,
// parent-directory traversal, scheme-prefixed URLs — is unsafe.
func isUnsafeExternalLocation(loc string) bool {
	lower := strings.ToLower(loc)

	for _, prefix := range patterns.ONNXSuspiciousExternalDataPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}

	// Absolute POSIX path.
	if strings.HasPrefix(loc, "/") {
		return true
	}
	// Absolute Windows path: C:\ or \\server\share or X:/.
	if len(loc) >= 2 && loc[1] == ':' {
		return true
	}
	if strings.HasPrefix(loc, "\\\\") {
		return true
	}

	// Parent-directory traversal in ANY normalised form.
	cleaned := filepath.ToSlash(filepath.Clean(loc))
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return true
	}
	// Defence in depth — the raw form ALSO contains a ".." segment.
	if strings.Contains(loc, "..") {
		segments := strings.FieldsFunc(loc, func(r rune) bool { return r == '/' || r == '\\' })
		for _, seg := range segments {
			if seg == ".." {
				return true
			}
		}
	}
	return false
}

// ── compile-time interface guard ────────────────────────────────────────────

var _ ONNXValidator = (*onnxValidator)(nil)

// ── unused helpers retained for future use ──────────────────────────────────

// readFixed64LE decodes a little-endian uint64 — kept for future fields.
//
//nolint:unused // Reserved for future field decoding (e.g. raw_data parsing).
func readFixed64LE(buf []byte, pos int) (uint64, int, error) {
	if pos+8 > len(buf) {
		return 0, pos, io.ErrUnexpectedEOF
	}
	return binary.LittleEndian.Uint64(buf[pos : pos+8]), pos + 8, nil
}
