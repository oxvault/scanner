package providers

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/oxvault/scanner/patterns"
)

// Safetensors header validator.
//
// File format (HuggingFace safetensors v0):
//
//   ┌────────────────────────────────────────────────────────────────────┐
//   │ 8 bytes  | header_length (uint64, little-endian)                   │
//   │ N bytes  | UTF-8 JSON header — { "name": {...}, "__metadata__":{}} │
//   │ M bytes  | raw tensor payload (offsets in header are payload-rel.) │
//   └────────────────────────────────────────────────────────────────────┘
//
// The validator NEVER loads tensor data into memory and NEVER trusts the
// header — every offset is bounds-checked against the actual file size, and
// the header itself is capped at maxSafetensorsHeaderBytes to prevent a
// hostile producer from forcing a huge JSON allocation.

const (
	// safetensorsLengthPrefix is the fixed 8-byte little-endian length prefix
	// at the start of every safetensors file.
	safetensorsLengthPrefix = 8

	// maxSafetensorsHeaderBytes caps the size of the JSON header. 100 MiB is
	// more than three orders of magnitude beyond any realistic header — even
	// a model with 100k tensors fits well under 10 MiB.
	maxSafetensorsHeaderBytes = 100 * 1024 * 1024 // 100 MiB
)

// safetensorsValidator is the production SafetensorsValidator. Stateless —
// every call to ValidateFile / ValidateDirectory works against a fresh
// rule-matcher and accumulates findings locally.
type safetensorsValidator struct {
	rules RuleMatcher
}

// NewSafetensorsValidator returns a SafetensorsValidator wired with a
// production RuleMatcher. The validator delegates metadata-content scans to
// the RuleMatcher's ScanDescription so prompt-injection detection stays in
// a single place.
func NewSafetensorsValidator() SafetensorsValidator {
	return &safetensorsValidator{rules: NewRuleMatcher()}
}

// ValidateFile inspects a single .safetensors file at path. Returns one
// Finding per rule violation, plus an aibom-safetensors-clean INFO finding
// when every check passes.
func (s *safetensorsValidator) ValidateFile(path string) []Finding {
	return s.validateFile(path)
}

// ValidateDirectory walks dir and validates every *.safetensors file found.
//
// In production the AIBOMComposer owns directory walking, so this method is
// rarely called — but keeping it functional satisfies the interface and
// makes the validator usable standalone.
func (s *safetensorsValidator) ValidateDirectory(dir string) []Finding {
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
		if DetectArtifactFormat(path) != FormatSafetensors {
			return nil
		}
		findings = append(findings, s.validateFile(path)...)
		return nil
	})
	return findings
}

// ── header parsing ──────────────────────────────────────────────────────────

// safetensorsHeader is the on-disk JSON header. Every entry except the
// reserved "__metadata__" key is a tensor descriptor.
type safetensorsHeader = map[string]json.RawMessage

// safetensorsTensor mirrors the per-tensor schema of the safetensors spec.
type safetensorsTensor struct {
	Dtype       string `json:"dtype"`
	Shape       []int  `json:"shape"`
	DataOffsets [2]int `json:"data_offsets"`
}

// validateFile is the actual entry point. It performs ALL checks in a single
// pass and returns either a list of violation findings, or — when the file
// is fully valid — a single aibom-safetensors-clean INFO finding.
func (s *safetensorsValidator) validateFile(path string) []Finding {
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

	// Reject files that cannot possibly contain a length prefix.
	if fileSize < safetensorsLengthPrefix {
		return []Finding{{
			Rule:            "aibom-safetensors-header-overflow",
			Severity:        SeverityCritical,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message:         fmt.Sprintf("file is %d bytes — cannot contain the 8-byte safetensors length prefix", fileSize),
			CWE:             "CWE-1284",
		}}
	}

	// Read the 8-byte length prefix.
	prefix := make([]byte, safetensorsLengthPrefix)
	if _, err := io.ReadFull(f, prefix); err != nil {
		return []Finding{{
			Rule:            "aibom-safetensors-header-overflow",
			Severity:        SeverityCritical,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message:         "could not read 8-byte safetensors length prefix: " + err.Error(),
			CWE:             "CWE-1284",
		}}
	}
	headerLen := binary.LittleEndian.Uint64(prefix)

	// Empty header — strictly malformed under the spec.
	if headerLen == 0 {
		return []Finding{{
			Rule:            "aibom-safetensors-empty-header",
			Severity:        SeverityWarning,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message:         "safetensors header length is 0 — file declares no tensors",
			CWE:             "CWE-1284",
		}}
	}

	// Header overflow checks: must fit in the file AND under the configured cap.
	if headerLen > maxSafetensorsHeaderBytes {
		return []Finding{{
			Rule:            "aibom-safetensors-header-overflow",
			Severity:        SeverityCritical,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message: fmt.Sprintf(
				"safetensors header length %d exceeds the %d-byte safety cap",
				headerLen, maxSafetensorsHeaderBytes),
			CWE: "CWE-1284",
		}}
	}
	if int64(headerLen) > fileSize-safetensorsLengthPrefix {
		return []Finding{{
			Rule:            "aibom-safetensors-header-overflow",
			Severity:        SeverityCritical,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message: fmt.Sprintf(
				"safetensors header length %d exceeds remaining file size %d",
				headerLen, fileSize-safetensorsLengthPrefix),
			CWE: "CWE-1284",
		}}
	}

	// Read the JSON header.
	headerBytes := make([]byte, headerLen)
	if _, err := io.ReadFull(f, headerBytes); err != nil {
		return []Finding{{
			Rule:            "aibom-safetensors-header-overflow",
			Severity:        SeverityCritical,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message:         "could not read declared header bytes: " + err.Error(),
			CWE:             "CWE-1284",
		}}
	}

	header := safetensorsHeader{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return []Finding{{
			Rule:            "aibom-safetensors-malformed-json",
			Severity:        SeverityHigh,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message:         "safetensors header is not valid JSON: " + err.Error(),
			CWE:             "CWE-1284",
		}}
	}

	// Pre-decode raw-header sweep for pickle magic JSON-escape sequences. JSON
	// cannot encode 0x80 directly (invalid UTF-8), so a real attacker is
	// forced to use -style escapes; we catch them on the wire before
	// any UTF-8 round-tripping has a chance to mask the bytes.
	rawHeaderFindings := scanRawHeaderForPickle(path, headerBytes)

	// Tensor data lives AFTER the header. Offsets are payload-relative, so
	// the maximum legal end-offset is fileSize - 8 - headerLen.
	payloadSize := fileSize - safetensorsLengthPrefix - int64(headerLen)

	var findings []Finding
	findings = append(findings, rawHeaderFindings...)

	// Walk the header entries. Sort keys so test output is deterministic
	// (Go's map iteration order is randomised).
	keys := make([]string, 0, len(header))
	for k := range header {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	type tensorRange struct {
		name  string
		start int
		end   int
	}
	var ranges []tensorRange

	for _, name := range keys {
		raw := header[name]

		if name == "__metadata__" {
			findings = append(findings, s.scanMetadata(path, raw)...)
			continue
		}

		var tensor safetensorsTensor
		if err := json.Unmarshal(raw, &tensor); err != nil {
			findings = append(findings, Finding{
				Rule:            "aibom-safetensors-malformed-json",
				Severity:        SeverityHigh,
				Confidence:      ConfidenceHigh,
				ConfidenceLabel: ConfidenceHigh.String(),
				File:            path,
				Message:         fmt.Sprintf("tensor %q has malformed descriptor: %v", name, err),
				CWE:             "CWE-1284",
			})
			continue
		}

		// Validate dtype.
		if !patterns.ValidSafetensorDtypes[tensor.Dtype] {
			findings = append(findings, Finding{
				Rule:            "aibom-safetensors-invalid-dtype",
				Severity:        SeverityWarning,
				Confidence:      ConfidenceHigh,
				ConfidenceLabel: ConfidenceHigh.String(),
				File:            path,
				Message:         fmt.Sprintf("tensor %q has unknown dtype %q", name, tensor.Dtype),
				CWE:             "CWE-20",
			})
		}

		// Validate shape — every dim must be non-negative.
		for i, dim := range tensor.Shape {
			if dim < 0 {
				findings = append(findings, Finding{
					Rule:            "aibom-safetensors-malformed-json",
					Severity:        SeverityHigh,
					Confidence:      ConfidenceHigh,
					ConfidenceLabel: ConfidenceHigh.String(),
					File:            path,
					Message:         fmt.Sprintf("tensor %q shape[%d] is negative: %d", name, i, dim),
					CWE:             "CWE-1284",
				})
			}
		}

		// Validate offsets.
		start, end := tensor.DataOffsets[0], tensor.DataOffsets[1]
		if start < 0 || end < 0 || end < start {
			findings = append(findings, Finding{
				Rule:            "aibom-safetensors-tensor-overflow",
				Severity:        SeverityHigh,
				Confidence:      ConfidenceHigh,
				ConfidenceLabel: ConfidenceHigh.String(),
				File:            path,
				Message: fmt.Sprintf(
					"tensor %q has invalid data_offsets [%d, %d]",
					name, start, end),
				CWE: "CWE-1284",
			})
			continue
		}
		if int64(end) > payloadSize {
			findings = append(findings, Finding{
				Rule:            "aibom-safetensors-tensor-overflow",
				Severity:        SeverityHigh,
				Confidence:      ConfidenceHigh,
				ConfidenceLabel: ConfidenceHigh.String(),
				File:            path,
				Message: fmt.Sprintf(
					"tensor %q data_offset end %d exceeds payload size %d",
					name, end, payloadSize),
				CWE: "CWE-1284",
			})
			continue
		}

		ranges = append(ranges, tensorRange{name: name, start: start, end: end})
	}

	// Detect overlapping byte ranges. Sort by start, scan once.
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].start != ranges[j].start {
			return ranges[i].start < ranges[j].start
		}
		return ranges[i].end < ranges[j].end
	})
	for i := 1; i < len(ranges); i++ {
		prev := ranges[i-1]
		cur := ranges[i]
		// Overlap exists when the next tensor begins before the previous one ends.
		// safetensors offsets are half-open [start, end), so equality is fine.
		if cur.start < prev.end {
			findings = append(findings, Finding{
				Rule:            "aibom-safetensors-overlapping-tensors",
				Severity:        SeverityHigh,
				Confidence:      ConfidenceHigh,
				ConfidenceLabel: ConfidenceHigh.String(),
				File:            path,
				Message: fmt.Sprintf(
					"tensors %q [%d,%d) and %q [%d,%d) claim overlapping byte ranges",
					prev.name, prev.start, prev.end, cur.name, cur.start, cur.end),
				CWE: "CWE-1284",
			})
		}
	}

	if len(findings) == 0 {
		return []Finding{{
			Rule:            "aibom-safetensors-clean",
			Severity:        SeverityInfo,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message: fmt.Sprintf(
				"safetensors header is well-formed (%d tensors, %d header bytes)",
				countTensors(header), headerLen),
		}}
	}
	return findings
}

// scanMetadata inspects the `__metadata__` map for prompt-injection,
// shell metacharacters, URLs, and pickle magic bytes. It delegates the
// prompt-injection portion to RuleMatcher.ScanDescription so detection
// patterns stay centralised.
func (s *safetensorsValidator) scanMetadata(path string, raw json.RawMessage) []Finding {
	var meta map[string]string
	if err := json.Unmarshal(raw, &meta); err != nil {
		return []Finding{{
			Rule:            "aibom-safetensors-malformed-json",
			Severity:        SeverityHigh,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message:         "__metadata__ is not a string→string map: " + err.Error(),
			CWE:             "CWE-1284",
		}}
	}

	// Sort keys for deterministic ordering.
	keys := make([]string, 0, len(meta))
	for k := range meta {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var findings []Finding
	for _, k := range keys {
		v := meta[k]

		// Reuse the production prompt-injection scanner. Each finding is
		// re-tagged with a safetensors-scoped rule id so users can filter
		// AIBOM findings discretely from MCP tool descriptions.
		for _, f := range s.rules.ScanDescription(v) {
			findings = append(findings, Finding{
				Rule:            "aibom-safetensors-suspicious-metadata",
				Severity:        SeverityWarning,
				Confidence:      ConfidenceMedium,
				ConfidenceLabel: ConfidenceMedium.String(),
				File:            path,
				Message: fmt.Sprintf(
					"metadata key %q matched %s: %s",
					k, f.Rule, f.Message),
				CWE: "CWE-20",
			})
		}

		// Shell metacharacters.
		for _, mc := range patterns.SafetensorsShellMetacharacters {
			if strings.Contains(v, mc) {
				findings = append(findings, Finding{
					Rule:            "aibom-safetensors-suspicious-metadata",
					Severity:        SeverityWarning,
					Confidence:      ConfidenceMedium,
					ConfidenceLabel: ConfidenceMedium.String(),
					File:            path,
					Message: fmt.Sprintf(
						"metadata key %q contains shell metacharacter %q",
						k, mc),
					CWE: "CWE-20",
				})
				break
			}
		}

		// URL / scheme prefixes.
		lower := strings.ToLower(v)
		for _, prefix := range patterns.SafetensorsURLPrefixes {
			if strings.Contains(lower, prefix) {
				findings = append(findings, Finding{
					Rule:            "aibom-safetensors-suspicious-metadata",
					Severity:        SeverityWarning,
					Confidence:      ConfidenceMedium,
					ConfidenceLabel: ConfidenceMedium.String(),
					File:            path,
					Message: fmt.Sprintf(
						"metadata key %q contains URL/scheme %q",
						k, prefix),
					CWE: "CWE-20",
				})
				break
			}
		}

		// NOTE: pickle-magic bytes are deliberately NOT scanned here.
		// JSON cannot encode raw 0x80 (invalid UTF-8) — the decoded string
		// `v` will never contain "\x80\x02..." literally; an attacker is
		// forced to use \uXXXX escapes which decode to UTF-8 sequences like
		// "\xc2\x80\x02". Detection of the on-disk escaped form happens in
		// scanRawHeaderForPickle (PRE-decode); a post-decode scan over `v`
		// would be dead code, so it is omitted.
	}
	return findings
}

// scanRawHeaderForPickle inspects the JSON header bytes (PRE-decode) for
// pickle protocol-2/3/4/5 magic bytes encoded as -style JSON escapes.
// Any match emits a suspicious-metadata finding. Detection is case-insensitive
// because JSON spec allows both upper- and lower-case hex digits.
func scanRawHeaderForPickle(path string, raw []byte) []Finding {
	lower := strings.ToLower(string(raw))
	var findings []Finding
	for _, esc := range patterns.SafetensorsPickleMagicEscapes {
		if strings.Contains(lower, strings.ToLower(esc)) {
			findings = append(findings, Finding{
				Rule:            "aibom-safetensors-suspicious-metadata",
				Severity:        SeverityWarning,
				Confidence:      ConfidenceMedium,
				ConfidenceLabel: ConfidenceMedium.String(),
				File:            path,
				Message: fmt.Sprintf(
					"header bytes contain JSON-escaped pickle protocol magic %q",
					esc),
				CWE: "CWE-20",
			})
			return findings // one is enough — avoid noisy duplicates
		}
	}
	return findings
}

// countTensors returns the number of tensor entries in the header, ignoring
// the reserved `__metadata__` key.
func countTensors(h safetensorsHeader) int {
	n := 0
	for k := range h {
		if k != "__metadata__" {
			n++
		}
	}
	return n
}
