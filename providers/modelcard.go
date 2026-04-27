package providers

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/oxvault/scanner/patterns"
)

// Model card checker.
//
// Validates HuggingFace / OpenSSF model cards (README.md, MODEL_CARD.md,
// model_card.yaml, .modelcard.yaml) for:
//
//   - prompt-injection in card text (delegated to RuleMatcher.ScanDescription)
//   - missing required metadata: license, base_model/source, training data
//   - suspicious claims: accuracy/F1/benchmark numbers without citation
//   - YAML frontmatter parse errors
//
// The checker NEVER renders markdown and NEVER follows links. It only inspects
// raw file bytes — the body is passed verbatim to RuleMatcher.ScanDescription
// so any injection patterns hidden in the markdown are caught by the same
// detector that scans MCP tool descriptions.
//
// Layer rule: providers/ depends on patterns/ only. RuleMatcher is reused via
// the existing provider interface (no cross-package state).

// modelCardChecker is the production ModelCardChecker. The rule-matcher seam
// is exposed via WithModelCardCheckerRuleMatcher so tests can swap the body
// scanner without rewiring the whole composer.
type modelCardChecker struct {
	rules RuleMatcher
}

// ModelCardCheckerOption configures the checker. Follows the same functional-
// option style as the AIBOM composer / app container.
type ModelCardCheckerOption func(*modelCardChecker)

// WithModelCardCheckerRuleMatcher overrides the default RuleMatcher used to
// scan body text for prompt-injection. Useful in tests that want to assert
// delegation or stub out detection.
func WithModelCardCheckerRuleMatcher(rm RuleMatcher) ModelCardCheckerOption {
	return func(m *modelCardChecker) { m.rules = rm }
}

// NewModelCardChecker returns a production ModelCardChecker wired with a
// default RuleMatcher. Equivalent to NewModelCardCheckerWithRuleMatcher(nil).
func NewModelCardChecker(opts ...ModelCardCheckerOption) ModelCardChecker {
	m := &modelCardChecker{}
	for _, opt := range opts {
		opt(m)
	}
	if m.rules == nil {
		m.rules = NewRuleMatcher()
	}
	return m
}

// NewModelCardCheckerWithRuleMatcher returns a ModelCardChecker that delegates
// body scans to the supplied RuleMatcher. Passing nil installs the default.
//
// This is the canonical factory for callers (e.g. the AIBOM composer) that
// want to share a RuleMatcher across providers — keeping detection state and
// pattern compilation in a single place.
func NewModelCardCheckerWithRuleMatcher(rm RuleMatcher) ModelCardChecker {
	if rm == nil {
		return NewModelCardChecker()
	}
	return NewModelCardChecker(WithModelCardCheckerRuleMatcher(rm))
}

// CheckFile inspects a single model-card file at path. Returns one Finding
// per rule violation, plus an aibom-modelcard-clean INFO finding when every
// check passes.
//
// Files larger than patterns.MaxModelCardFileBytes are refused (model cards
// are docs — anything beyond 1 MiB is almost certainly not a real card).
func (m *modelCardChecker) CheckFile(path string) []Finding {
	return m.checkFile(path)
}

// CheckDirectory walks dir and checks every model card file it finds. The
// composer owns directory walking in production, so this method is rarely
// called — but keeping it functional satisfies the interface and makes the
// checker usable standalone.
//
// In addition to per-file checks, this method emits a single
// aibom-modelcard-missing WARNING for any directory that contains a model
// artifact (.pkl/.pt/.onnx/.safetensors) but NO model card alongside it.
func (m *modelCardChecker) CheckDirectory(dir string) []Finding {
	var findings []Finding

	// Pass 1: walk every file. Run per-file checks on model cards, and
	// remember which directories saw an artifact and which saw a card.
	hasArtifact := map[string]bool{}
	hasCard := map[string]bool{}

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
		parent := filepath.Dir(path)
		switch DetectArtifactFormat(path) {
		case FormatModelCard:
			hasCard[parent] = true
			findings = append(findings, m.checkFile(path)...)
		case FormatPickle, FormatONNX, FormatSafetensors:
			hasArtifact[parent] = true
		default:
			// nothing
		}
		return nil
	})

	// Pass 2: any directory with an artifact but no card emits the
	// missing-card warning. Do NOT emit when the directory only contains
	// non-artifact files — this is a provenance signal scoped to model
	// directories.
	for parent := range hasArtifact {
		if !hasCard[parent] {
			findings = append(findings, Finding{
				Rule:            "aibom-modelcard-missing",
				Severity:        SeverityWarning,
				Confidence:      ConfidenceHigh,
				ConfidenceLabel: ConfidenceHigh.String(),
				File:            parent,
				Message:         "directory contains model artifacts but no model card (README.md / MODEL_CARD.md) — provenance is missing",
			})
		}
	}
	return findings
}

// ── per-file checker ─────────────────────────────────────────────────────────

// checkFile is the shared entry point for both CheckFile and the per-file
// pass of CheckDirectory.
//
// All checks run in a single pass against an in-memory copy of the file. The
// file is bounded by patterns.MaxModelCardFileBytes to refuse pathological
// inputs.
func (m *modelCardChecker) checkFile(path string) []Finding {
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

	// Refuse oversize files outright. Real model cards are <100 KiB; anything
	// >1 MiB is either generated noise or an attempt to drown the body
	// scanner in irrelevant text.
	if fileSize > patterns.MaxModelCardFileBytes {
		return []Finding{{
			Rule:            "aibom-modelcard-malformed-yaml",
			Severity:        SeverityWarning,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message: fmt.Sprintf(
				"model card is %d bytes — exceeds the %d-byte safety cap",
				fileSize, patterns.MaxModelCardFileBytes),
			CWE: "CWE-20",
		}}
	}

	// Bounded read with peek-one-extra-byte so we detect at-cap files.
	limited := io.LimitReader(f, patterns.MaxModelCardFileBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil
	}

	// Empty file — fail-fast with the malformed-yaml signal so reports never
	// silently pass an empty card.
	if len(data) == 0 {
		return []Finding{{
			Rule:            "aibom-modelcard-malformed-yaml",
			Severity:        SeverityWarning,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message:         "model card file is empty",
			CWE:             "CWE-20",
		}}
	}

	ext := strings.ToLower(filepath.Ext(filepath.Base(path)))
	switch ext {
	case ".yaml", ".yml":
		return m.checkYAMLOnly(path, data)
	default:
		// .md (and the dotted .modelcard.* form is YAML, handled above).
		return m.checkMarkdown(path, data)
	}
}

// ── markdown checker ─────────────────────────────────────────────────────────

// checkMarkdown inspects a `.md` model card. It optionally splits a YAML
// frontmatter block from the body, then runs metadata + body checks.
func (m *modelCardChecker) checkMarkdown(path string, data []byte) []Finding {
	frontmatter, body, hasFrontmatter, parseErr := splitFrontmatter(data)

	var findings []Finding

	// Frontmatter parse failure is its own finding — the rest of the body
	// is still scanned because injection patterns don't depend on YAML.
	var meta map[string]any
	if hasFrontmatter {
		if parseErr != nil {
			findings = append(findings, Finding{
				Rule:            "aibom-modelcard-malformed-yaml",
				Severity:        SeverityWarning,
				Confidence:      ConfidenceHigh,
				ConfidenceLabel: ConfidenceHigh.String(),
				File:            path,
				Message:         "model card YAML frontmatter is malformed: " + parseErr.Error(),
				CWE:             "CWE-20",
			})
		} else {
			meta = frontmatter
		}
	}

	// Metadata + body checks.
	findings = append(findings, m.checkLicense(path, meta, body)...)
	findings = append(findings, m.checkSource(path, meta, body)...)
	findings = append(findings, m.checkEval(path, meta, body)...)
	findings = append(findings, m.checkBodyForInjection(path, body)...)

	if !hasViolation(findings) {
		findings = append(findings, Finding{
			Rule:            "aibom-modelcard-clean",
			Severity:        SeverityInfo,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message:         "model card declares license + source + eval and contains no injection patterns",
		})
	}
	return findings
}

// ── YAML-only checker ────────────────────────────────────────────────────────

// checkYAMLOnly inspects a `.yaml` / `.yml` model card document. The whole
// file is parsed as YAML; there is no markdown body to scan.
func (m *modelCardChecker) checkYAMLOnly(path string, data []byte) []Finding {
	var meta map[string]any
	if err := yaml.Unmarshal(data, &meta); err != nil {
		return []Finding{{
			Rule:            "aibom-modelcard-malformed-yaml",
			Severity:        SeverityWarning,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message:         "model card YAML is malformed: " + err.Error(),
			CWE:             "CWE-20",
		}}
	}

	var findings []Finding
	findings = append(findings, m.checkLicense(path, meta, "")...)
	findings = append(findings, m.checkSource(path, meta, "")...)
	findings = append(findings, m.checkEval(path, meta, "")...)

	// YAML-only cards have no markdown body, so injection scanning would be
	// noisy. We DO scan string values inside the YAML for poisoning — a
	// determined attacker could embed instructions in the `description`
	// field, which is rendered verbatim in some HuggingFace UIs.
	findings = append(findings, m.checkYAMLValuesForInjection(path, meta)...)

	if !hasViolation(findings) {
		findings = append(findings, Finding{
			Rule:            "aibom-modelcard-clean",
			Severity:        SeverityInfo,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message:         "model card declares license + source + eval and contains no injection patterns",
		})
	}
	return findings
}

// ── individual checks ───────────────────────────────────────────────────────

// checkLicense fires aibom-modelcard-no-license when neither the frontmatter
// declares a license key with a non-empty value, nor the body contains a
// "## License" section heading.
func (m *modelCardChecker) checkLicense(path string, meta map[string]any, body string) []Finding {
	if hasNonEmptyKey(meta, patterns.ModelCardLicenseKeys) {
		return nil
	}
	if body != "" && patterns.ModelCardLicenseSectionHeaders.MatchString(body) {
		return nil
	}
	return []Finding{{
		Rule:            "aibom-modelcard-no-license",
		Severity:        SeverityWarning,
		Confidence:      ConfidenceHigh,
		ConfidenceLabel: ConfidenceHigh.String(),
		File:            path,
		Message:         "model card declares no license — neither YAML frontmatter nor a body heading mentions one",
	}}
}

// checkSource fires aibom-modelcard-no-source when neither the frontmatter
// declares a base_model / source / training_data key with a non-empty value,
// nor the body contains an inline reference to a base model or training
// dataset URL.
func (m *modelCardChecker) checkSource(path string, meta map[string]any, body string) []Finding {
	if hasNonEmptyKey(meta, patterns.ModelCardSourceKeys) {
		return nil
	}
	// Body fallback: any heading like "## Base model" / "## Training data"
	// or an inline link to a HuggingFace / arXiv / GitHub model registry.
	if body != "" && bodyMentionsSource(body) {
		return nil
	}
	return []Finding{{
		Rule:            "aibom-modelcard-no-source",
		Severity:        SeverityWarning,
		Confidence:      ConfidenceHigh,
		ConfidenceLabel: ConfidenceHigh.String(),
		File:            path,
		Message:         "model card declares no provenance — no base_model / source / training_data key in frontmatter or body",
	}}
}

// checkEval fires aibom-modelcard-no-eval when the body contains a benchmark
// claim (e.g. "94.2% accuracy") but neither a frontmatter eval key nor a
// body eval section nor an inline citation explains where the number came
// from. This is the lowest-confidence check — false-positives downgrade to
// INFO severity.
func (m *modelCardChecker) checkEval(path string, meta map[string]any, body string) []Finding {
	// Cards with no body cannot make claims, so the check is vacuous.
	if body == "" {
		return nil
	}
	claim := patterns.ModelCardClaimRegex.FindString(body)
	if claim == "" {
		return nil
	}
	// Frontmatter eval block satisfies the citation requirement.
	if hasNonEmptyKey(meta, patterns.ModelCardEvalKeys) {
		return nil
	}
	// Body eval section satisfies the citation requirement.
	if patterns.ModelCardEvalSectionHeaders.MatchString(body) {
		return nil
	}
	// Inline citation satisfies the citation requirement.
	if patterns.ModelCardCitationRegex.MatchString(body) {
		return nil
	}

	matched := claim
	if len(matched) > 80 {
		matched = matched[:80] + "..."
	}
	return []Finding{{
		Rule:            "aibom-modelcard-no-eval",
		Severity:        SeverityInfo,
		Confidence:      ConfidenceMedium,
		ConfidenceLabel: ConfidenceMedium.String(),
		File:            path,
		Message: fmt.Sprintf(
			"model card claims %q but contains no evaluation section, frontmatter eval key, or inline citation",
			matched),
	}}
}

// checkBodyForInjection delegates the markdown body to RuleMatcher.ScanDescription.
// Each finding returned by the rule matcher is re-tagged with a model-card-scoped
// rule id so AIBOM users can filter card injections from MCP tool descriptions.
func (m *modelCardChecker) checkBodyForInjection(path, body string) []Finding {
	if body == "" {
		return nil
	}
	var findings []Finding
	for _, f := range m.rules.ScanDescription(body) {
		findings = append(findings, Finding{
			Rule:            "aibom-modelcard-suspicious-instructions",
			Severity:        SeverityHigh,
			Confidence:      ConfidenceMedium,
			ConfidenceLabel: ConfidenceMedium.String(),
			File:            path,
			Message: fmt.Sprintf(
				"model card body matched %s: %s", f.Rule, f.Message),
			CWE: "CWE-1039",
		})
	}
	return findings
}

// checkYAMLValuesForInjection walks the parsed YAML metadata and scans every
// string-valued leaf with RuleMatcher.ScanDescription. Hidden instructions in
// description / tags / etc. are flagged exactly like markdown body matches.
func (m *modelCardChecker) checkYAMLValuesForInjection(path string, meta map[string]any) []Finding {
	if len(meta) == 0 {
		return nil
	}
	var findings []Finding
	walkYAMLStrings(meta, func(s string) {
		for _, f := range m.rules.ScanDescription(s) {
			findings = append(findings, Finding{
				Rule:            "aibom-modelcard-suspicious-instructions",
				Severity:        SeverityHigh,
				Confidence:      ConfidenceMedium,
				ConfidenceLabel: ConfidenceMedium.String(),
				File:            path,
				Message: fmt.Sprintf(
					"model card metadata matched %s: %s", f.Rule, f.Message),
				CWE: "CWE-1039",
			})
		}
	})
	return findings
}

// ── helpers ──────────────────────────────────────────────────────────────────

// splitFrontmatter splits a markdown file into its YAML frontmatter (if any)
// and the body. The frontmatter delimiter is `---` on its own line at the
// very start of the file, terminated by another `---` on its own line.
//
// Returns:
//
//	frontmatter map (nil when none / when YAML parsing failed)
//	body string (everything after the closing `---`, or the whole file when no frontmatter)
//	hasFrontmatter bool (true even when YAML parsing failed — so callers know to emit malformed-yaml)
//	parseErr (non-nil only when frontmatter was present but failed to parse as YAML)
func splitFrontmatter(data []byte) (map[string]any, string, bool, error) {
	// Trim a leading UTF-8 BOM if present — some editors prepend one and it
	// would otherwise prevent the `---` prefix match.
	trimmed := bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})

	// Check for an opening `---` line. The opening MUST be at byte 0 (after
	// optional BOM) and MUST be followed by either \n or \r\n.
	const opener = "---"
	if !bytes.HasPrefix(trimmed, []byte(opener)) {
		return nil, string(data), false, nil
	}
	// What follows the opener must be a newline (CRLF or LF). If it's
	// anything else, this is a regular `---` horizontal rule, not a
	// frontmatter delimiter.
	rest := trimmed[len(opener):]
	if len(rest) == 0 {
		return nil, string(data), false, nil
	}
	switch rest[0] {
	case '\n':
		rest = rest[1:]
	case '\r':
		if len(rest) >= 2 && rest[1] == '\n' {
			rest = rest[2:]
		} else {
			return nil, string(data), false, nil
		}
	default:
		return nil, string(data), false, nil
	}

	// Find the closing `---` line. It must appear on a line by itself —
	// possibly with trailing whitespace before the newline.
	closingIdx := findFrontmatterClose(rest)
	if closingIdx < 0 {
		// Opener present but no closer — treat as malformed frontmatter.
		// We still emit a parse error so the caller fires the malformed-yaml
		// finding; the body is whatever remains after the opener so users
		// can still inspect it.
		return nil, string(rest), true, fmt.Errorf("frontmatter `---` opener has no matching closer")
	}

	yamlBytes := rest[:closingIdx]
	body := rest[closingIdx:]
	// Skip the closing `---` line and any trailing whitespace.
	body = trimClosingLine(body)

	var meta map[string]any
	if err := yaml.Unmarshal(yamlBytes, &meta); err != nil {
		return nil, string(body), true, err
	}
	return meta, string(body), true, nil
}

// findFrontmatterClose returns the byte index inside `rest` where the closing
// `---` line begins, or -1 if no closer exists.
//
// A closer is `---` at the start of a line, optionally followed by spaces or
// tabs, then a newline (CRLF or LF) or EOF.
func findFrontmatterClose(rest []byte) int {
	// Walk line-by-line.
	pos := 0
	for pos < len(rest) {
		// Find the end of the current line.
		eol := bytes.IndexByte(rest[pos:], '\n')
		var line []byte
		var nextStart int
		if eol < 0 {
			line = rest[pos:]
			nextStart = len(rest)
		} else {
			line = rest[pos : pos+eol]
			nextStart = pos + eol + 1
		}
		// Strip CR.
		stripped := bytes.TrimRight(line, "\r")
		// Strip trailing whitespace ONLY (leading must remain intact — a
		// "---" with leading whitespace is NOT a closer).
		trimmed := bytes.TrimRight(stripped, " \t")
		if bytes.Equal(trimmed, []byte("---")) {
			return pos
		}
		pos = nextStart
	}
	return -1
}

// trimClosingLine returns body with its first line — the closing `---` —
// removed, preserving the rest verbatim.
func trimClosingLine(body []byte) []byte {
	idx := bytes.IndexByte(body, '\n')
	if idx < 0 {
		return nil
	}
	return body[idx+1:]
}

// hasNonEmptyKey returns true when meta contains at least one of the named
// keys with a non-empty value. Map iteration order is not stable in Go, so
// we walk the predicate set rather than the map itself — every named key is
// checked exactly once.
func hasNonEmptyKey(meta map[string]any, keys map[string]bool) bool {
	if len(meta) == 0 {
		return false
	}
	for k, v := range meta {
		if !keys[strings.ToLower(k)] {
			continue
		}
		if isNonEmptyYAMLValue(v) {
			return true
		}
	}
	return false
}

// isNonEmptyYAMLValue returns true when v is a real, non-empty value. nil,
// empty strings, empty maps, and empty slices all count as missing.
func isNonEmptyYAMLValue(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(x) != ""
	case []any:
		for _, item := range x {
			if isNonEmptyYAMLValue(item) {
				return true
			}
		}
		return false
	case map[string]any:
		for _, item := range x {
			if isNonEmptyYAMLValue(item) {
				return true
			}
		}
		return false
	default:
		// Numeric / bool — treat as present.
		return true
	}
}

// bodyMentionsSource returns true when the markdown body mentions a base
// model or training data source via either a section heading or an inline
// link to a known model registry (HuggingFace, GitHub, arXiv).
func bodyMentionsSource(body string) bool {
	lower := strings.ToLower(body)
	// Section headings like "## Base model", "## Training data", "## Source".
	headings := []string{
		"## base model", "# base model", "### base model",
		"## training data", "# training data", "### training data",
		"## source", "# source", "### source",
		"## dataset", "# dataset", "### dataset",
		"## datasets", "# datasets", "### datasets",
		"## parent model", "# parent model", "### parent model",
	}
	for _, h := range headings {
		if strings.Contains(lower, h) {
			return true
		}
	}
	// Inline registry links — any of these is sufficient evidence.
	registries := []string{
		"huggingface.co/",
		"github.com/",
		"arxiv.org/",
		"paperswithcode.com/",
		"kaggle.com/datasets",
	}
	for _, r := range registries {
		if strings.Contains(lower, r) {
			return true
		}
	}
	return false
}

// walkYAMLStrings invokes fn for every string-valued leaf in v. Maps and
// slices are walked recursively; non-string leaves are ignored.
func walkYAMLStrings(v any, fn func(string)) {
	switch x := v.(type) {
	case string:
		fn(x)
	case []any:
		for _, item := range x {
			walkYAMLStrings(item, fn)
		}
	case map[string]any:
		// Iterate keys deterministically would require sorting; the order
		// only affects test assertions on individual findings, and tests
		// assert by rule id rather than ordering. Random map iteration is
		// fine here.
		for k, val := range x {
			fn(k)
			walkYAMLStrings(val, fn)
		}
	case map[any]any:
		// yaml.v3 may produce map[any]any when the YAML keys are non-string;
		// translate keys via fmt.Sprint to scan them too.
		for k, val := range x {
			fn(fmt.Sprint(k))
			walkYAMLStrings(val, fn)
		}
	}
}

// ── compile-time interface guard ────────────────────────────────────────────

var _ ModelCardChecker = (*modelCardChecker)(nil)
