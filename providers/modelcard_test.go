package providers_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oxvault/scanner/providers"
)

// ── repo fixture suite ──────────────────────────────────────────────────────
//
// These tests exercise the static fixtures emitted by
// scripts/gen_aibom_fixtures.py. Each fixture is paired with its expected
// rule id + severity so any regression in the checker is loud and obvious.

func TestModelCardChecker_Fixtures(t *testing.T) {
	tests := []struct {
		name         string
		fixture      string
		wantRule     string
		wantSeverity providers.Severity
	}{
		{
			name:         "full safe card emits clean INFO",
			fixture:      "safe/full.md",
			wantRule:     "aibom-modelcard-clean",
			wantSeverity: providers.SeverityInfo,
		},
		{
			name:         "minimal clean card emits clean INFO",
			fixture:      "safe/minimal_clean.md",
			wantRule:     "aibom-modelcard-clean",
			wantSeverity: providers.SeverityInfo,
		},
		{
			name:         "yaml-only safe card emits clean INFO",
			fixture:      "safe/model_card.yaml",
			wantRule:     "aibom-modelcard-clean",
			wantSeverity: providers.SeverityInfo,
		},
		{
			name:         "no_license flagged WARNING",
			fixture:      "malicious/no_license.md",
			wantRule:     "aibom-modelcard-no-license",
			wantSeverity: providers.SeverityWarning,
		},
		{
			name:         "no_source flagged WARNING",
			fixture:      "malicious/no_source.md",
			wantRule:     "aibom-modelcard-no-source",
			wantSeverity: providers.SeverityWarning,
		},
		{
			name:         "poisoned_card flagged HIGH",
			fixture:      "malicious/poisoned_card.md",
			wantRule:     "aibom-modelcard-suspicious-instructions",
			wantSeverity: providers.SeverityHigh,
		},
		{
			name:         "uncited_claim flagged INFO",
			fixture:      "malicious/uncited_claim.md",
			wantRule:     "aibom-modelcard-no-eval",
			wantSeverity: providers.SeverityInfo,
		},
		{
			name:         "malformed_frontmatter flagged WARNING",
			fixture:      "malicious/malformed_frontmatter.md",
			wantRule:     "aibom-modelcard-malformed-yaml",
			wantSeverity: providers.SeverityWarning,
		},
		{
			name:         "empty file flagged WARNING with empty rule id",
			fixture:      "malicious/empty.md",
			wantRule:     "aibom-modelcard-empty",
			wantSeverity: providers.SeverityWarning,
		},
		{
			name:         "yaml-only malformed flagged WARNING with malformed-yaml id",
			fixture:      "malicious/model_card.yaml",
			wantRule:     "aibom-modelcard-malformed-yaml",
			wantSeverity: providers.SeverityWarning,
		},
	}

	c := providers.NewModelCardChecker()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join("..", "testdata", "aibom", "modelcard", tt.fixture)
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("missing fixture %s: %v (run scripts/gen_aibom_fixtures.py)", tt.fixture, err)
			}

			findings := c.CheckFile(path)
			if !findRuleAndSeverity(findings, tt.wantRule, tt.wantSeverity) {
				t.Errorf("expected rule %q at severity %v, got %d findings: %+v",
					tt.wantRule, tt.wantSeverity, len(findings), findings)
			}
		})
	}
}

// TestModelCardChecker_CleanFixturesEmitOnlyClean ensures the safe fixtures
// emit exactly one INFO finding and never a violation.
func TestModelCardChecker_CleanFixturesEmitOnlyClean(t *testing.T) {
	cases := []string{
		"safe/full.md",
		"safe/minimal_clean.md",
		"safe/model_card.yaml",
	}
	c := providers.NewModelCardChecker()
	for _, fixture := range cases {
		t.Run(fixture, func(t *testing.T) {
			path := filepath.Join("..", "testdata", "aibom", "modelcard", fixture)
			findings := c.CheckFile(path)
			if len(findings) != 1 {
				t.Fatalf("clean fixture %s: expected exactly 1 finding, got %d (%+v)",
					fixture, len(findings), findings)
			}
			if findings[0].Rule != "aibom-modelcard-clean" {
				t.Errorf("clean fixture %s: rule = %q, want aibom-modelcard-clean",
					fixture, findings[0].Rule)
			}
			if findings[0].Severity != providers.SeverityInfo {
				t.Errorf("clean fixture %s: severity = %v, want INFO",
					fixture, findings[0].Severity)
			}
		})
	}
}

// TestModelCardChecker_PoisonedCardDelegatesToRuleMatcher confirms that the
// suspicious-instructions finding is produced by RuleMatcher.ScanDescription
// (no duplicate injection patterns in the model-card layer). We swap in a
// stub rule matcher and assert the body is forwarded verbatim.
func TestModelCardChecker_PoisonedCardDelegatesToRuleMatcher(t *testing.T) {
	stub := &captureRuleMatcher{
		emit: []providers.Finding{
			{Rule: "mcp-tool-poisoning", Severity: providers.SeverityCritical, Message: "stubbed match"},
		},
	}
	c := providers.NewModelCardChecker(providers.WithModelCardCheckerRuleMatcher(stub))

	path := filepath.Join("..", "testdata", "aibom", "modelcard", "malicious", "poisoned_card.md")
	findings := c.CheckFile(path)

	if !findRule(findings, "aibom-modelcard-suspicious-instructions") {
		t.Fatalf("expected aibom-modelcard-suspicious-instructions, got %+v", findings)
	}
	if stub.descCalls == 0 {
		t.Errorf("RuleMatcher.ScanDescription was never called — checker did not delegate")
	}
	// The body forwarded to ScanDescription must contain the Important tag from
	// the fixture so we know the body (not the frontmatter) is what got passed.
	if !strings.Contains(stub.lastDescription, "<IMPORTANT>") {
		t.Errorf("ScanDescription received %q — expected to contain <IMPORTANT>", stub.lastDescription)
	}
}

// TestModelCardChecker_RealRuleMatcherFiresOnPoisonedCard exercises the
// production RuleMatcher (the same one MCP tool descriptions use) against
// the poisoned fixture and confirms at least one suspicious-instructions
// finding is produced. This is the integration test that locks the
// delegation contract end-to-end.
func TestModelCardChecker_RealRuleMatcherFiresOnPoisonedCard(t *testing.T) {
	c := providers.NewModelCardChecker()
	path := filepath.Join("..", "testdata", "aibom", "modelcard", "malicious", "poisoned_card.md")
	findings := c.CheckFile(path)

	count := 0
	for _, f := range findings {
		if f.Rule == "aibom-modelcard-suspicious-instructions" {
			count++
		}
	}
	if count == 0 {
		t.Fatalf("expected at least one aibom-modelcard-suspicious-instructions finding from real rule matcher; got %+v", findings)
	}
}

// ── synthesised edge-case suite ─────────────────────────────────────────────
//
// These tests build their own files with t.TempDir() so they run without any
// external script. They cover the byte-level edge cases that fixtures cannot
// express cleanly.

func TestModelCardChecker_NonexistentFile(t *testing.T) {
	c := providers.NewModelCardChecker()
	findings := c.CheckFile("/no/such/file/anywhere")
	if findings != nil {
		t.Errorf("expected nil for missing file, got %+v", findings)
	}
}

func TestModelCardChecker_FileTooLargeRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.md")

	// Write a 2 MiB file — well above the 1 MiB cap.
	body := strings.Repeat("a", 2*1024*1024)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewModelCardChecker()
	findings := c.CheckFile(path)
	if !findRuleAndSeverity(findings, "aibom-modelcard-too-large", providers.SeverityWarning) {
		t.Errorf("expected oversize file to fire too-large WARNING, got: %+v", findings)
	}
}

func TestModelCardChecker_NoFrontmatterPlainBody(t *testing.T) {
	// A markdown card with NO frontmatter — the body itself must contain
	// license + source markers for the file to pass.
	dir := t.TempDir()
	path := filepath.Join(dir, "README.md")
	body := `# My Model

## License
MIT.

## Base model
Built on top of bert-base-uncased.

A short description.
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewModelCardChecker()
	findings := c.CheckFile(path)

	if !findRule(findings, "aibom-modelcard-clean") {
		t.Errorf("expected clean INFO from body-only card with license + source headings, got: %+v", findings)
	}
}

func TestModelCardChecker_ClaimWithEvalSectionPasses(t *testing.T) {
	// Body claims accuracy AND has an explicit Evaluation section — the no-
	// eval check must NOT fire. Frontmatter declares license + base_model so
	// the only suppression decision under test is the eval rule.
	dir := t.TempDir()
	path := filepath.Join(dir, "README.md")
	body := `---
license: mit
base_model: bert-base-uncased
---
# Cited Model

## Evaluation
On the dev split we get 94% accuracy and 0.91 F1.
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewModelCardChecker()
	findings := c.CheckFile(path)
	for _, f := range findings {
		if f.Rule == "aibom-modelcard-no-eval" {
			t.Errorf("eval section should suppress no-eval rule; got: %+v", f)
		}
	}
}

func TestModelCardChecker_ClaimWithCitationPasses(t *testing.T) {
	// Body claims accuracy with an inline citation — no-eval must NOT fire.
	dir := t.TempDir()
	path := filepath.Join(dir, "README.md")
	body := `---
license: mit
base_model: bert-base-uncased
---
# Cited Model

We report 94% accuracy (see [eval.md](./eval.md)).
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewModelCardChecker()
	findings := c.CheckFile(path)
	for _, f := range findings {
		if f.Rule == "aibom-modelcard-no-eval" {
			t.Errorf("inline citation should suppress no-eval rule; got: %+v", f)
		}
	}
}

func TestModelCardChecker_FrontmatterEvalKeyPasses(t *testing.T) {
	// Body claims accuracy, frontmatter declares `metrics:` — the no-eval
	// check must NOT fire because the frontmatter eval key satisfies it.
	dir := t.TempDir()
	path := filepath.Join(dir, "README.md")
	body := `---
license: mit
base_model: bert-base-uncased
metrics:
  - accuracy
  - f1
---
# Eval-Frontmatter Model

We achieved 94% accuracy on the dev split.
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewModelCardChecker()
	findings := c.CheckFile(path)
	for _, f := range findings {
		if f.Rule == "aibom-modelcard-no-eval" {
			t.Errorf("frontmatter metrics key should suppress no-eval rule; got: %+v", f)
		}
	}
}

func TestModelCardChecker_EmptyLicenseValueIsTreatedAsMissing(t *testing.T) {
	// `license:` is present but its value is empty — the no-license rule
	// must still fire, because an empty value is not a real declaration.
	dir := t.TempDir()
	path := filepath.Join(dir, "README.md")
	body := `---
license:
base_model: bert-base-uncased
---
# Empty License
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewModelCardChecker()
	findings := c.CheckFile(path)
	if !findRule(findings, "aibom-modelcard-no-license") {
		t.Errorf("empty license value should fire no-license; got: %+v", findings)
	}
}

func TestModelCardChecker_LicenceUKSpellingPasses(t *testing.T) {
	// UK spelling `licence:` should be accepted (HuggingFace's spec is silent
	// on the spelling and producers in the wild use both).
	dir := t.TempDir()
	path := filepath.Join(dir, "README.md")
	body := `---
licence: apache-2.0
base_model: bert
---
# UK Spelling
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewModelCardChecker()
	findings := c.CheckFile(path)
	for _, f := range findings {
		if f.Rule == "aibom-modelcard-no-license" {
			t.Errorf("UK spelling `licence:` should suppress no-license; got: %+v", f)
		}
	}
}

// ── CheckDirectory ──────────────────────────────────────────────────────────

func TestModelCardChecker_CheckDirectory_MissingCardEmitsWarning(t *testing.T) {
	// A directory containing a model artifact (.pkl) but NO model card must
	// fire aibom-modelcard-missing.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "weights.pkl"), []byte{0x80, 0x04}, 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewModelCardChecker()
	findings := c.CheckDirectory(dir)

	if !findRuleAndSeverity(findings, "aibom-modelcard-missing", providers.SeverityWarning) {
		t.Errorf("expected aibom-modelcard-missing WARNING, got: %+v", findings)
	}
}

func TestModelCardChecker_CheckDirectory_ArtifactWithCardSuppressesMissing(t *testing.T) {
	// Same directory, but with a README.md alongside the .pkl — the missing
	// card warning must NOT fire.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "weights.pkl"), []byte{0x80, 0x04}, 0o644); err != nil {
		t.Fatal(err)
	}
	body := `---
license: mit
base_model: bert-base-uncased
---
# My Model
`
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewModelCardChecker()
	findings := c.CheckDirectory(dir)
	for _, f := range findings {
		if f.Rule == "aibom-modelcard-missing" {
			t.Errorf("artifact + card present should suppress missing rule; got: %+v", f)
		}
	}
}

func TestModelCardChecker_CheckDirectory_AggregatesPerFileFindings(t *testing.T) {
	// Two cards — one clean, one without license. The directory walker must
	// run per-file checks for both.
	dir := t.TempDir()

	cleanBody := `---
license: mit
base_model: bert
---
# Clean
`
	if err := os.WriteFile(filepath.Join(dir, "model_card.md"), []byte(cleanBody), 0o644); err != nil {
		t.Fatal(err)
	}

	sub := filepath.Join(dir, "submodel")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	noLicenseBody := `---
base_model: bert
---
# No License Here
`
	if err := os.WriteFile(filepath.Join(sub, "README.md"), []byte(noLicenseBody), 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewModelCardChecker()
	findings := c.CheckDirectory(dir)

	if !findRule(findings, "aibom-modelcard-clean") {
		t.Errorf("expected clean finding from model_card.md; got: %+v", findings)
	}
	if !findRule(findings, "aibom-modelcard-no-license") {
		t.Errorf("expected no-license finding from submodel/README.md; got: %+v", findings)
	}
}

func TestModelCardChecker_CheckDirectory_SkipsExcludedDirs(t *testing.T) {
	// A model card inside an excluded directory (node_modules) must NOT be
	// scanned.
	dir := t.TempDir()
	excluded := filepath.Join(dir, "node_modules")
	if err := os.MkdirAll(excluded, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(excluded, "README.md"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	// And a sibling card in the visible tree.
	body := `---
license: mit
base_model: bert
---
# Visible
`
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewModelCardChecker()
	findings := c.CheckDirectory(dir)

	// Exactly one clean finding from the visible README. The excluded README
	// is empty and would have fired the empty-card WARNING — its absence
	// proves the exclusion fired.
	cleanCount := 0
	for _, f := range findings {
		if f.Rule == "aibom-modelcard-clean" {
			cleanCount++
		}
		if f.Rule == "aibom-modelcard-empty" {
			t.Errorf("excluded directory should not have been scanned; got: %+v", f)
		}
	}
	if cleanCount != 1 {
		t.Errorf("expected exactly 1 clean finding from visible README, got %d", cleanCount)
	}
}

// ── rule-id split: too-large / empty / malformed-yaml are distinct ─────────
//
// Day 6 review feedback: the previous implementation funnelled all three
// signals through aibom-modelcard-malformed-yaml, which made user-facing
// triage impossible ("did the file fail to parse, or is it just large?").
// These tests lock the split.

func TestModelCardChecker_TooLarge_FiresOwnRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.md")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 2*1024*1024)), 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewModelCardChecker()
	findings := c.CheckFile(path)

	if !findRuleAndSeverity(findings, "aibom-modelcard-too-large", providers.SeverityWarning) {
		t.Errorf("oversize card should fire aibom-modelcard-too-large; got: %+v", findings)
	}
	for _, f := range findings {
		if f.Rule == "aibom-modelcard-malformed-yaml" {
			t.Errorf("oversize card should NOT also fire malformed-yaml; got: %+v", f)
		}
		if f.Rule == "aibom-modelcard-empty" {
			t.Errorf("oversize card should NOT fire empty; got: %+v", f)
		}
	}
}

func TestModelCardChecker_Empty_FiresOwnRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "README.md")
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewModelCardChecker()
	findings := c.CheckFile(path)

	if !findRuleAndSeverity(findings, "aibom-modelcard-empty", providers.SeverityWarning) {
		t.Errorf("empty card should fire aibom-modelcard-empty; got: %+v", findings)
	}
	for _, f := range findings {
		if f.Rule == "aibom-modelcard-malformed-yaml" {
			t.Errorf("empty card should NOT fire malformed-yaml; got: %+v", f)
		}
		if f.Rule == "aibom-modelcard-too-large" {
			t.Errorf("empty card should NOT fire too-large; got: %+v", f)
		}
	}
}

func TestModelCardChecker_MalformedYAML_FiresOwnRule(t *testing.T) {
	// A real YAML parse failure — must emit malformed-yaml ONLY, not the
	// too-large or empty signals.
	dir := t.TempDir()
	path := filepath.Join(dir, "README.md")
	body := `---
license: [unclosed list
base_model: bert
---
# Broken
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewModelCardChecker()
	findings := c.CheckFile(path)

	if !findRuleAndSeverity(findings, "aibom-modelcard-malformed-yaml", providers.SeverityWarning) {
		t.Errorf("malformed YAML should fire malformed-yaml; got: %+v", findings)
	}
	for _, f := range findings {
		if f.Rule == "aibom-modelcard-too-large" {
			t.Errorf("malformed YAML should NOT fire too-large; got: %+v", f)
		}
		if f.Rule == "aibom-modelcard-empty" {
			t.Errorf("malformed YAML should NOT fire empty; got: %+v", f)
		}
	}
}

// ── tightened bodyMentionsSource: bare github.com no longer suppresses ──────

func TestModelCardChecker_BareGithubLinkDoesNotSuppressNoSource(t *testing.T) {
	// Day 6 review: previously any `github.com/` URL satisfied the source
	// check, so a card with a bare "follow me on GitHub" link was treated
	// as having declared provenance. The tightened check requires either a
	// section heading or a HuggingFace / arXiv path.
	dir := t.TempDir()
	path := filepath.Join(dir, "README.md")
	body := `---
license: mit
---
# Sneaky Card

A model with a github.com/somebody/blog link but no real provenance.
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewModelCardChecker()
	findings := c.CheckFile(path)

	if !findRule(findings, "aibom-modelcard-no-source") {
		t.Errorf("bare github.com link should NOT suppress no-source; got: %+v", findings)
	}
}

func TestModelCardChecker_HuggingFaceModelPathSuppressesNoSource(t *testing.T) {
	// A HuggingFace model URL like huggingface.co/meta-llama/Llama-2-7b is
	// a real source signal — must suppress no-source.
	dir := t.TempDir()
	path := filepath.Join(dir, "README.md")
	body := `---
license: mit
---
# HF Card

Built on top of huggingface.co/meta-llama/Llama-2-7b.
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewModelCardChecker()
	findings := c.CheckFile(path)

	for _, f := range findings {
		if f.Rule == "aibom-modelcard-no-source" {
			t.Errorf("huggingface model path should suppress no-source; got: %+v", f)
		}
	}
}

func TestModelCardChecker_HuggingFaceDatasetPathSuppressesNoSource(t *testing.T) {
	// A HuggingFace datasets URL is a real source signal.
	dir := t.TempDir()
	path := filepath.Join(dir, "README.md")
	body := `---
license: mit
---
# Dataset Card

Trained on huggingface.co/datasets/openassistant/oasst1.
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewModelCardChecker()
	findings := c.CheckFile(path)

	for _, f := range findings {
		if f.Rule == "aibom-modelcard-no-source" {
			t.Errorf("huggingface datasets path should suppress no-source; got: %+v", f)
		}
	}
}

func TestModelCardChecker_HuggingFaceSpacesPathDoesNotSuppress(t *testing.T) {
	// huggingface.co/spaces/ is NOT a model-source signal — it points at a
	// HuggingFace Space (a UI demo), not a base model or dataset.
	dir := t.TempDir()
	path := filepath.Join(dir, "README.md")
	body := `---
license: mit
---
# Spaces Card

Try the demo at huggingface.co/spaces/some-org/some-demo.
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewModelCardChecker()
	findings := c.CheckFile(path)

	if !findRule(findings, "aibom-modelcard-no-source") {
		t.Errorf("huggingface spaces path should NOT suppress no-source; got: %+v", findings)
	}
}

func TestModelCardChecker_PaperswithcodeAndKaggleNoLongerSuppress(t *testing.T) {
	// Day 6 review: paperswithcode.com / kaggle.com/datasets were too
	// permissive — drop them. A bare paperswithcode link must NOT satisfy
	// the source check.
	dir := t.TempDir()
	path := filepath.Join(dir, "README.md")
	body := `---
license: mit
---
# Permissive

See benchmarks at paperswithcode.com/sota/something and the data on
kaggle.com/datasets/foo/bar.
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewModelCardChecker()
	findings := c.CheckFile(path)

	if !findRule(findings, "aibom-modelcard-no-source") {
		t.Errorf("paperswithcode/kaggle links should NOT suppress no-source; got: %+v", findings)
	}
}

// ── defer recover() panic safety ────────────────────────────────────────────

// panicRuleMatcher is a RuleMatcher that panics on every ScanDescription
// call. It exercises the deferred recover() in checkFile so that a panic
// inside body-injection scanning does NOT take down the scanner.
type panicRuleMatcher struct{}

func (panicRuleMatcher) ScanDescription(string) []providers.Finding {
	panic("synthetic panic from rule matcher")
}

func (panicRuleMatcher) ScanArguments(map[string]any) []providers.Finding { return nil }
func (panicRuleMatcher) ScanResponse(string) []providers.Finding          { return nil }
func (panicRuleMatcher) ClassifyTool(providers.MCPTool, string) providers.RiskTier {
	return providers.RiskTierLow
}

var _ providers.RuleMatcher = (*panicRuleMatcher)(nil)

func TestModelCardChecker_PanicInRuleMatcherIsRecovered(t *testing.T) {
	// A panic inside ScanDescription must NOT propagate out of CheckFile.
	// The deferred recover() emits a malformed-yaml WARNING so the panic is
	// at least visible to the user.
	dir := t.TempDir()
	path := filepath.Join(dir, "README.md")
	body := `---
license: mit
base_model: bert
---
# Card With Body

Some prose so the body-scan path is reached.
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewModelCardChecker(
		providers.WithModelCardCheckerRuleMatcher(panicRuleMatcher{}),
	)

	// Sanity: must not panic.
	findings := c.CheckFile(path)

	if !findRuleAndSeverity(findings, "aibom-modelcard-malformed-yaml", providers.SeverityWarning) {
		t.Errorf("panic should surface as malformed-yaml WARNING; got: %+v", findings)
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

// captureRuleMatcher is a stub RuleMatcher that records every ScanDescription
// invocation and returns a configured set of findings. It is purpose-built
// for TestModelCardChecker_PoisonedCardDelegatesToRuleMatcher and is the
// model-card equivalent of testutil.MockRuleMatcher (kept local to avoid
// pulling testutil into the test suite for a single use).
type captureRuleMatcher struct {
	emit            []providers.Finding
	descCalls       int
	lastDescription string
}

func (c *captureRuleMatcher) ScanDescription(s string) []providers.Finding {
	c.descCalls++
	c.lastDescription = s
	return c.emit
}

func (c *captureRuleMatcher) ScanArguments(_ map[string]any) []providers.Finding {
	return nil
}

func (c *captureRuleMatcher) ScanResponse(_ string) []providers.Finding {
	return nil
}

func (c *captureRuleMatcher) ClassifyTool(_ providers.MCPTool, _ string) providers.RiskTier {
	return providers.RiskTierLow
}

// compile-time guard
var _ providers.RuleMatcher = (*captureRuleMatcher)(nil)
