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
			name:         "empty file flagged WARNING",
			fixture:      "malicious/empty.md",
			wantRule:     "aibom-modelcard-malformed-yaml",
			wantSeverity: providers.SeverityWarning,
		},
		{
			name:         "yaml-only malformed flagged WARNING",
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
	c := providers.NewModelCardCheckerWithRuleMatcher(stub)

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
	if !findRuleAndSeverity(findings, "aibom-modelcard-malformed-yaml", providers.SeverityWarning) {
		t.Errorf("expected oversize file to fire malformed-yaml WARNING, got: %+v", findings)
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
	// is empty and would have fired malformed-yaml WARNING — its absence
	// proves the exclusion fired.
	cleanCount := 0
	for _, f := range findings {
		if f.Rule == "aibom-modelcard-clean" {
			cleanCount++
		}
		if f.Rule == "aibom-modelcard-malformed-yaml" {
			t.Errorf("excluded directory should not have been scanned; got: %+v", f)
		}
	}
	if cleanCount != 1 {
		t.Errorf("expected exactly 1 clean finding from visible README, got %d", cleanCount)
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
