package providers_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oxvault/scanner/providers"
	"github.com/oxvault/scanner/testutil"
)

// ── interface guards ─────────────────────────────────────────────────────────
//
// These guards verify the testutil mocks satisfy the AIBOM interfaces at
// compile time. They live in the test package to avoid creating a
// providers -> testutil dependency in production code.

var (
	_ providers.PickleAnalyzer       = (*testutil.MockPickleAnalyzer)(nil)
	_ providers.ONNXValidator        = (*testutil.MockONNXValidator)(nil)
	_ providers.SafetensorsValidator = (*testutil.MockSafetensorsValidator)(nil)
	_ providers.ModelCardChecker     = (*testutil.MockModelCardChecker)(nil)
	_ providers.SignatureVerifier    = (*testutil.MockSignatureVerifier)(nil)
	_ providers.AIBOMComposer        = (*testutil.MockAIBOMComposer)(nil)
)

// ── helpers ──────────────────────────────────────────────────────────────────

type composerMocks struct {
	pickle      *testutil.MockPickleAnalyzer
	onnx        *testutil.MockONNXValidator
	safetensors *testutil.MockSafetensorsValidator
	modelCard   *testutil.MockModelCardChecker
	signature   *testutil.MockSignatureVerifier
}

func newComposerMocks() composerMocks {
	return composerMocks{
		pickle:      &testutil.MockPickleAnalyzer{},
		onnx:        &testutil.MockONNXValidator{},
		safetensors: &testutil.MockSafetensorsValidator{},
		modelCard:   &testutil.MockModelCardChecker{},
		signature:   &testutil.MockSignatureVerifier{},
	}
}

func (m composerMocks) wire() providers.AIBOMComposer {
	return providers.NewComposer(
		providers.WithPickleAnalyzer(m.pickle),
		providers.WithONNXValidator(m.onnx),
		providers.WithSafetensorsValidator(m.safetensors),
		providers.WithModelCardChecker(m.modelCard),
		providers.WithSignatureVerifier(m.signature),
	)
}

// writeAibomFile creates a file at dir/name with the given binary body.
// Distinct name from depaudit_test.go's string-content writeFile helper for
// reader clarity (the two live in different test packages and would not
// actually collide at the symbol level).
func writeAibomFile(t *testing.T, dir, name string, body []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// ── single-file dispatch ────────────────────────────────────────────────────

func TestComposer_Scan_File_DispatchesByFormat(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		body     []byte
		want     func(composerMocks) int32
	}{
		{
			name:     "pickle file routes to PickleAnalyzer",
			filename: "weights.pkl",
			body:     []byte{0x80, 0x04},
			want:     func(m composerMocks) int32 { return m.pickle.AnalyzeFileCount.Load() },
		},
		{
			name:     "torch checkpoint routes to PickleAnalyzer",
			filename: "model.pt",
			body:     []byte{0x80, 0x02},
			want:     func(m composerMocks) int32 { return m.pickle.AnalyzeFileCount.Load() },
		},
		{
			name:     "onnx file routes to ONNXValidator",
			filename: "graph.onnx",
			body:     []byte{0x08, 0x01},
			want:     func(m composerMocks) int32 { return m.onnx.ValidateFileCount.Load() },
		},
		{
			name:     "safetensors file routes to SafetensorsValidator",
			filename: "weights.safetensors",
			body:     []byte(`{"__metadata__":{}}`),
			want:     func(m composerMocks) int32 { return m.safetensors.ValidateFileCount.Load() },
		},
		{
			name:     "README routes to ModelCardChecker",
			filename: "README.md",
			body:     []byte("# Model Card\n"),
			want:     func(m composerMocks) int32 { return m.modelCard.CheckFileCount.Load() },
		},
		{
			name:     "sigstore bundle routes to SignatureVerifier",
			filename: "weights.pkl.sigstore",
			body:     []byte("{}"),
			want:     func(m composerMocks) int32 { return m.signature.VerifyArtifactCount.Load() },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeAibomFile(t, dir, tt.filename, tt.body)

			mocks := newComposerMocks()
			c := mocks.wire()

			findings := c.Scan(path)
			if findings != nil {
				t.Errorf("expected nil findings from skeletons, got %d", len(findings))
			}
			if got := tt.want(mocks); got != 1 {
				t.Errorf("expected exactly 1 dispatch, got %d", got)
			}
		})
	}
}

func TestComposer_Scan_File_UnknownFormatDispatchesNothing(t *testing.T) {
	dir := t.TempDir()
	path := writeAibomFile(t, dir, "random.txt", []byte("just text"))

	mocks := newComposerMocks()
	c := mocks.wire()

	findings := c.Scan(path)
	if findings != nil {
		t.Errorf("expected nil findings, got %d", len(findings))
	}

	// Sum every dispatch counter — must be zero.
	total := mocks.pickle.AnalyzeFileCount.Load() +
		mocks.onnx.ValidateFileCount.Load() +
		mocks.safetensors.ValidateFileCount.Load() +
		mocks.modelCard.CheckFileCount.Load() +
		mocks.signature.VerifyArtifactCount.Load()
	if total != 0 {
		t.Errorf("expected no dispatches for unknown format, got %d", total)
	}
}

func TestComposer_Scan_NonexistentPathReturnsNil(t *testing.T) {
	mocks := newComposerMocks()
	c := mocks.wire()

	findings := c.Scan("/no/such/path/exists/here")
	if findings != nil {
		t.Errorf("expected nil for missing path, got %d findings", len(findings))
	}
}

// ── directory walk ──────────────────────────────────────────────────────────

func TestComposer_Scan_Directory_DispatchesEachFileByFormat(t *testing.T) {
	dir := t.TempDir()
	writeAibomFile(t, dir, "weights.pkl", []byte{0x80, 0x04})
	writeAibomFile(t, dir, "graph.onnx", []byte{0x08, 0x01})
	writeAibomFile(t, dir, "weights.safetensors", []byte(`{"a":1}`))
	writeAibomFile(t, dir, "README.md", []byte("# card"))
	writeAibomFile(t, dir, "weights.pkl.sigstore", []byte("{}"))
	writeAibomFile(t, dir, "ignore-me.txt", []byte("noise"))

	mocks := newComposerMocks()
	c := mocks.wire()

	findings := c.Scan(dir)
	if findings != nil {
		t.Errorf("expected nil findings from skeletons, got %d", len(findings))
	}

	if got := mocks.pickle.AnalyzeFileCount.Load(); got != 1 {
		t.Errorf("PickleAnalyzer.AnalyzeFile: want 1, got %d", got)
	}
	if got := mocks.onnx.ValidateFileCount.Load(); got != 1 {
		t.Errorf("ONNXValidator.ValidateFile: want 1, got %d", got)
	}
	if got := mocks.safetensors.ValidateFileCount.Load(); got != 1 {
		t.Errorf("SafetensorsValidator.ValidateFile: want 1, got %d", got)
	}
	if got := mocks.modelCard.CheckFileCount.Load(); got != 1 {
		t.Errorf("ModelCardChecker.CheckFile: want 1, got %d", got)
	}
	// Expected calls: 1 from FormatSignature dispatch (.sigstore file) + 3
	// from cross-file aggregation (one per model artifact: .pkl, .onnx,
	// .safetensors). Day 7: the composer owns missing-signature aggregation,
	// same pattern as missing-card aggregation.
	if got := mocks.signature.VerifyArtifactCount.Load(); got != 4 {
		t.Errorf("SignatureVerifier.VerifyArtifact: want 4 (1 dispatch + 3 aggregation), got %d", got)
	}

	// Directory-scoped methods must NOT be called — the composer owns the walk.
	if got := mocks.pickle.AnalyzeDirectoryCount.Load(); got != 0 {
		t.Errorf("PickleAnalyzer.AnalyzeDirectory: want 0, got %d", got)
	}
	if got := mocks.onnx.ValidateDirectoryCount.Load(); got != 0 {
		t.Errorf("ONNXValidator.ValidateDirectory: want 0, got %d", got)
	}
}

func TestComposer_Scan_Directory_AggregatesFindings(t *testing.T) {
	dir := t.TempDir()
	writeAibomFile(t, dir, "a.pkl", []byte{0x80, 0x04})
	writeAibomFile(t, dir, "b.onnx", []byte{0x08, 0x01})
	// Drop a model card alongside the artifacts to suppress the composer's
	// missing-card aggregation; this test asserts per-provider dispatch
	// aggregation, not the missing-card rule (which has its own tests).
	writeAibomFile(t, dir, "README.md", []byte("# card\n"))

	mocks := newComposerMocks()
	mocks.pickle.AnalyzeFileResult = []providers.Finding{{Rule: "pickle-1"}}
	mocks.onnx.ValidateFileResult = []providers.Finding{{Rule: "onnx-1"}, {Rule: "onnx-2"}}
	c := mocks.wire()

	findings := c.Scan(dir)
	if len(findings) != 3 {
		t.Fatalf("expected 3 aggregated findings, got %d (%+v)", len(findings), findings)
	}

	rules := map[string]bool{}
	for _, f := range findings {
		rules[f.Rule] = true
	}
	for _, want := range []string{"pickle-1", "onnx-1", "onnx-2"} {
		if !rules[want] {
			t.Errorf("missing finding rule %q in aggregated output", want)
		}
	}
}

func TestComposer_Scan_Directory_SkipsExcludedDirs(t *testing.T) {
	dir := t.TempDir()
	// Create an excluded directory with a pickle in it — it must NOT be scanned.
	excluded := filepath.Join(dir, "node_modules")
	if err := os.Mkdir(excluded, 0o755); err != nil {
		t.Fatal(err)
	}
	writeAibomFile(t, excluded, "hidden.pkl", []byte{0x80, 0x04})
	// Sanity artifact in the visible tree.
	writeAibomFile(t, dir, "visible.pkl", []byte{0x80, 0x04})

	mocks := newComposerMocks()
	c := mocks.wire()

	_ = c.Scan(dir)
	if got := mocks.pickle.AnalyzeFileCount.Load(); got != 1 {
		t.Errorf("expected exactly the visible pickle to be analysed, got %d calls", got)
	}
}

// ── functional-options nil-safety ────────────────────────────────────────────

func TestNewComposer_DefaultsAreInstalledForMissingOptions(t *testing.T) {
	// Construct with no options — the composer must still operate without
	// panicking. Real default sub-providers may emit findings; we just
	// assert the call completes safely.
	c := providers.NewComposer()

	dir := t.TempDir()
	path := writeAibomFile(t, dir, "weights.pkl", []byte{0x80, 0x04})
	_ = c.Scan(path) // must not panic
}

// ── cross-file aggregation: missing model card ──────────────────────────────
//
// These tests exercise the production composer (no mocks for the model-card
// provider) end-to-end so the missing-card rule actually fires on real
// `oxvault scan` invocations. Mock-based per-file dispatch tests are not
// sufficient because mocks cannot tell the composer "I saw an artifact" —
// the aggregation lives in the composer itself.

func TestComposer_Scan_Directory_MissingCard_FiresOnArtifactWithoutCard(t *testing.T) {
	// Real-world repro: a directory containing a pickle artifact but no
	// README.md / MODEL_CARD.md. Before the fix this rule was dead in
	// production because the composer dispatched per-file via dispatch()
	// and never invoked CheckDirectory; only the unit tests fired the rule.
	dir := t.TempDir()
	writeAibomFile(t, dir, "weights.pkl", []byte{0x80, 0x04})

	// Use the real composer (no model-card mock) to exercise aggregation.
	c := providers.NewComposer()
	findings := c.Scan(dir)

	if !findRule(findings, "aibom-modelcard-missing") {
		t.Errorf("expected aibom-modelcard-missing from real composer scan; got: %+v", findings)
	}
}

func TestComposer_Scan_Directory_MissingCard_SuppressedWhenCardPresent(t *testing.T) {
	// A README.md alongside the pickle suppresses the missing-card warning.
	dir := t.TempDir()
	writeAibomFile(t, dir, "weights.pkl", []byte{0x80, 0x04})
	cardBody := []byte(`---
license: mit
base_model: bert-base-uncased
---
# My Model
`)
	writeAibomFile(t, dir, "README.md", cardBody)

	c := providers.NewComposer()
	findings := c.Scan(dir)

	for _, f := range findings {
		if f.Rule == "aibom-modelcard-missing" {
			t.Errorf("artifact + card present should suppress missing rule; got: %+v", f)
		}
	}
}

func TestComposer_Scan_Directory_MissingCard_PerArtifactDirectory(t *testing.T) {
	// Two sibling subdirectories — one with a card, one without. Only the
	// uncovered directory must emit missing-card.
	dir := t.TempDir()

	covered := filepath.Join(dir, "model-a")
	if err := os.MkdirAll(covered, 0o755); err != nil {
		t.Fatal(err)
	}
	writeAibomFile(t, covered, "weights.pkl", []byte{0x80, 0x04})
	writeAibomFile(t, covered, "README.md", []byte(`---
license: mit
base_model: bert
---
# A
`))

	uncovered := filepath.Join(dir, "model-b")
	if err := os.MkdirAll(uncovered, 0o755); err != nil {
		t.Fatal(err)
	}
	writeAibomFile(t, uncovered, "weights.pkl", []byte{0x80, 0x04})

	c := providers.NewComposer()
	findings := c.Scan(dir)

	missingCount := 0
	for _, f := range findings {
		if f.Rule == "aibom-modelcard-missing" {
			missingCount++
			if f.File != uncovered {
				t.Errorf("missing-card File = %q, want %q", f.File, uncovered)
			}
		}
	}
	if missingCount != 1 {
		t.Errorf("expected exactly 1 missing-card finding, got %d", missingCount)
	}
}

func TestComposer_Scan_Directory_MissingCard_OnnxArtifactAlsoTriggers(t *testing.T) {
	// The aggregation must include onnx and safetensors, not just pickle.
	dir := t.TempDir()
	writeAibomFile(t, dir, "graph.onnx", []byte{0x08, 0x01})

	c := providers.NewComposer()
	findings := c.Scan(dir)

	if !findRule(findings, "aibom-modelcard-missing") {
		t.Errorf("onnx artifact without card should fire missing-card; got: %+v", findings)
	}
}

func TestComposer_Scan_Directory_MissingCard_FileTargetDoesNotFire(t *testing.T) {
	// When the user scans a single file (not a directory), the composer
	// MUST NOT emit missing-card — the user is targeting an artifact in
	// isolation, not declaring "this directory should have a card".
	dir := t.TempDir()
	path := writeAibomFile(t, dir, "weights.pkl", []byte{0x80, 0x04})

	c := providers.NewComposer()
	findings := c.Scan(path)

	for _, f := range findings {
		if f.Rule == "aibom-modelcard-missing" {
			t.Errorf("single-file scan should not fire missing-card; got: %+v", f)
		}
	}
}
