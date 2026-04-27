package aibom_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oxvault/scanner/providers"
	"github.com/oxvault/scanner/providers/aibom"
	"github.com/oxvault/scanner/testutil"
)

// ── interface guards ─────────────────────────────────────────────────────────
//
// These guards verify the testutil mocks satisfy the aibom interfaces at
// compile time. They live in the test package to avoid creating an
// aibom -> testutil dependency in production code.

var (
	_ aibom.PickleAnalyzer       = (*testutil.MockPickleAnalyzer)(nil)
	_ aibom.ONNXValidator        = (*testutil.MockONNXValidator)(nil)
	_ aibom.SafetensorsValidator = (*testutil.MockSafetensorsValidator)(nil)
	_ aibom.ModelCardChecker     = (*testutil.MockModelCardChecker)(nil)
	_ aibom.SignatureVerifier    = (*testutil.MockSignatureVerifier)(nil)
	_ aibom.AIBOMComposer        = (*testutil.MockAIBOMComposer)(nil)
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

func (m composerMocks) wire() aibom.AIBOMComposer {
	return aibom.NewComposer(
		aibom.WithPickleAnalyzer(m.pickle),
		aibom.WithONNXValidator(m.onnx),
		aibom.WithSafetensorsValidator(m.safetensors),
		aibom.WithModelCardChecker(m.modelCard),
		aibom.WithSignatureVerifier(m.signature),
	)
}

func writeFile(t *testing.T, dir, name string, body []byte) string {
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
			path := writeFile(t, dir, tt.filename, tt.body)

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
	path := writeFile(t, dir, "random.txt", []byte("just text"))

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
	writeFile(t, dir, "weights.pkl", []byte{0x80, 0x04})
	writeFile(t, dir, "graph.onnx", []byte{0x08, 0x01})
	writeFile(t, dir, "weights.safetensors", []byte(`{"a":1}`))
	writeFile(t, dir, "README.md", []byte("# card"))
	writeFile(t, dir, "weights.pkl.sigstore", []byte("{}"))
	writeFile(t, dir, "ignore-me.txt", []byte("noise"))

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
	if got := mocks.signature.VerifyArtifactCount.Load(); got != 1 {
		t.Errorf("SignatureVerifier.VerifyArtifact: want 1, got %d", got)
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
	writeFile(t, dir, "a.pkl", []byte{0x80, 0x04})
	writeFile(t, dir, "b.onnx", []byte{0x08, 0x01})

	mocks := newComposerMocks()
	mocks.pickle.AnalyzeFileResult = []providers.Finding{{Rule: "pickle-1"}}
	mocks.onnx.ValidateFileResult = []providers.Finding{{Rule: "onnx-1"}, {Rule: "onnx-2"}}
	c := mocks.wire()

	findings := c.Scan(dir)
	if len(findings) != 3 {
		t.Fatalf("expected 3 aggregated findings, got %d", len(findings))
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
	writeFile(t, excluded, "hidden.pkl", []byte{0x80, 0x04})
	// Sanity artifact in the visible tree.
	writeFile(t, dir, "visible.pkl", []byte{0x80, 0x04})

	mocks := newComposerMocks()
	c := mocks.wire()

	_ = c.Scan(dir)
	if got := mocks.pickle.AnalyzeFileCount.Load(); got != 1 {
		t.Errorf("expected exactly the visible pickle to be analysed, got %d calls", got)
	}
}

// ── functional-options nil-safety ────────────────────────────────────────────

func TestNewComposer_DefaultsAreInstalledForMissingOptions(t *testing.T) {
	// Construct with no options — the composer must still operate.
	c := aibom.NewComposer()

	dir := t.TempDir()
	path := writeFile(t, dir, "weights.pkl", []byte{0x80, 0x04})
	findings := c.Scan(path)
	// Skeletons return nil — but the test passes if no panic occurs.
	if findings != nil {
		t.Errorf("expected nil findings from default skeleton, got %d", len(findings))
	}
}
