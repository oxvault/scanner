package aibom_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oxvault/scanner/providers"
	"github.com/oxvault/scanner/providers/aibom"
)

func TestDetectArtifactFormat_ByExtension(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		body     []byte
		want     providers.ArtifactFormat
	}{
		{"pkl", "weights.pkl", []byte("anything"), providers.FormatPickle},
		{"pickle", "weights.pickle", []byte("anything"), providers.FormatPickle},
		{"pt torch checkpoint", "model.pt", []byte{0x80, 0x02}, providers.FormatPickle},
		{"pth torch checkpoint", "model.pth", []byte{0x80, 0x02}, providers.FormatPickle},
		{"bin torch checkpoint", "pytorch_model.bin", []byte{0x80, 0x04}, providers.FormatPickle},
		{"ckpt", "checkpoint.ckpt", []byte{0x80, 0x04}, providers.FormatPickle},
		{"onnx", "graph.onnx", []byte{0x08, 0x01}, providers.FormatONNX},
		{"safetensors", "weights.safetensors", []byte(`{"a":1}`), providers.FormatSafetensors},
		{"sigstore bundle", "weights.pkl.sigstore", []byte("{}"), providers.FormatSignature},
		{"detached sig", "weights.pkl.sig", []byte("xxx"), providers.FormatSignature},
		{"pem cert", "cert.pem", []byte("-----BEGIN"), providers.FormatSignature},
		{"cert", "leaf.cert", []byte("-----BEGIN"), providers.FormatSignature},
		{"readme model card", "README.md", []byte("# card"), providers.FormatModelCard},
		{"explicit model card", "MODEL_CARD.md", []byte("# card"), providers.FormatModelCard},
		{"hyphen model card", "model-card.md", []byte("# card"), providers.FormatModelCard},
		{"compact model card", "modelcard.md", []byte("# card"), providers.FormatModelCard},
		{"unknown plain text", "notes.txt", []byte("hello"), providers.FormatUnknown},
		{"unknown extension", "data.parquet", []byte("PAR1"), providers.FormatUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tt.filename)
			if err := os.WriteFile(path, tt.body, 0o644); err != nil {
				t.Fatal(err)
			}

			got := aibom.DetectArtifactFormat(path)
			if got != tt.want {
				t.Errorf("DetectArtifactFormat(%q) = %q, want %q", tt.filename, got, tt.want)
			}
		})
	}
}

func TestDetectArtifactFormat_CaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Weights.PKL")
	if err := os.WriteFile(path, []byte{0x80}, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := aibom.DetectArtifactFormat(path); got != providers.FormatPickle {
		t.Errorf("expected FormatPickle for upper-case extension, got %q", got)
	}
}

func TestDetectArtifactFormat_MagicByteFallback_Pickle(t *testing.T) {
	dir := t.TempDir()
	// No recognised extension — must fall back to magic bytes.
	path := filepath.Join(dir, "noext")
	if err := os.WriteFile(path, []byte{0x80, 0x04, 0x95}, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := aibom.DetectArtifactFormat(path); got != providers.FormatPickle {
		t.Errorf("expected FormatPickle from magic-byte fallback, got %q", got)
	}
}

func TestDetectArtifactFormat_MagicByteFallback_Safetensors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "noext")
	if err := os.WriteFile(path, []byte(`{"__metadata__":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := aibom.DetectArtifactFormat(path); got != providers.FormatSafetensors {
		t.Errorf("expected FormatSafetensors from leading-brace fallback, got %q", got)
	}
}

func TestDetectArtifactFormat_MagicByteFallback_ONNX(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "noext")
	if err := os.WriteFile(path, []byte{0x08, 0x07}, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := aibom.DetectArtifactFormat(path); got != providers.FormatONNX {
		t.Errorf("expected FormatONNX from protobuf magic, got %q", got)
	}
}

func TestDetectArtifactFormat_NonexistentFileReturnsUnknown(t *testing.T) {
	got := aibom.DetectArtifactFormat("/no/such/file/here.weird")
	if got != providers.FormatUnknown {
		t.Errorf("expected FormatUnknown for missing file, got %q", got)
	}
}

func TestDetectArtifactFormat_EmptyFileWithUnknownExt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.unknownext")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := aibom.DetectArtifactFormat(path); got != providers.FormatUnknown {
		t.Errorf("expected FormatUnknown for empty file, got %q", got)
	}
}

// TestDetectArtifactFormat_TorchExtMissingMagic verifies that a file with a
// torch-checkpoint extension but NO pickle magic byte is reported as
// FormatUnknown rather than mis-routed to the pickle disassembler. This is
// the regression test for the dead-branch fix in the .pt/.pth/.bin/.ckpt
// extension switch.
func TestDetectArtifactFormat_TorchExtMissingMagic(t *testing.T) {
	tests := []struct {
		name     string
		filename string
	}{
		{"pt with text content", "fake.pt"},
		{"pth with text content", "fake.pth"},
		{"bin with text content", "fake.bin"},
		{"ckpt with text content", "fake.ckpt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tt.filename)
			// "Hello world" — neither pickle nor zip magic.
			if err := os.WriteFile(path, []byte("Hello world\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if got := aibom.DetectArtifactFormat(path); got != providers.FormatUnknown {
				t.Errorf("expected FormatUnknown for non-pickle %s, got %q", tt.filename, got)
			}
		})
	}
}

// TestDetectArtifactFormat_TorchExtZipMagic verifies that ZIP-wrapped torch
// checkpoints (the standard PyTorch save format since 1.6) are still
// classified as pickle so the analyser unwraps them.
func TestDetectArtifactFormat_TorchExtZipMagic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "model.pt")
	// PK\x03\x04 — local-file-header signature.
	if err := os.WriteFile(path, []byte{'P', 'K', 0x03, 0x04, 0x00}, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := aibom.DetectArtifactFormat(path); got != providers.FormatPickle {
		t.Errorf("expected FormatPickle for ZIP-wrapped .pt, got %q", got)
	}
}
