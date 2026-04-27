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
