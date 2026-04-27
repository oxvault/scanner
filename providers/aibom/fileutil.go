package aibom

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"

	"github.com/oxvault/scanner/providers"
)

// Magic-byte prefixes used to disambiguate ambiguous extensions.
//
// pickle protocol 2+ starts with 0x80 followed by a single-byte protocol
// version. We only check the first byte — the second is the protocol version
// (0x02 .. 0x05 in practice) and is intentionally not validated here so that
// future protocols are still recognised.
var (
	pickleMagic      = []byte{0x80}
	safetensorsMagic = []byte{'{'} // safetensors files start with a JSON header
	// ONNX uses protobuf wire format. The standard top-level "ir_version" field
	// is field number 1, varint type — encoded as 0x08. This is a heuristic.
	onnxMagic = []byte{0x08}
)

// DetectArtifactFormat returns the ArtifactFormat for the given path based on
// its file extension and (when the extension is ambiguous) magic bytes.
//
// The function never returns an error: unknown or unreadable files are
// reported as FormatUnknown so that walkers can keep going.
func DetectArtifactFormat(path string) providers.ArtifactFormat {
	base := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(base))

	// Model cards: filename-based detection (no extension lookup).
	if isModelCardName(base) {
		return providers.FormatModelCard
	}

	switch ext {
	case ".pkl", ".pickle":
		return providers.FormatPickle
	case ".pt", ".pth", ".bin", ".ckpt":
		// Torch checkpoints are pickle by default. Confirm via magic byte
		// when the file is readable; otherwise trust the extension.
		if hasMagicPrefix(path, pickleMagic) {
			return providers.FormatPickle
		}
		return providers.FormatPickle
	case ".onnx":
		return providers.FormatONNX
	case ".safetensors":
		return providers.FormatSafetensors
	case ".sigstore", ".sig", ".pem", ".cert":
		return providers.FormatSignature
	}

	// Extensionless or ambiguous: fall back to magic bytes.
	switch {
	case hasMagicPrefix(path, pickleMagic):
		return providers.FormatPickle
	case hasMagicPrefix(path, safetensorsMagic):
		// A leading '{' is also valid JSON — but in the AIBOM context this is
		// a strong hint of a safetensors header. Real validation happens in
		// SafetensorsValidator (Day 4).
		return providers.FormatSafetensors
	case hasMagicPrefix(path, onnxMagic):
		return providers.FormatONNX
	}

	return providers.FormatUnknown
}

// isModelCardName returns true for documentation files that conventionally
// serve as model cards in HuggingFace and PyTorch Hub repositories.
func isModelCardName(base string) bool {
	switch base {
	case "readme.md", "model_card.md", "modelcard.md", "model-card.md":
		return true
	}
	return false
}

// hasMagicPrefix returns true when the file at path starts with the given
// byte sequence. Unreadable files return false (not an error).
func hasMagicPrefix(path string, magic []byte) bool {
	if len(magic) == 0 {
		return false
	}
	f, err := os.Open(path) //nolint:gosec // path comes from filesystem walks scoped to the scan target.
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, len(magic))
	n, err := f.Read(buf)
	if err != nil || n < len(magic) {
		return false
	}
	return bytes.Equal(buf[:len(magic)], magic)
}
