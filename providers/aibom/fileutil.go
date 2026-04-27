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
	// zipMagic is the local-file-header signature `PK\x03\x04`. PyTorch
	// checkpoints saved with torch.save() since 1.6 are ZIP archives wrapping
	// an inner data.pkl, so a .pt/.pth/.bin/.ckpt that begins with this magic
	// is still a legitimate pickle artifact — it is unwrapped by the pickle
	// analyser, not the safetensors validator.
	zipMagic = []byte{'P', 'K', 0x03, 0x04}
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
		// Torch checkpoints are pickle by default. Require the pickle magic
		// byte before classifying as pickle: an attacker who renames a non-
		// pickle file (or a ZIP-wrapped torch checkpoint, which starts with
		// "PK\x03\x04") to one of these extensions would otherwise be
		// dispatched to the pickle disassembler with garbage input.
		//
		// ZIP-wrapped checkpoints are still recognised — the pickle analyser
		// detects the ZIP magic and recurses into the inner data.pkl.
		if hasMagicPrefix(path, pickleMagic) {
			return providers.FormatPickle
		}
		if hasMagicPrefix(path, zipMagic) {
			return providers.FormatPickle
		}
		// Unreadable or non-matching magic — defer classification to the
		// extensionless fallback below; if THAT also fails the file is
		// reported as FormatUnknown rather than mis-routed to the pickle
		// path.
		return providers.FormatUnknown
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
