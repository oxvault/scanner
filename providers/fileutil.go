package providers

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

// IsExcludedDir returns true when the directory should be entirely skipped
// during source analysis. It is the single source of truth for directory
// exclusion across all providers (SAST, dep-audit, hook-analyzer).
func IsExcludedDir(name string) bool {
	return isExcludedDir(name)
}

// IsExcludedFile returns true when the file should be skipped during source
// analysis regardless of its directory.
func IsExcludedFile(name string) bool {
	return isExcludedFile(name)
}

// WalkScanFiles walks dir, skipping excluded directories and files (per the
// shared isExcludedDir / isExcludedFile rules), and calls fn for every
// remaining regular file. Symlinks are NOT followed — filepath.Walk's default
// behaviour. Walk errors are swallowed so a single unreadable subdirectory
// never aborts the whole scan.
//
// This is the cross-provider equivalent of the unexported walkSourceFiles in
// sast.go; consumers that don't care about source-language detection (e.g.
// the AIBOM composer) should use this helper rather than re-rolling their own
// filepath.Walk.
func WalkScanFiles(dir string, fn func(path string)) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if isExcludedDir(filepath.Base(path)) {
				return filepath.SkipDir
			}
			return nil
		}
		if isExcludedFile(filepath.Base(path)) {
			return nil
		}
		fn(path)
		return nil
	})
}

// ── AIBOM artifact-format detection ──────────────────────────────────────────
//
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
func DetectArtifactFormat(path string) ArtifactFormat {
	base := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(base))

	// Model cards: filename-based detection (no extension lookup).
	if isModelCardName(base) {
		return FormatModelCard
	}

	switch ext {
	case ".pkl", ".pickle":
		return FormatPickle
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
			return FormatPickle
		}
		if hasMagicPrefix(path, zipMagic) {
			return FormatPickle
		}
		// Unreadable or non-matching magic — defer classification to the
		// extensionless fallback below; if THAT also fails the file is
		// reported as FormatUnknown rather than mis-routed to the pickle
		// path.
		return FormatUnknown
	case ".onnx":
		return FormatONNX
	case ".safetensors":
		return FormatSafetensors
	case ".sigstore", ".sig", ".pem", ".cert":
		return FormatSignature
	}

	// Magic-byte fallback ONLY for files without an extension. Files with a
	// non-artifact extension (.json, .yaml, .txt, etc.) must NOT be reclassified
	// as safetensors / pickle / onnx — leading '{' would otherwise misroute
	// every JSON file into the safetensors validator (regression caught in HF
	// resolver smoke testing — config.json was firing header-overflow because
	// its first 8 bytes formed a uint64 larger than the file).
	if ext != "" {
		return FormatUnknown
	}
	switch {
	case hasMagicPrefix(path, pickleMagic):
		return FormatPickle
	case hasMagicPrefix(path, safetensorsMagic):
		return FormatSafetensors
	case hasMagicPrefix(path, onnxMagic):
		return FormatONNX
	}

	return FormatUnknown
}

// IsModelCardName returns true for documentation files that conventionally
// serve as model cards in HuggingFace, OpenSSF, and PyTorch Hub repositories.
//
// Recognised forms:
//
//   - readme.md                    (HuggingFace default)
//   - model_card.md / modelcard.md / model-card.md
//   - model_card.yaml / modelcard.yaml / model-card.yaml (and .yml variants)
//   - .modelcard.yaml / .modelcard.yml                   (dotted YAML form)
//
// The match is case-insensitive — callers should pass an already-lowercased
// base, or rely on the lower-case copy this function makes internally.
func IsModelCardName(base string) bool {
	return isModelCardName(base)
}

// isModelCardName is the lowercase-internal worker. It is kept unexported so
// callers within this package use the same path as DetectArtifactFormat
// without a string-allocation round-trip.
func isModelCardName(base string) bool {
	switch base {
	case "readme.md",
		"model_card.md", "modelcard.md", "model-card.md",
		"model_card.yaml", "modelcard.yaml", "model-card.yaml",
		"model_card.yml", "modelcard.yml", "model-card.yml",
		".modelcard.yaml", ".modelcard.yml":
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
