package providers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/oxvault/scanner/patterns"
)

// Signature verifier.
//
// Verifies the provenance of ML model artifacts via the OpenSSF Model Signing
// hash manifest format. Day 7 ships hash-only verification — the manifest
// declares a SHA-256 for each artifact path, and we re-hash the on-disk file
// to confirm it matches. Full Sigstore Rekor/Fulcio verification is deferred
// to v0.4.1.
//
// Three signature carriers are recognised:
//
//  1. OpenSSF Model Signing manifest — `model_signing.json` or `manifest.json`
//     next to the artifact. Schema:
//
//     {
//       "version": "1.0",
//       "artifacts": [
//         {"path": "pytorch_model.bin", "sha256": "abc..."},
//         {"path": "config.json",       "sha256": "def..."}
//       ],
//       "publisher": "did:web:meta.com",
//       "signature": "<base64>",
//       "issuer":    "https://accounts.google.com"
//     }
//
//  2. Sigstore bundle (`.sigstore`) — JSON shape only. Day 7 records its
//     presence so users know the artifact is signed; v0.4.1 will verify the
//     embedded Rekor entry against the public good instance.
//
//  3. Loose detached signature (`.sig`) — presence-only check.
//
// Rule ID table (kept in sync with the implementation below):
//
//	aibom-signature-missing             WARNING   no signature found alongside artifact
//	aibom-signature-invalid             CRITICAL  signature present but verification failed
//	aibom-signature-untrusted-issuer    HIGH      manifest issuer not in configured trusted list
//	aibom-signature-hash-mismatch       CRITICAL  manifest hash != actual artifact SHA-256
//	aibom-signature-malformed-manifest  WARNING   manifest JSON parse fails / size cap exceeded
//	aibom-signature-clean               INFO      manifest verified (hash match + trusted issuer)
//
// Layer rule: providers/ depends on patterns/ only. The verifier is pure
// stdlib crypto — no Sigstore SDK, no protobuf, no external deps.

// signatureManifest mirrors the OpenSSF Model Signing JSON shape. We only
// decode the fields we need for hash verification + issuer trust; unknown
// fields are silently ignored so future schema additions don't break the
// parser.
type signatureManifest struct {
	Version   string                  `json:"version"`
	Artifacts []signatureManifestItem `json:"artifacts"`
	Publisher string                  `json:"publisher"`
	Signature string                  `json:"signature"`
	Issuer    string                  `json:"issuer"`
}

// signatureManifestItem is a single entry inside the artifacts array.
type signatureManifestItem struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// signatureVerifier is the production SignatureVerifier. Stateless apart
// from the configured trusted-issuer set, which is captured at construction
// time via WithTrustedIssuers.
type signatureVerifier struct {
	// trustedIssuers is the set of OIDC issuer URLs accepted as "trusted".
	// A manifest whose issuer is missing from this set fires
	// aibom-signature-untrusted-issuer at HIGH severity. Empty means the
	// default list from patterns.DefaultTrustedSignatureIssuers is used.
	trustedIssuers map[string]bool
}

// SignatureVerifierOption configures the verifier. Follows the same
// functional-option style as the AIBOM composer / app container.
type SignatureVerifierOption func(*signatureVerifier)

// WithTrustedIssuers overrides the default OIDC issuer allowlist with the
// supplied list. Pass nil or an empty slice to keep the defaults; otherwise
// only the supplied issuers are trusted (the defaults are NOT merged in —
// users who want both should pass them explicitly).
func WithTrustedIssuers(issuers []string) SignatureVerifierOption {
	return func(v *signatureVerifier) {
		if len(issuers) == 0 {
			return
		}
		v.trustedIssuers = make(map[string]bool, len(issuers))
		for _, iss := range issuers {
			v.trustedIssuers[strings.TrimSpace(iss)] = true
		}
	}
}

// NewSignatureVerifier returns a production SignatureVerifier. The default
// trusted-issuer set is patterns.DefaultTrustedSignatureIssuers; pass
// WithTrustedIssuers to override.
func NewSignatureVerifier(opts ...SignatureVerifierOption) SignatureVerifier {
	v := &signatureVerifier{}
	for _, opt := range opts {
		opt(v)
	}
	if v.trustedIssuers == nil {
		v.trustedIssuers = make(map[string]bool, len(patterns.DefaultTrustedSignatureIssuers))
		for _, iss := range patterns.DefaultTrustedSignatureIssuers {
			v.trustedIssuers[iss] = true
		}
	}
	return v
}

// VerifyArtifact verifies the signature of the model artifact at path.
//
// Behaviour by file type:
//
//   - When path is a model artifact (.pkl/.pt/.onnx/.safetensors/...), the
//     verifier looks in the same directory for a paired manifest, sigstore
//     bundle, or loose .sig file and runs the appropriate check.
//   - When path is itself a signature carrier (.sigstore/.sig/.pem/.cert)
//     dispatched here by the composer, the verifier emits no findings —
//     signatures are evaluated FROM the artifact's perspective, not the
//     signature file's. This keeps double-counting at bay when the composer
//     walks a directory containing both.
//
// Returns nil for paths that cannot be opened. The named return is
// load-bearing for the deferred recover() — see comment in verifyArtifact.
func (v *signatureVerifier) VerifyArtifact(path string) []Finding {
	return v.verifyArtifact(path)
}

// VerifyDirectory walks dir and verifies every model artifact it finds.
//
// In production the AIBOMComposer owns directory walking and adds the
// per-artifact verification step itself (so the rule set fires on real
// `oxvault scan ./model-dir` invocations regardless of dispatch path). This
// method is preserved for callers that use the verifier standalone — it
// produces the same findings, so behaviour is identical regardless of entry
// point.
func (v *signatureVerifier) VerifyDirectory(dir string) []Finding {
	var findings []Finding
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
		if !isModelArtifactExt(path) {
			return nil
		}
		findings = append(findings, v.verifyArtifact(path)...)
		return nil
	})
	return findings
}

// ── per-artifact verifier ───────────────────────────────────────────────────

// verifyArtifact is the shared entry point for both VerifyArtifact (single
// file dispatch) and VerifyDirectory (per-file pass during a walk).
//
// The named return is load-bearing: the deferred recover() below appends a
// finding to it on panic. Without the named return, an explicit `return ...`
// would have already evaluated by the time the recover runs, causing the
// panic-derived finding to be silently dropped (same lesson learned in Day
// 5 onnx and Day 6 modelcard).
func (v *signatureVerifier) verifyArtifact(path string) (findings []Finding) {
	// Defensive: JSON unmarshal and SHA-256 streaming must NEVER take down
	// the scanner. On panic we surface a malformed-manifest WARNING so the
	// caller can still see something happened, rather than silently
	// swallowing the input.
	defer func() {
		if r := recover(); r != nil {
			findings = []Finding{{
				Rule:            "aibom-signature-malformed-manifest",
				Severity:        SeverityWarning,
				Confidence:      ConfidenceHigh,
				ConfidenceLabel: ConfidenceHigh.String(),
				File:            path,
				Message:         fmt.Sprintf("panic during signature verification: %v", r),
				CWE:             "CWE-20",
			}}
		}
	}()

	// Signature carriers themselves are never verified directly — they are
	// evaluated FROM the artifact's perspective by the next walk step. This
	// keeps the composer's per-file dispatch from double-counting findings.
	if isSignatureCarrier(path) {
		return nil
	}

	// Only model artifacts go through verification. Anything else (model
	// cards, random text files) is silently ignored.
	if !isModelArtifactExt(path) {
		return nil
	}

	// Confirm the artifact actually exists and is readable. A non-existent
	// or unreadable artifact is not a security finding by itself — the
	// pickle/onnx/safetensors validators handle their own readability
	// errors and would have surfaced a finding already.
	if _, err := os.Stat(path); err != nil {
		return nil
	}

	dir := filepath.Dir(path)
	base := filepath.Base(path)

	// 1. Loose detached signature (`.sig`) — presence-only check.
	if hasCompanion(dir, base+patterns.LooseSignatureExt) {
		return []Finding{cleanFinding(path, "loose .sig file present alongside artifact (presence-only check; cryptographic verification deferred to v0.4.1)")}
	}

	// 2. Sigstore bundle (`.sigstore`) — JSON shape check only.
	if bundlePath := findCompanion(dir, base+patterns.SigstoreBundleExt); bundlePath != "" {
		return verifySigstoreBundle(path, bundlePath)
	}

	// 3. OpenSSF Model Signing manifest — model_signing.json or manifest.json.
	if manifestPath := findManifest(dir); manifestPath != "" {
		return v.verifyManifest(path, manifestPath)
	}

	// No signature carrier found.
	return []Finding{{
		Rule:            "aibom-signature-missing",
		Severity:        SeverityWarning,
		Confidence:      ConfidenceHigh,
		ConfidenceLabel: ConfidenceHigh.String(),
		File:            path,
		Message:         "model artifact has no paired signature (no model_signing.json, no .sigstore bundle, no .sig file)",
		CWE:             "CWE-347",
	}}
}

// ── manifest verification ───────────────────────────────────────────────────

// verifyManifest reads the OpenSSF Model Signing manifest at manifestPath
// and verifies the artifact at artifactPath against it.
//
// The verification chain is:
//
//  1. Manifest exists and is within the size cap.
//  2. Manifest parses as JSON (object shape).
//  3. Manifest's artifacts[] contains an entry whose `path` matches the
//     artifact's basename.
//  4. The on-disk SHA-256 of the artifact equals the manifest's declared
//     hash.
//  5. The manifest's `issuer` is in the configured trusted-issuer set.
//
// Failures are reported with distinct rule ids so users can triage:
// "manifest is broken" vs "hash doesn't match" vs "issuer not trusted".
func (v *signatureVerifier) verifyManifest(artifactPath, manifestPath string) []Finding {
	data, sizeFinding := readBoundedFile(manifestPath, patterns.MaxSignatureManifestBytes)
	if sizeFinding != nil {
		return []Finding{*sizeFinding}
	}

	var manifest signatureManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return []Finding{{
			Rule:            "aibom-signature-malformed-manifest",
			Severity:        SeverityWarning,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            manifestPath,
			Message:         "signature manifest JSON is malformed: " + err.Error(),
			CWE:             "CWE-20",
		}}
	}

	// Locate the artifact entry by basename. Manifest paths may be relative
	// to the manifest directory or bare basenames; we accept both.
	artifactBase := filepath.Base(artifactPath)
	var entry *signatureManifestItem
	for i := range manifest.Artifacts {
		item := &manifest.Artifacts[i]
		if filepath.Base(item.Path) == artifactBase {
			entry = item
			break
		}
	}
	if entry == nil {
		return []Finding{{
			Rule:            "aibom-signature-invalid",
			Severity:        SeverityCritical,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            artifactPath,
			Message: fmt.Sprintf(
				"signature manifest %s lists no entry for artifact %q — manifest does not cover this file",
				filepath.Base(manifestPath), artifactBase),
			CWE: "CWE-347",
		}}
	}

	// Hash check. A mismatch means the artifact was modified after signing
	// — the canonical sign-then-tamper attack. CRITICAL.
	actual, hashErr := sha256File(artifactPath)
	if hashErr != nil {
		// Treat unreadable as a malformed-manifest signal — the manifest
		// itself parsed fine but the artifact it covers is unreadable.
		return []Finding{{
			Rule:            "aibom-signature-malformed-manifest",
			Severity:        SeverityWarning,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            artifactPath,
			Message:         "could not hash artifact for manifest verification: " + hashErr.Error(),
			CWE:             "CWE-20",
		}}
	}
	declared := strings.ToLower(strings.TrimSpace(entry.SHA256))
	if declared != actual {
		return []Finding{{
			Rule:            "aibom-signature-hash-mismatch",
			Severity:        SeverityCritical,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            artifactPath,
			Message: fmt.Sprintf(
				"manifest hash mismatch: declared %s, actual %s — artifact was modified after signing",
				truncateHex(declared), truncateHex(actual)),
			CWE: "CWE-353",
		}}
	}

	// Issuer trust check. An untrusted issuer means a valid hash AND a
	// valid signature, but signed by an identity the user did not approve.
	// We surface HIGH (not CRITICAL) — the integrity is intact, only the
	// provenance is suspect.
	issuer := strings.TrimSpace(manifest.Issuer)
	if issuer == "" {
		return []Finding{{
			Rule:            "aibom-signature-untrusted-issuer",
			Severity:        SeverityHigh,
			Confidence:      ConfidenceMedium,
			ConfidenceLabel: ConfidenceMedium.String(),
			File:            artifactPath,
			Message:         "signature manifest declares no issuer — provenance cannot be attributed",
			CWE:             "CWE-347",
		}}
	}
	if !v.trustedIssuers[issuer] {
		return []Finding{{
			Rule:            "aibom-signature-untrusted-issuer",
			Severity:        SeverityHigh,
			Confidence:      ConfidenceMedium,
			ConfidenceLabel: ConfidenceMedium.String(),
			File:            artifactPath,
			Message: fmt.Sprintf(
				"signature manifest issuer %q is not in the configured trusted-issuer list",
				issuer),
			CWE: "CWE-347",
		}}
	}

	// All checks passed — emit the clean INFO finding.
	return []Finding{cleanFinding(artifactPath, fmt.Sprintf(
		"signature manifest verified (sha256 match, issuer %q trusted)", issuer))}
}

// ── sigstore bundle (presence + JSON shape only) ────────────────────────────

// verifySigstoreBundle performs a presence + JSON-shape check on a
// `.sigstore` bundle. Day 7 does NOT verify the embedded Rekor entry — that
// requires the Sigstore SDK and lands in v0.4.1.
//
// Failures here are limited to: the bundle file is unreadable, exceeds the
// size cap, or fails JSON parsing. All other "validation" passes through
// silently to the clean INFO finding — the user knows the artifact is
// signed; they don't yet know whether the signature is valid.
func verifySigstoreBundle(artifactPath, bundlePath string) []Finding {
	data, sizeFinding := readBoundedFile(bundlePath, patterns.MaxSignatureManifestBytes)
	if sizeFinding != nil {
		return []Finding{*sizeFinding}
	}
	// Just check JSON parses to an object — sigstore bundles are always
	// JSON objects per the spec.
	var probe map[string]any
	if err := json.Unmarshal(data, &probe); err != nil {
		return []Finding{{
			Rule:            "aibom-signature-malformed-manifest",
			Severity:        SeverityWarning,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            bundlePath,
			Message:         "sigstore bundle JSON is malformed: " + err.Error(),
			CWE:             "CWE-20",
		}}
	}
	return []Finding{cleanFinding(artifactPath,
		"sigstore bundle present alongside artifact (Rekor/Fulcio verification deferred to v0.4.1)")}
}

// ── helpers ─────────────────────────────────────────────────────────────────

// cleanFinding constructs the standard aibom-signature-clean INFO finding.
func cleanFinding(path, msg string) Finding {
	return Finding{
		Rule:            "aibom-signature-clean",
		Severity:        SeverityInfo,
		Confidence:      ConfidenceHigh,
		ConfidenceLabel: ConfidenceHigh.String(),
		File:            path,
		Message:         msg,
	}
}

// readBoundedFile reads up to maxBytes+1 from path. Returns the data and
// (nil) on success. On size-cap or read failure returns nil and a Finding
// the caller can append; the second return is a *Finding so a nil pointer
// disambiguates "no problem" from "empty findings".
func readBoundedFile(path string, maxBytes int64) ([]byte, *Finding) {
	f, err := os.Open(path) //nolint:gosec // path comes from filesystem walks scoped to the scan target.
	if err != nil {
		return nil, &Finding{
			Rule:            "aibom-signature-malformed-manifest",
			Severity:        SeverityWarning,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message:         "could not read signature manifest: " + err.Error(),
			CWE:             "CWE-20",
		}
	}
	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		return nil, &Finding{
			Rule:            "aibom-signature-malformed-manifest",
			Severity:        SeverityWarning,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message:         "could not stat signature manifest: " + err.Error(),
			CWE:             "CWE-20",
		}
	}
	if stat.Size() > maxBytes {
		return nil, &Finding{
			Rule:            "aibom-signature-malformed-manifest",
			Severity:        SeverityWarning,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message: fmt.Sprintf(
				"signature manifest is %d bytes — exceeds the %d-byte safety cap",
				stat.Size(), maxBytes),
			CWE: "CWE-20",
		}
	}

	// Bounded read with peek-one-extra-byte so we still catch a producer
	// that lies about its declared length.
	limited := io.LimitReader(f, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, &Finding{
			Rule:            "aibom-signature-malformed-manifest",
			Severity:        SeverityWarning,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message:         "could not read signature manifest body: " + err.Error(),
			CWE:             "CWE-20",
		}
	}
	if int64(len(data)) > maxBytes {
		return nil, &Finding{
			Rule:            "aibom-signature-malformed-manifest",
			Severity:        SeverityWarning,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message: fmt.Sprintf(
				"signature manifest exceeds %d-byte safety cap during read", maxBytes),
			CWE: "CWE-20",
		}
	}
	return data, nil
}

// sha256File streams path through SHA-256 and returns the lowercase hex
// digest. Streaming is mandatory — model artifacts can be multi-GB and a
// naive io.ReadAll would OOM the scanner on large checkpoints.
func sha256File(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // path comes from filesystem walks scoped to the scan target.
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hasCompanion returns true when a file at dir/name exists and is readable.
func hasCompanion(dir, name string) bool {
	info, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// findCompanion returns the absolute path to dir/name if it exists, or "".
func findCompanion(dir, name string) string {
	full := filepath.Join(dir, name)
	info, err := os.Stat(full)
	if err != nil || info.IsDir() {
		return ""
	}
	return full
}

// findManifest returns the path to a recognised OpenSSF Model Signing
// manifest in dir, or "" if none is present. Lookup is case-insensitive on
// the basename — `MANIFEST.json` is accepted alongside `manifest.json`.
func findManifest(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if patterns.SignatureManifestNames[strings.ToLower(e.Name())] {
			return filepath.Join(dir, e.Name())
		}
	}
	return ""
}

// isModelArtifactExt returns true when path's extension is in the AIBOM
// model-artifact set. Used to scope the verifier's walk to files that are
// plausibly model checkpoints.
func isModelArtifactExt(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return patterns.SignatureModelArtifactExtensions[ext]
}

// isSignatureCarrier returns true for files the AIBOM module classifies as
// FormatSignature. The signature verifier never operates on a signature
// file directly — it operates on the artifact a signature covers, so the
// composer's per-file dispatch passing us a .sigstore is a no-op.
func isSignatureCarrier(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case patterns.SigstoreBundleExt, patterns.LooseSignatureExt, ".pem", ".cert":
		return true
	}
	return false
}

// truncateHex returns the first 12 characters of a hex string, with an
// ellipsis when truncation occurred. Keeps finding messages from blowing
// out terminal width while still being unique enough to triage.
func truncateHex(hex string) string {
	if len(hex) <= 12 {
		return hex
	}
	return hex[:12] + "..."
}

// missingSignatureFindings emits one aibom-signature-missing WARNING per
// model artifact that has no paired signature. Pulled out as a helper so
// both the standalone VerifyDirectory entry point AND the AIBOM composer
// can share identical aggregation logic — same approach used for the
// missing-card rule in modelcard.go.
//
// The verifier is passed in so the function can dispatch through the user-
// configured trusted issuer set when a manifest IS present.
func missingSignatureFindings(v SignatureVerifier, artifactPaths []string) []Finding {
	var findings []Finding
	for _, p := range artifactPaths {
		findings = append(findings, v.VerifyArtifact(p)...)
	}
	return findings
}

// ── compile-time interface guard ────────────────────────────────────────────

var _ SignatureVerifier = (*signatureVerifier)(nil)
