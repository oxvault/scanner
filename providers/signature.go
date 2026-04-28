package providers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/oxvault/scanner/patterns"
)

// Signature verifier.
//
// Verifies the provenance of ML model artifacts via the OpenSSF Model Signing
// hash manifest format. v0.4 ships hash-only verification — the manifest
// declares a SHA-256 for each artifact path, and we re-hash the on-disk file
// to confirm it matches. Full Sigstore Rekor/Fulcio + OIDC chain verification
// is deferred to v0.4.1.
//
// Three signature carriers are recognised:
//
//  1. OpenSSF Model Signing manifest — `model_signing.json` next to the
//     artifact. Schema:
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
//  2. Sigstore bundle (`.sigstore`) — JSON shape + spec-shaped content. The
//     bundle must contain at least one of the keys defined in
//     patterns.SigstoreBundleSpecKeys (mediaType, messageSignature,
//     verificationMaterial, dsseEnvelope). Empty `{}` or arbitrary JSON is
//     rejected as a malformed bundle. v0.4.1 will verify the embedded Rekor
//     entry against the public good instance.
//
//  3. Loose detached signature (`.sig`) — presence-only check.
//
// Carrier priority on a multi-carrier directory: manifest > .sigstore > .sig.
// All present carriers are evaluated and their findings merged — any failure
// promotes the artifact's verdict to CRITICAL.
//
// Rule ID table (kept in sync with the implementation below):
//
//	aibom-signature-missing             WARNING   no signature found alongside artifact
//	aibom-signature-invalid             CRITICAL  signature present but verification failed
//	aibom-signature-untrusted-issuer    HIGH      manifest issuer not in configured trusted list
//	aibom-signature-hash-mismatch       CRITICAL  manifest hash != actual artifact SHA-256
//	aibom-signature-malformed-manifest  WARNING   manifest JSON parse fails / size cap exceeded
//	aibom-signature-malformed-bundle    WARNING   sigstore bundle missing spec-shaped content
//	aibom-signature-hash-match          INFO      manifest hash matches; issuer self-declared (v0.4)
//	aibom-signature-presence-deferred   INFO      .sigstore / .sig present; crypto deferred to v0.4.1
//	aibom-signature-clean               INFO      RESERVED for v0.4.1 OIDC-verified path
//
// Layer rule: providers/ depends on patterns/ only. The verifier is pure
// stdlib crypto — no Sigstore SDK, no protobuf, no external deps.

// Rule IDs surfaced by the verifier. Defined as constants so the test suite
// and the docs can reference them without typos drifting between layers.
const (
	RuleSignatureMissing           = "aibom-signature-missing"
	RuleSignatureInvalid           = "aibom-signature-invalid"
	RuleSignatureUntrustedIssuer   = "aibom-signature-untrusted-issuer"
	RuleSignatureHashMismatch      = "aibom-signature-hash-mismatch"
	RuleSignatureMalformedManifest = "aibom-signature-malformed-manifest"
	RuleSignatureMalformedBundle   = "aibom-signature-malformed-bundle"
	RuleSignatureHashMatch         = "aibom-signature-hash-match"
	RuleSignaturePresenceDeferred  = "aibom-signature-presence-deferred"
	// RuleSignatureClean is RESERVED for the v0.4.1 OIDC-verified path. v0.4
	// must NOT emit this rule — manifest verification stops at hash + self-
	// declared issuer; until Rekor/Fulcio chain verification ships, no
	// "clean" claim can be honestly made.
	RuleSignatureClean = "aibom-signature-clean"
)

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
// time via WithTrustedIssuers / WithAdditionalTrustedIssuers.
type signatureVerifier struct {
	// trustedIssuers is the set of canonicalised OIDC issuer URLs accepted
	// as "trusted". A manifest whose issuer is missing from this set fires
	// aibom-signature-untrusted-issuer at HIGH severity. Keys are stored
	// post-canonicalisation (lowercase scheme + host, no trailing slash) —
	// see canonicaliseIssuer.
	trustedIssuers map[string]bool
}

// SignatureVerifierOption configures the verifier. Follows the same
// functional-option style as the AIBOM composer / app container.
type SignatureVerifierOption func(*signatureVerifier)

// WithTrustedIssuers REPLACES the default OIDC issuer allowlist with the
// supplied list. Pass nil or an empty slice to keep the defaults; otherwise
// only the supplied issuers are trusted (the defaults are NOT merged in —
// users who want both should pass them explicitly, or use
// WithAdditionalTrustedIssuers to merge with defaults).
//
// Issuer URLs are canonicalised (lowercase scheme/host, trailing slash
// trimmed) before storage — case-only differences and trailing-slash
// noise will not cause spurious untrusted-issuer findings.
//
// IMPORTANT: this option REPLACES the default list. If the caller's
// supplied list does not include `https://accounts.google.com`, manifests
// signed by a Google Cloud OIDC identity will be flagged as untrusted.
// Use WithAdditionalTrustedIssuers if the intent is to add to the
// defaults rather than replace them.
func WithTrustedIssuers(issuers []string) SignatureVerifierOption {
	return func(v *signatureVerifier) {
		if len(issuers) == 0 {
			return
		}
		v.trustedIssuers = make(map[string]bool, len(issuers))
		for _, iss := range issuers {
			if c := canonicaliseIssuer(iss); c != "" {
				v.trustedIssuers[c] = true
			}
		}
	}
}

// WithAdditionalTrustedIssuers MERGES the supplied list with the default
// OIDC issuer allowlist. Use this when you want to extend (not replace)
// the defaults — e.g. accept the standard Sigstore public issuers AND
// your internal corporate OIDC.
//
// Issuer URLs are canonicalised (lowercase scheme/host, trailing slash
// trimmed) before storage.
//
// Order of evaluation: NewSignatureVerifier seeds the default set; this
// option layers on top. If both WithTrustedIssuers and
// WithAdditionalTrustedIssuers are passed, the order they appear in the
// constructor call determines the final set — WithTrustedIssuers will
// reset the map, so put it first if you want to combine "narrow base" +
// "explicit additions".
func WithAdditionalTrustedIssuers(issuers []string) SignatureVerifierOption {
	return func(v *signatureVerifier) {
		if v.trustedIssuers == nil {
			// Seed defaults so the merge has a base set.
			v.trustedIssuers = make(map[string]bool, len(patterns.DefaultTrustedSignatureIssuers))
			for _, iss := range patterns.DefaultTrustedSignatureIssuers {
				if c := canonicaliseIssuer(iss); c != "" {
					v.trustedIssuers[c] = true
				}
			}
		}
		for _, iss := range issuers {
			if c := canonicaliseIssuer(iss); c != "" {
				v.trustedIssuers[c] = true
			}
		}
	}
}

// NewSignatureVerifier returns a production SignatureVerifier. The default
// trusted-issuer set is patterns.DefaultTrustedSignatureIssuers; pass
// WithTrustedIssuers to replace, or WithAdditionalTrustedIssuers to merge.
func NewSignatureVerifier(opts ...SignatureVerifierOption) SignatureVerifier {
	v := &signatureVerifier{}
	for _, opt := range opts {
		opt(v)
	}
	if v.trustedIssuers == nil {
		v.trustedIssuers = make(map[string]bool, len(patterns.DefaultTrustedSignatureIssuers))
		for _, iss := range patterns.DefaultTrustedSignatureIssuers {
			if c := canonicaliseIssuer(iss); c != "" {
				v.trustedIssuers[c] = true
			}
		}
	}
	return v
}

// VerifyArtifact verifies the signature of the model artifact at path.
//
// Behaviour by file type:
//
//   - When path is a model artifact (.pkl/.pt/.onnx/.safetensors/...), the
//     verifier looks in the same directory for ALL paired carriers
//     (manifest, sigstore bundle, loose .sig) and runs each check it
//     can. Findings from every present carrier are merged — any failure
//     promotes the verdict to CRITICAL. This prevents an attacker from
//     dropping a 1-byte `.sig` to shadow a real manifest.
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
//
// Carrier priority: when multiple carriers are present we evaluate ALL of
// them in order (manifest > .sigstore > .sig) and merge findings. The
// "any failure promotes to CRITICAL" rule is enforced naturally — every
// failed check appends its own finding, and the reporter picks the highest
// severity.
func (v *signatureVerifier) verifyArtifact(path string) (findings []Finding) {
	// Defensive: JSON unmarshal and SHA-256 streaming must NEVER take down
	// the scanner. On panic we surface a malformed-manifest WARNING so the
	// caller can still see something happened, rather than silently
	// swallowing the input.
	defer func() {
		if r := recover(); r != nil {
			findings = []Finding{{
				Rule:            RuleSignatureMalformedManifest,
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

	var merged []Finding
	hasCarrier := false

	// Carrier priority — manifest first, then sigstore bundle, then loose
	// .sig. Each carrier present contributes its own findings; the
	// reporter promotes to CRITICAL when any of them fails.
	//
	// 1. OpenSSF Model Signing manifest — model_signing.json.
	if manifestPath := findManifest(dir); manifestPath != "" {
		hasCarrier = true
		merged = append(merged, v.verifyManifest(path, manifestPath)...)
	}

	// 2. Sigstore bundle (`.sigstore`) — JSON shape + spec-shaped content.
	if bundlePath := findCompanion(dir, base+patterns.SigstoreBundleExt); bundlePath != "" {
		hasCarrier = true
		merged = append(merged, verifySigstoreBundle(path, bundlePath)...)
	}

	// 3. Loose detached signature (`.sig`) — presence-only check.
	if sigPath := findCompanion(dir, base+patterns.LooseSignatureExt); sigPath != "" {
		hasCarrier = true
		merged = append(merged, verifyLooseSig(path, sigPath)...)
	}

	if hasCarrier {
		return merged
	}

	// No signature carrier found.
	return []Finding{{
		Rule:            RuleSignatureMissing,
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
//  4. The manifest's declared SHA-256 is well-formed (64 hex chars).
//  5. The on-disk SHA-256 of the artifact equals the manifest's declared
//     hash.
//  6. The manifest's `issuer` is in the configured trusted-issuer set
//     (post-canonicalisation).
//
// Failures are reported with distinct rule ids so users can triage:
// "manifest is broken" vs "hash doesn't match" vs "issuer not trusted".
//
// SUCCESS PATH (v0.4): emits aibom-signature-hash-match INFO. The message
// makes the trust posture explicit — the issuer is self-declared by the
// manifest writer, with no cryptographic chain proving who actually
// signed. v0.4.1 will perform Rekor/Fulcio + OIDC chain verification and
// promote successful runs to aibom-signature-clean. We deliberately do
// NOT emit -clean here to avoid misleading users about the level of
// trust the v0.4 hash-only check provides.
func (v *signatureVerifier) verifyManifest(artifactPath, manifestPath string) []Finding {
	data, sizeFinding := readBoundedFile(manifestPath, patterns.MaxSignatureManifestBytes)
	if sizeFinding != nil {
		return []Finding{*sizeFinding}
	}

	var manifest signatureManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return []Finding{{
			Rule:            RuleSignatureMalformedManifest,
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
			Rule:            RuleSignatureInvalid,
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

	// Validate declared hash format BEFORE any equality check or message
	// formatting. An attacker controls the manifest contents — without
	// this validation, garbage like "DROP TABLE" or terminal escape
	// sequences would flow into Finding.Message verbatim. Reject anything
	// that isn't exactly 64 lowercase hex chars.
	declared := strings.ToLower(strings.TrimSpace(entry.SHA256))
	if !sha256HexRegex.MatchString(declared) {
		return []Finding{{
			Rule:            RuleSignatureMalformedManifest,
			Severity:        SeverityWarning,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            manifestPath,
			Message: fmt.Sprintf(
				"signature manifest declared hash for %q is not a valid SHA-256 hex digest (expected 64 lowercase hex characters)",
				artifactBase),
			CWE: "CWE-20",
		}}
	}

	// Hash check. A mismatch means the artifact was modified after signing
	// — the canonical sign-then-tamper attack. CRITICAL.
	actual, hashErr := sha256File(artifactPath)
	if hashErr != nil {
		// Treat unreadable as a malformed-manifest signal — the manifest
		// itself parsed fine but the artifact it covers is unreadable.
		return []Finding{{
			Rule:            RuleSignatureMalformedManifest,
			Severity:        SeverityWarning,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            artifactPath,
			Message:         "could not hash artifact for manifest verification: " + hashErr.Error(),
			CWE:             "CWE-20",
		}}
	}
	if declared != actual {
		return []Finding{{
			Rule:            RuleSignatureHashMismatch,
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
	rawIssuer := strings.TrimSpace(manifest.Issuer)
	if rawIssuer == "" {
		return []Finding{{
			Rule:            RuleSignatureUntrustedIssuer,
			Severity:        SeverityHigh,
			Confidence:      ConfidenceMedium,
			ConfidenceLabel: ConfidenceMedium.String(),
			File:            artifactPath,
			Message:         "signature manifest declares no issuer — provenance cannot be attributed",
			CWE:             "CWE-347",
		}}
	}
	canonIssuer := canonicaliseIssuer(rawIssuer)
	if canonIssuer == "" || !v.trustedIssuers[canonIssuer] {
		return []Finding{{
			Rule:            RuleSignatureUntrustedIssuer,
			Severity:        SeverityHigh,
			Confidence:      ConfidenceMedium,
			ConfidenceLabel: ConfidenceMedium.String(),
			File:            artifactPath,
			Message: fmt.Sprintf(
				"signature manifest issuer %q is not in the configured trusted-issuer list",
				rawIssuer),
			CWE: "CWE-347",
		}}
	}

	// All checks passed — emit the v0.4 hash-match INFO. We deliberately
	// do NOT emit aibom-signature-clean: this path verified the artifact
	// SHA-256 matches the manifest's declared hash, but it did NOT verify
	// who actually signed the manifest. The issuer field is a self-
	// declaration that the attacker controls if they control the
	// manifest. v0.4.1 will perform Rekor/Fulcio chain verification and
	// promote successful runs to aibom-signature-clean.
	return []Finding{{
		Rule:            RuleSignatureHashMatch,
		Severity:        SeverityInfo,
		Confidence:      ConfidenceHigh,
		ConfidenceLabel: ConfidenceHigh.String(),
		File:            artifactPath,
		Message: fmt.Sprintf(
			"manifest hash matches artifact (issuer %q is self-declared; OIDC verification ships in v0.4.1)",
			rawIssuer),
	}}
}

// ── sigstore bundle (presence + JSON shape + spec-shaped keys) ──────────────

// verifySigstoreBundle performs a presence + JSON-shape + spec-shaped-keys
// check on a `.sigstore` bundle. Day 7 does NOT verify the embedded Rekor
// entry — that requires the Sigstore SDK and lands in v0.4.1.
//
// Failures here are limited to: the bundle file is unreadable, exceeds the
// size cap, fails JSON parsing, or parses fine but is missing every key
// defined in the Sigstore Bundle proto spec. The last case is the trust-
// model fix landed in this PR — an attacker dropping `{}` next to a
// tampered artifact can no longer pass a presence-only check.
func verifySigstoreBundle(artifactPath, bundlePath string) []Finding {
	data, sizeFinding := readBoundedFile(bundlePath, patterns.MaxSignatureManifestBytes)
	if sizeFinding != nil {
		return []Finding{*sizeFinding}
	}
	var probe map[string]any
	if err := json.Unmarshal(data, &probe); err != nil {
		return []Finding{{
			Rule:            RuleSignatureMalformedBundle,
			Severity:        SeverityWarning,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            bundlePath,
			Message:         "sigstore bundle JSON is malformed: " + err.Error(),
			CWE:             "CWE-20",
		}}
	}
	// A real Sigstore bundle must contain at least one of the spec-defined
	// top-level keys. Empty `{}`, `null`, or any random JSON object is
	// rejected — otherwise an attacker can spoof a "signed" claim by
	// dropping a JSON file with the right extension.
	if !hasSigstoreSpecKey(probe) {
		return []Finding{{
			Rule:            RuleSignatureMalformedBundle,
			Severity:        SeverityWarning,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            bundlePath,
			Message: fmt.Sprintf(
				"sigstore bundle is missing all required top-level keys (expected one of: %s)",
				strings.Join(patterns.SigstoreBundleSpecKeys, ", ")),
			CWE: "CWE-345",
		}}
	}
	// Spec-shaped bundle present. Crypto verification is deferred to
	// v0.4.1 — flag the deferral explicitly so users see the gap rather
	// than reading a "clean" verdict that doesn't exist yet.
	return []Finding{{
		Rule:            RuleSignaturePresenceDeferred,
		Severity:        SeverityInfo,
		Confidence:      ConfidenceHigh,
		ConfidenceLabel: ConfidenceHigh.String(),
		File:            artifactPath,
		Message:         "sigstore bundle present alongside artifact — cryptographic verification deferred to v0.4.1",
	}}
}

// verifyLooseSig handles a `.sig` companion file. v0.4 has no way to
// verify a detached signature without the public key, so the check is
// presence-only: report deferral. Empty `.sig` files are a flavour of
// "presence" — we still emit the deferred-verification finding so the
// directory is not silently treated as signed.
func verifyLooseSig(artifactPath, sigPath string) []Finding {
	// Presence is enough for v0.4. We do not parse the .sig contents
	// because there is no canonical schema for "loose detached signature"
	// — they're commonly raw DER or PEM, and inspecting them without a
	// trust anchor is meaningless.
	_ = sigPath
	return []Finding{{
		Rule:            RuleSignaturePresenceDeferred,
		Severity:        SeverityInfo,
		Confidence:      ConfidenceHigh,
		ConfidenceLabel: ConfidenceHigh.String(),
		File:            artifactPath,
		Message:         "loose .sig file present alongside artifact — cryptographic verification deferred to v0.4.1",
	}}
}

// ── helpers ─────────────────────────────────────────────────────────────────

// sha256HexRegex matches a well-formed lowercase SHA-256 hex digest.
// Compiled once at package init.
var sha256HexRegex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// canonicaliseIssuer normalises an OIDC issuer URL so case-only and
// trailing-slash differences don't cause spurious untrusted-issuer
// findings.
//
// Rules:
//   - Whitespace trimmed
//   - Scheme and host lowercased
//   - Single trailing slash on the path stripped
//   - If the input fails to parse as a URL we return the lowercased,
//     trimmed input — better to have a stable bucket key than to silently
//     drop entries.
//
// The empty string is returned for empty input.
func canonicaliseIssuer(issuer string) string {
	trimmed := strings.TrimSpace(issuer)
	if trimmed == "" {
		return ""
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Scheme == "" || u.Host == "" {
		// Fall back to a stable lowercased form — never drop the entry
		// silently.
		return strings.ToLower(trimmed)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	// Strip a single trailing slash on the path so "https://x.example/"
	// and "https://x.example" hash to the same bucket.
	if len(u.Path) > 1 && strings.HasSuffix(u.Path, "/") {
		u.Path = strings.TrimRight(u.Path, "/")
	} else if u.Path == "/" {
		u.Path = ""
	}
	return u.String()
}

// hasSigstoreSpecKey returns true when the parsed JSON object contains at
// least one of the Sigstore bundle's spec-defined top-level keys.
func hasSigstoreSpecKey(obj map[string]any) bool {
	if len(obj) == 0 {
		return false
	}
	for _, k := range patterns.SigstoreBundleSpecKeys {
		if _, ok := obj[k]; ok {
			return true
		}
	}
	return false
}

// readBoundedFile reads up to maxBytes+1 from path. Returns the data and
// (nil) on success. On size-cap or read failure returns nil and a Finding
// the caller can append; the second return is a *Finding so a nil pointer
// disambiguates "no problem" from "empty findings".
func readBoundedFile(path string, maxBytes int64) ([]byte, *Finding) {
	f, err := os.Open(path) //nolint:gosec // path comes from filesystem walks scoped to the scan target.
	if err != nil {
		return nil, &Finding{
			Rule:            RuleSignatureMalformedManifest,
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
			Rule:            RuleSignatureMalformedManifest,
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
			Rule:            RuleSignatureMalformedManifest,
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
			Rule:            RuleSignatureMalformedManifest,
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
			Rule:            RuleSignatureMalformedManifest,
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
// the basename — `MODEL_SIGNING.json` is accepted alongside
// `model_signing.json`.
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

// signatureFindings runs full per-artifact verification across a list of
// artifact paths and returns the merged findings. Pulled out as a helper
// so both the standalone VerifyDirectory entry point AND the AIBOM
// composer can share identical aggregation logic — same approach used for
// the missing-card rule in modelcard.go.
//
// Despite the historical name `missingSignatureFindings`, this helper
// performs full verification (hash + issuer + carrier presence) — the
// missing-signature rule is only one of many possible outcomes. The
// composer wraps this helper so the rule set fires on every real
// `oxvault scan ./model-dir` invocation.
func signatureFindings(v SignatureVerifier, artifactPaths []string) []Finding {
	var findings []Finding
	for _, p := range artifactPaths {
		findings = append(findings, v.VerifyArtifact(p)...)
	}
	return findings
}

// ── compile-time interface guard ────────────────────────────────────────────

var _ SignatureVerifier = (*signatureVerifier)(nil)
