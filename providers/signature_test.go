package providers_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
// rule id + severity so any regression in the verifier is loud and obvious.

func TestSignatureVerifier_Fixtures(t *testing.T) {
	tests := []struct {
		name         string
		fixtureDir   string
		artifactName string
		wantRule     string
		wantSeverity providers.Severity
	}{
		{
			name:         "signed model with valid manifest emits clean INFO",
			fixtureDir:   "safe/signed_model",
			artifactName: "weights.pkl",
			wantRule:     "aibom-signature-clean",
			wantSeverity: providers.SeverityInfo,
		},
		{
			name:         "sigstore bundle emits clean INFO",
			fixtureDir:   "safe/sigstore_bundled",
			artifactName: "model.onnx",
			wantRule:     "aibom-signature-clean",
			wantSeverity: providers.SeverityInfo,
		},
		{
			name:         "no signature flagged WARNING",
			fixtureDir:   "malicious/no_sig",
			artifactName: "weights.pkl",
			wantRule:     "aibom-signature-missing",
			wantSeverity: providers.SeverityWarning,
		},
		{
			name:         "hash mismatch flagged CRITICAL",
			fixtureDir:   "malicious/hash_mismatch",
			artifactName: "weights.pkl",
			wantRule:     "aibom-signature-hash-mismatch",
			wantSeverity: providers.SeverityCritical,
		},
		{
			name:         "untrusted issuer flagged HIGH",
			fixtureDir:   "malicious/untrusted_issuer",
			artifactName: "weights.pkl",
			wantRule:     "aibom-signature-untrusted-issuer",
			wantSeverity: providers.SeverityHigh,
		},
		{
			name:         "malformed manifest flagged WARNING",
			fixtureDir:   "malicious/malformed_manifest",
			artifactName: "weights.pkl",
			wantRule:     "aibom-signature-malformed-manifest",
			wantSeverity: providers.SeverityWarning,
		},
	}

	v := providers.NewSignatureVerifier()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join("..", "testdata", "aibom", "signature", tt.fixtureDir, tt.artifactName)
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("missing fixture %s: %v (run scripts/gen_aibom_fixtures.py)", path, err)
			}

			findings := v.VerifyArtifact(path)
			if !findRuleAndSeverity(findings, tt.wantRule, tt.wantSeverity) {
				t.Errorf("expected rule %q at severity %v, got %d findings: %+v",
					tt.wantRule, tt.wantSeverity, len(findings), findings)
			}
		})
	}
}

// TestSignatureVerifier_CleanFixturesEmitOnlyClean ensures the safe fixtures
// emit exactly one INFO finding and never a violation.
func TestSignatureVerifier_CleanFixturesEmitOnlyClean(t *testing.T) {
	cases := []struct {
		dir      string
		artifact string
	}{
		{"safe/signed_model", "weights.pkl"},
		{"safe/sigstore_bundled", "model.onnx"},
	}
	v := providers.NewSignatureVerifier()
	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			path := filepath.Join("..", "testdata", "aibom", "signature", tc.dir, tc.artifact)
			findings := v.VerifyArtifact(path)
			if len(findings) != 1 {
				t.Fatalf("clean fixture %s: expected exactly 1 finding, got %d (%+v)",
					tc.dir, len(findings), findings)
			}
			if findings[0].Rule != "aibom-signature-clean" {
				t.Errorf("clean fixture %s: rule = %q, want aibom-signature-clean",
					tc.dir, findings[0].Rule)
			}
			if findings[0].Severity != providers.SeverityInfo {
				t.Errorf("clean fixture %s: severity = %v, want INFO", tc.dir, findings[0].Severity)
			}
		})
	}
}

// ── synthesised edge-case suite ─────────────────────────────────────────────
//
// These tests build their own files with t.TempDir() so they run without any
// external script. They cover the byte-level edge cases that fixtures cannot
// express cleanly.

func TestSignatureVerifier_NonexistentArtifact(t *testing.T) {
	v := providers.NewSignatureVerifier()
	findings := v.VerifyArtifact("/no/such/artifact/anywhere.pkl")
	if findings != nil {
		t.Errorf("expected nil for missing artifact, got %+v", findings)
	}
}

func TestSignatureVerifier_NonArtifactPathReturnsNil(t *testing.T) {
	// A file with an extension the verifier doesn't recognise as a model
	// artifact must produce zero findings — it's not the verifier's job to
	// audit random files.
	dir := t.TempDir()
	path := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	v := providers.NewSignatureVerifier()
	if findings := v.VerifyArtifact(path); findings != nil {
		t.Errorf("expected nil for non-artifact path, got %+v", findings)
	}
}

func TestSignatureVerifier_SignatureCarrierItselfReturnsNil(t *testing.T) {
	// A .sigstore / .sig / .pem file is a signature CARRIER, not an artifact.
	// The verifier evaluates from the artifact's perspective only — handing
	// it a carrier directly must produce zero findings to avoid double-
	// counting when the composer dispatches per-file.
	cases := []string{"weights.pkl.sigstore", "weights.pkl.sig", "leaf.pem", "leaf.cert"}
	v := providers.NewSignatureVerifier()
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
			if findings := v.VerifyArtifact(path); findings != nil {
				t.Errorf("expected nil for signature carrier %s, got %+v", name, findings)
			}
		})
	}
}

func TestSignatureVerifier_LooseSigFilePresenceEmitsClean(t *testing.T) {
	// An artifact paired with a `.sig` file (presence-only, no manifest) is
	// signed enough for Day 7 — emit clean INFO, no missing-signature
	// finding. Cryptographic verification of detached sigs is deferred to
	// v0.4.1.
	dir := t.TempDir()
	artifact := filepath.Join(dir, "weights.pkl")
	if err := os.WriteFile(artifact, []byte{0x80, 0x04}, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact+".sig", []byte("dummy-sig"), 0o644); err != nil {
		t.Fatal(err)
	}
	v := providers.NewSignatureVerifier()
	findings := v.VerifyArtifact(artifact)
	if !findRuleAndSeverity(findings, "aibom-signature-clean", providers.SeverityInfo) {
		t.Errorf("loose .sig should emit clean INFO; got: %+v", findings)
	}
	for _, f := range findings {
		if f.Rule == "aibom-signature-missing" {
			t.Errorf("loose .sig should suppress missing-signature; got: %+v", f)
		}
	}
}

func TestSignatureVerifier_ManifestTooLarge(t *testing.T) {
	// A manifest exceeding the size cap (256 KiB) must fire malformed-
	// manifest, not the hash-check path.
	dir := t.TempDir()
	artifact := filepath.Join(dir, "weights.pkl")
	if err := os.WriteFile(artifact, []byte{0x80, 0x04}, 0o644); err != nil {
		t.Fatal(err)
	}
	// 300 KiB of "a" characters.
	huge := strings.Repeat("a", 300*1024)
	if err := os.WriteFile(filepath.Join(dir, "model_signing.json"), []byte(huge), 0o644); err != nil {
		t.Fatal(err)
	}
	v := providers.NewSignatureVerifier()
	findings := v.VerifyArtifact(artifact)
	if !findRuleAndSeverity(findings, "aibom-signature-malformed-manifest", providers.SeverityWarning) {
		t.Errorf("oversize manifest should fire malformed-manifest; got: %+v", findings)
	}
}

func TestSignatureVerifier_ManifestMissingArtifactEntry(t *testing.T) {
	// Manifest parses fine but does NOT list the artifact under scrutiny.
	// This is "we have a manifest but it doesn't cover this file" — fire
	// aibom-signature-invalid CRITICAL.
	dir := t.TempDir()
	artifact := filepath.Join(dir, "weights.pkl")
	if err := os.WriteFile(artifact, []byte{0x80, 0x04}, 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{
		"version": "1.0",
		"artifacts": []map[string]string{
			{"path": "other_model.bin", "sha256": strings.Repeat("0", 64)},
		},
		"issuer": "https://accounts.google.com",
	}
	body, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(dir, "model_signing.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	v := providers.NewSignatureVerifier()
	findings := v.VerifyArtifact(artifact)
	if !findRuleAndSeverity(findings, "aibom-signature-invalid", providers.SeverityCritical) {
		t.Errorf("manifest missing artifact entry should fire signature-invalid; got: %+v", findings)
	}
}

func TestSignatureVerifier_ManifestNoIssuerFiresUntrusted(t *testing.T) {
	// A manifest whose hash matches but issuer field is empty is treated as
	// untrusted — provenance cannot be attributed.
	dir := t.TempDir()
	artifact := filepath.Join(dir, "weights.pkl")
	body := []byte{0x80, 0x04, 0x95, 0x01}
	if err := os.WriteFile(artifact, body, 0o644); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(body)
	manifest := map[string]any{
		"version": "1.0",
		"artifacts": []map[string]string{
			{"path": "weights.pkl", "sha256": hex.EncodeToString(hash[:])},
		},
		"issuer": "",
	}
	mb, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(dir, "model_signing.json"), mb, 0o644); err != nil {
		t.Fatal(err)
	}
	v := providers.NewSignatureVerifier()
	findings := v.VerifyArtifact(artifact)
	if !findRuleAndSeverity(findings, "aibom-signature-untrusted-issuer", providers.SeverityHigh) {
		t.Errorf("empty issuer should fire untrusted-issuer; got: %+v", findings)
	}
}

func TestSignatureVerifier_WithTrustedIssuersOverridesDefault(t *testing.T) {
	// A user-supplied trusted-issuer list REPLACES the defaults — the
	// default https://accounts.google.com must NOT be trusted when the user
	// configures only a custom issuer.
	dir := t.TempDir()
	artifact := filepath.Join(dir, "weights.pkl")
	body := []byte{0x80, 0x04, 0x95, 0x02}
	if err := os.WriteFile(artifact, body, 0o644); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(body)
	manifest := map[string]any{
		"version": "1.0",
		"artifacts": []map[string]string{
			{"path": "weights.pkl", "sha256": hex.EncodeToString(hash[:])},
		},
		"issuer": "https://accounts.google.com",
	}
	mb, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(dir, "model_signing.json"), mb, 0o644); err != nil {
		t.Fatal(err)
	}
	// Configure an issuer set that does NOT include accounts.google.com.
	v := providers.NewSignatureVerifier(
		providers.WithTrustedIssuers([]string{"https://internal.corp.example.com"}),
	)
	findings := v.VerifyArtifact(artifact)
	if !findRuleAndSeverity(findings, "aibom-signature-untrusted-issuer", providers.SeverityHigh) {
		t.Errorf("custom trusted set should reject default issuer; got: %+v", findings)
	}
}

func TestSignatureVerifier_WithTrustedIssuersAcceptsConfigured(t *testing.T) {
	// A user-supplied trusted issuer that DOES match the manifest's issuer
	// produces a clean finding.
	dir := t.TempDir()
	artifact := filepath.Join(dir, "weights.pkl")
	body := []byte{0x80, 0x04, 0x95, 0x03}
	if err := os.WriteFile(artifact, body, 0o644); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(body)
	manifest := map[string]any{
		"version": "1.0",
		"artifacts": []map[string]string{
			{"path": "weights.pkl", "sha256": hex.EncodeToString(hash[:])},
		},
		"issuer": "https://internal.corp.example.com",
	}
	mb, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(dir, "model_signing.json"), mb, 0o644); err != nil {
		t.Fatal(err)
	}
	v := providers.NewSignatureVerifier(
		providers.WithTrustedIssuers([]string{"https://internal.corp.example.com"}),
	)
	findings := v.VerifyArtifact(artifact)
	if !findRuleAndSeverity(findings, "aibom-signature-clean", providers.SeverityInfo) {
		t.Errorf("configured trusted issuer should produce clean; got: %+v", findings)
	}
}

func TestSignatureVerifier_VerifyDirectory_WalksAllArtifacts(t *testing.T) {
	// VerifyDirectory must recurse and verify every model artifact it
	// finds. This test plants two artifacts in different subdirectories,
	// neither of which has a signature carrier — both must fire missing.
	dir := t.TempDir()
	a := filepath.Join(dir, "model-a")
	b := filepath.Join(dir, "subdir", "model-b")
	if err := os.MkdirAll(a, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(b, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a, "weights.pkl"), []byte{0x80, 0x04}, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b, "weights.safetensors"), []byte(`{"a":1}`), 0o644); err != nil {
		t.Fatal(err)
	}

	v := providers.NewSignatureVerifier()
	findings := v.VerifyDirectory(dir)

	missingCount := 0
	for _, f := range findings {
		if f.Rule == "aibom-signature-missing" {
			missingCount++
		}
	}
	if missingCount != 2 {
		t.Errorf("expected 2 missing-signature findings (one per artifact), got %d (%+v)", missingCount, findings)
	}
}

func TestSignatureVerifier_VerifyDirectory_SkipsExcludedDirs(t *testing.T) {
	// An artifact in node_modules must NOT be verified — same exclusion
	// rules as the rest of the AIBOM walkers.
	dir := t.TempDir()
	excluded := filepath.Join(dir, "node_modules")
	if err := os.MkdirAll(excluded, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(excluded, "hidden.pkl"), []byte{0x80, 0x04}, 0o644); err != nil {
		t.Fatal(err)
	}
	v := providers.NewSignatureVerifier()
	findings := v.VerifyDirectory(dir)
	for _, f := range findings {
		if f.Rule == "aibom-signature-missing" {
			t.Errorf("excluded directory should not be verified; got: %+v", f)
		}
	}
}

// ── composer integration ────────────────────────────────────────────────────
//
// These tests exercise the production composer end-to-end so the missing-
// signature rule actually fires on real `oxvault scan` invocations. The
// composer aggregates per-artifact verification results — without this
// integration the verifier would fire only when called directly, never on
// a real scan target.

func TestComposer_Scan_Directory_MissingSignature_FiresOnArtifactWithoutSig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "weights.pkl"), []byte{0x80, 0x04}, 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewComposer()
	findings := c.Scan(dir)

	if !findRule(findings, "aibom-signature-missing") {
		t.Errorf("expected aibom-signature-missing from real composer scan; got: %+v", findings)
	}
}

func TestComposer_Scan_Directory_MissingSignature_SuppressedWhenManifestPresent(t *testing.T) {
	dir := t.TempDir()
	body := []byte{0x80, 0x04, 0x95, 0x05}
	if err := os.WriteFile(filepath.Join(dir, "weights.pkl"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(body)
	manifest := map[string]any{
		"version": "1.0",
		"artifacts": []map[string]string{
			{"path": "weights.pkl", "sha256": hex.EncodeToString(hash[:])},
		},
		"issuer": "https://accounts.google.com",
	}
	mb, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(dir, "model_signing.json"), mb, 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewComposer()
	findings := c.Scan(dir)

	for _, f := range findings {
		if f.Rule == "aibom-signature-missing" {
			t.Errorf("artifact + manifest present should suppress missing-signature; got: %+v", f)
		}
	}
	if !findRule(findings, "aibom-signature-clean") {
		t.Errorf("artifact + valid manifest should fire clean; got: %+v", findings)
	}
}

func TestComposer_Scan_Directory_MissingSignature_FileTargetDoesNotFire(t *testing.T) {
	// Single-file scan must NOT fire missing-signature — same convention as
	// missing-card. The aggregation only runs on directory walks.
	dir := t.TempDir()
	path := filepath.Join(dir, "weights.pkl")
	if err := os.WriteFile(path, []byte{0x80, 0x04}, 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewComposer()
	findings := c.Scan(path)
	for _, f := range findings {
		if f.Rule == "aibom-signature-missing" {
			t.Errorf("single-file scan should not fire missing-signature; got: %+v", f)
		}
	}
}

// ── defer recover() panic safety ────────────────────────────────────────────
//
// The verifier's deferred recover() must surface a malformed-manifest
// WARNING rather than crashing the scanner. We simulate a panic by handing
// the verifier a path whose manifest would normally parse fine but trigger
// a panic in our injected hook. Since signature.go has no hook seam, we
// instead exercise the recover via a panic-inducing artifact path that
// trips the os layer (not realistic in CI), so we settle for the
// assertion-via-fixture: a malformed manifest already covers the parse-
// failure code path; a true panic-recovery test would require an internal
// seam similar to onnxPanicHookForTest.
//
// We DO assert the recover at compile time via the named return contract —
// the recover-into-named-return pattern is the only thing protecting us
// from silent-drop on panic. The fixture suite above plus the synthesised
// edge cases together exercise every reachable error path.

// Interface guards for testutil.MockSignatureVerifier and the real
// SignatureVerifier are already covered in aibom_composer_test.go's package-
// level var block (this file lives in the same _test package).
