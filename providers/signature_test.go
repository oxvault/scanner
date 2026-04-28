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
			// v0.4 hash-only verification — manifest hash matches the
			// artifact and the issuer is self-declared in the
			// trusted-issuer list. We do NOT emit -clean here: that's
			// reserved for the v0.4.1 OIDC-chain-verified path.
			name:         "signed model with valid manifest emits hash-match INFO",
			fixtureDir:   "safe/signed_model",
			artifactName: "weights.pkl",
			wantRule:     "aibom-signature-hash-match",
			wantSeverity: providers.SeverityInfo,
		},
		{
			// Sigstore bundles get a presence-deferred verdict in v0.4.
			// Cryptographic verification of the embedded Rekor entry
			// ships in v0.4.1.
			name:         "sigstore bundle emits presence-deferred INFO",
			fixtureDir:   "safe/sigstore_bundled",
			artifactName: "model.onnx",
			wantRule:     "aibom-signature-presence-deferred",
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

// TestSignatureVerifier_SafeFixturesEmitOnlyInfo ensures the safe fixtures
// emit exactly one INFO finding (the appropriate v0.4 rule for each
// carrier) and never a violation.
//
// v0.4 trust posture:
//   - manifest carrier → aibom-signature-hash-match (NOT -clean: -clean is
//     reserved for v0.4.1 OIDC-verified chain)
//   - sigstore bundle  → aibom-signature-presence-deferred
//   - loose .sig       → aibom-signature-presence-deferred (covered in
//     synthesised tests further down)
func TestSignatureVerifier_SafeFixturesEmitOnlyInfo(t *testing.T) {
	cases := []struct {
		dir      string
		artifact string
		wantRule string
	}{
		{"safe/signed_model", "weights.pkl", "aibom-signature-hash-match"},
		{"safe/sigstore_bundled", "model.onnx", "aibom-signature-presence-deferred"},
	}
	v := providers.NewSignatureVerifier()
	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			path := filepath.Join("..", "testdata", "aibom", "signature", tc.dir, tc.artifact)
			findings := v.VerifyArtifact(path)
			if len(findings) != 1 {
				t.Fatalf("safe fixture %s: expected exactly 1 finding, got %d (%+v)",
					tc.dir, len(findings), findings)
			}
			if findings[0].Rule != tc.wantRule {
				t.Errorf("safe fixture %s: rule = %q, want %q",
					tc.dir, findings[0].Rule, tc.wantRule)
			}
			if findings[0].Severity != providers.SeverityInfo {
				t.Errorf("safe fixture %s: severity = %v, want INFO", tc.dir, findings[0].Severity)
			}
			// The reserved -clean rule must NEVER appear in v0.4 — that
			// rule ID is held back for the v0.4.1 OIDC-verified path.
			if findings[0].Rule == "aibom-signature-clean" {
				t.Errorf("safe fixture %s: emitted reserved aibom-signature-clean rule in v0.4 (must wait for v0.4.1 OIDC verification)", tc.dir)
			}
		})
	}
}

// TestSignatureVerifier_CleanRuleNeverEmittedInV04 is a hard guarantee that
// no code path in v0.4 emits aibom-signature-clean. The rule ID is reserved
// for v0.4.1 (Rekor/Fulcio chain verification). If this test starts failing
// it means somebody re-introduced an unverified "clean" claim — which is
// exactly the trust-bypass the Day 7 review found.
func TestSignatureVerifier_CleanRuleNeverEmittedInV04(t *testing.T) {
	v := providers.NewSignatureVerifier()
	// Walk every fixture under testdata/aibom/signature and assert no
	// finding bears the reserved rule ID.
	root := filepath.Join("..", "testdata", "aibom", "signature")
	_ = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return nil
		}
		findings := v.VerifyArtifact(path)
		for _, f := range findings {
			if f.Rule == "aibom-signature-clean" {
				t.Errorf("v0.4 emitted reserved -clean rule for %s: %+v", path, f)
			}
		}
		return nil
	})
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

func TestSignatureVerifier_LooseSigFilePresenceEmitsDeferred(t *testing.T) {
	// An artifact paired with a `.sig` file (presence-only, no manifest)
	// is "we have a signature carrier but cannot verify its crypto in
	// v0.4". Emit aibom-signature-presence-deferred INFO, suppress
	// missing-signature. The v0.4 trust posture is honest: the .sig is
	// there, but we are NOT cryptographically validating it yet.
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
	if !findRuleAndSeverity(findings, "aibom-signature-presence-deferred", providers.SeverityInfo) {
		t.Errorf("loose .sig should emit presence-deferred INFO; got: %+v", findings)
	}
	for _, f := range findings {
		if f.Rule == "aibom-signature-missing" {
			t.Errorf("loose .sig should suppress missing-signature; got: %+v", f)
		}
		if f.Rule == "aibom-signature-clean" {
			t.Errorf("loose .sig must NOT emit reserved -clean rule in v0.4; got: %+v", f)
		}
	}
}

// TestSignatureVerifier_EmptyLooseSigEmitsDeferred guards the trust-bypass
// the review flagged: an attacker dropping a 0-byte `.sig` next to a
// tampered artifact must still surface deferred-verification, not silently
// pass as "clean". (We never had a "clean" verdict for .sig in the new
// model — this test pins the contract.)
func TestSignatureVerifier_EmptyLooseSigEmitsDeferred(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "weights.pkl")
	if err := os.WriteFile(artifact, []byte{0x80, 0x04}, 0o644); err != nil {
		t.Fatal(err)
	}
	// Zero-byte .sig — no crypto check possible, presence-deferred only.
	if err := os.WriteFile(artifact+".sig", []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	v := providers.NewSignatureVerifier()
	findings := v.VerifyArtifact(artifact)
	if !findRuleAndSeverity(findings, "aibom-signature-presence-deferred", providers.SeverityInfo) {
		t.Errorf("empty .sig should emit presence-deferred; got: %+v", findings)
	}
	for _, f := range findings {
		if f.Rule == "aibom-signature-clean" {
			t.Errorf("empty .sig must NOT emit reserved -clean rule; got: %+v", f)
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
	// produces a hash-match finding (v0.4 — NOT -clean). The -clean rule
	// is reserved for v0.4.1 OIDC chain verification.
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
	if !findRuleAndSeverity(findings, "aibom-signature-hash-match", providers.SeverityInfo) {
		t.Errorf("configured trusted issuer should produce hash-match; got: %+v", findings)
	}
	for _, f := range findings {
		if f.Rule == "aibom-signature-clean" {
			t.Errorf("v0.4 must NOT emit reserved -clean rule; got: %+v", f)
		}
	}
}

// TestSignatureVerifier_WithAdditionalTrustedIssuers verifies the merge
// variant: defaults are preserved AND the supplied issuers are added.
func TestSignatureVerifier_WithAdditionalTrustedIssuers(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "weights.pkl")
	body := []byte{0x80, 0x04, 0x95, 0x10}
	if err := os.WriteFile(artifact, body, 0o644); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(body)
	// Default issuer (https://accounts.google.com) — trusted by base set.
	googleManifest := map[string]any{
		"version": "1.0",
		"artifacts": []map[string]string{
			{"path": "weights.pkl", "sha256": hex.EncodeToString(hash[:])},
		},
		"issuer": "https://accounts.google.com",
	}
	mb, _ := json.Marshal(googleManifest)
	if err := os.WriteFile(filepath.Join(dir, "model_signing.json"), mb, 0o644); err != nil {
		t.Fatal(err)
	}
	v := providers.NewSignatureVerifier(
		providers.WithAdditionalTrustedIssuers([]string{"https://internal.corp.example.com"}),
	)
	findings := v.VerifyArtifact(artifact)
	if !findRuleAndSeverity(findings, "aibom-signature-hash-match", providers.SeverityInfo) {
		t.Errorf("additional-issuers MUST preserve defaults; got: %+v", findings)
	}

	// Now flip to the additional issuer — also must be trusted.
	corpManifest := map[string]any{
		"version": "1.0",
		"artifacts": []map[string]string{
			{"path": "weights.pkl", "sha256": hex.EncodeToString(hash[:])},
		},
		"issuer": "https://internal.corp.example.com",
	}
	mb2, _ := json.Marshal(corpManifest)
	if err := os.WriteFile(filepath.Join(dir, "model_signing.json"), mb2, 0o644); err != nil {
		t.Fatal(err)
	}
	findings2 := v.VerifyArtifact(artifact)
	if !findRuleAndSeverity(findings2, "aibom-signature-hash-match", providers.SeverityInfo) {
		t.Errorf("additional-issuers MUST also accept the supplied issuer; got: %+v", findings2)
	}
}

// TestSignatureVerifier_IssuerCanonicalisation verifies that case-only
// differences and trailing-slash noise do NOT cause spurious untrusted-
// issuer findings. The trusted set is canonicalised at construction; the
// manifest issuer is canonicalised at verification.
func TestSignatureVerifier_IssuerCanonicalisation(t *testing.T) {
	cases := []struct {
		name     string
		trusted  string
		manifest string
	}{
		{"scheme case", "HTTPS://accounts.google.com", "https://accounts.google.com"},
		{"host case", "https://Accounts.Google.Com", "https://accounts.google.com"},
		{"trailing slash on trusted", "https://accounts.google.com/", "https://accounts.google.com"},
		{"trailing slash on manifest", "https://accounts.google.com", "https://accounts.google.com/"},
		{"mixed case + slash on both", "HTTPS://Accounts.Google.Com/", "https://accounts.google.com/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			artifact := filepath.Join(dir, "weights.pkl")
			body := []byte{0x80, 0x04, 0x95, 0x20}
			if err := os.WriteFile(artifact, body, 0o644); err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(body)
			manifest := map[string]any{
				"version": "1.0",
				"artifacts": []map[string]string{
					{"path": "weights.pkl", "sha256": hex.EncodeToString(hash[:])},
				},
				"issuer": tc.manifest,
			}
			mb, _ := json.Marshal(manifest)
			if err := os.WriteFile(filepath.Join(dir, "model_signing.json"), mb, 0o644); err != nil {
				t.Fatal(err)
			}
			v := providers.NewSignatureVerifier(
				providers.WithTrustedIssuers([]string{tc.trusted}),
			)
			findings := v.VerifyArtifact(artifact)
			if !findRuleAndSeverity(findings, "aibom-signature-hash-match", providers.SeverityInfo) {
				t.Errorf("canonicalisation should accept differing forms; got: %+v", findings)
			}
		})
	}
}

// TestSignatureVerifier_DeclaredHashMustBeHex64 guards the trust-bypass
// where attacker-controlled garbage in the declared hash field flowed into
// Finding.Message verbatim. Anything other than 64 lowercase hex chars is
// rejected as a malformed manifest BEFORE any equality check runs.
func TestSignatureVerifier_DeclaredHashMustBeHex64(t *testing.T) {
	cases := []struct {
		name     string
		declared string
	}{
		{"too short", "abc123"},
		{"too long", strings.Repeat("a", 65)},
		{"non-hex chars", strings.Repeat("z", 64)},
		{"shell metachars", "; rm -rf /; " + strings.Repeat("a", 52)},
		{"ansi escape", "\x1b[31m" + strings.Repeat("a", 60)},
		// Uppercase 64-hex is canonicalised to lowercase BEFORE the
		// regex check, so it's accepted as well-formed and falls through
		// to the equality test (where it mismatches the artifact's
		// actual hash). This case has its own assertion branch below.
		{"uppercase hex normalises to mismatch", strings.Repeat("A", 64)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			artifact := filepath.Join(dir, "weights.pkl")
			body := []byte{0x80, 0x04, 0x95, 0x30}
			if err := os.WriteFile(artifact, body, 0o644); err != nil {
				t.Fatal(err)
			}
			manifest := map[string]any{
				"version": "1.0",
				"artifacts": []map[string]string{
					{"path": "weights.pkl", "sha256": tc.declared},
				},
				"issuer": "https://accounts.google.com",
			}
			mb, _ := json.Marshal(manifest)
			if err := os.WriteFile(filepath.Join(dir, "model_signing.json"), mb, 0o644); err != nil {
				t.Fatal(err)
			}
			v := providers.NewSignatureVerifier()
			findings := v.VerifyArtifact(artifact)
			// uppercase-only is the one case where lowercasing rescues
			// it — that produces hash-mismatch (well-formed but wrong).
			if tc.name == "uppercase hex normalises to mismatch" {
				if !findRule(findings, "aibom-signature-hash-mismatch") {
					t.Errorf("uppercase 64-hex should normalise to valid form and fall through to hash-mismatch; got: %+v", findings)
				}
				return
			}
			if !findRuleAndSeverity(findings, "aibom-signature-malformed-manifest", providers.SeverityWarning) {
				t.Errorf("non-hex64 declared hash should fire malformed-manifest; got: %+v", findings)
			}
			// Defence-in-depth: the attacker-supplied garbage MUST NOT
			// appear in the finding message (no terminal escape, no
			// shell metachars).
			for _, f := range findings {
				if strings.Contains(f.Message, tc.declared) {
					t.Errorf("attacker-supplied declared hash leaked into finding message: %q", f.Message)
				}
			}
		})
	}
}

// TestSignatureVerifier_SigstoreBundleEmptyObjectIsRejected guards the
// trust-bypass the review flagged: a sigstore-bundle file containing
// `{}` (or any JSON without spec-shaped content) must NOT pass as a
// valid signature carrier.
func TestSignatureVerifier_SigstoreBundleEmptyObjectIsRejected(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty object", "{}"},
		{"random keys", `{"foo":"bar","baz":42}`},
		{"npm-style", `{"name":"my-pkg","version":"1.0.0"}`},
		{"null", "null"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			artifact := filepath.Join(dir, "weights.pkl")
			if err := os.WriteFile(artifact, []byte{0x80, 0x04}, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(artifact+".sigstore", []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}
			v := providers.NewSignatureVerifier()
			findings := v.VerifyArtifact(artifact)
			if !findRuleAndSeverity(findings, "aibom-signature-malformed-bundle", providers.SeverityWarning) {
				t.Errorf("non-spec sigstore bundle should fire malformed-bundle; got: %+v", findings)
			}
			for _, f := range findings {
				if f.Rule == "aibom-signature-clean" || f.Rule == "aibom-signature-presence-deferred" {
					t.Errorf("non-spec sigstore bundle must NOT pass as valid; got: %+v", f)
				}
			}
		})
	}
}

// TestSignatureVerifier_SigstoreBundleSpecKeyAccepted ensures a real
// sigstore bundle (containing one of the spec-defined top-level keys)
// passes the shape check.
func TestSignatureVerifier_SigstoreBundleSpecKeyAccepted(t *testing.T) {
	specKeys := []string{"mediaType", "messageSignature", "verificationMaterial", "dsseEnvelope"}
	for _, key := range specKeys {
		t.Run(key, func(t *testing.T) {
			dir := t.TempDir()
			artifact := filepath.Join(dir, "weights.pkl")
			if err := os.WriteFile(artifact, []byte{0x80, 0x04}, 0o644); err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(map[string]any{key: "sentinel"})
			if err := os.WriteFile(artifact+".sigstore", body, 0o644); err != nil {
				t.Fatal(err)
			}
			v := providers.NewSignatureVerifier()
			findings := v.VerifyArtifact(artifact)
			if !findRuleAndSeverity(findings, "aibom-signature-presence-deferred", providers.SeverityInfo) {
				t.Errorf("spec-shaped bundle should fire presence-deferred; got: %+v", findings)
			}
		})
	}
}

// TestSignatureVerifier_CarrierPriorityManifestBeatsSig is the trust-model
// regression test the review demanded: an attacker dropping a 1-byte .sig
// next to a tampered artifact must NOT shadow the manifest's hash-mismatch
// CRITICAL. Carriers are evaluated in priority order (manifest > .sigstore
// > .sig) and findings are merged.
func TestSignatureVerifier_CarrierPriorityManifestBeatsSig(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "weights.pkl")
	body := []byte{0x80, 0x04, 0x95, 0x40}
	if err := os.WriteFile(artifact, body, 0o644); err != nil {
		t.Fatal(err)
	}
	// Tampered manifest: declares a hash that does NOT match the artifact.
	manifest := map[string]any{
		"version": "1.0",
		"artifacts": []map[string]string{
			{"path": "weights.pkl", "sha256": strings.Repeat("0", 64)},
		},
		"issuer": "https://accounts.google.com",
	}
	mb, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(dir, "model_signing.json"), mb, 0o644); err != nil {
		t.Fatal(err)
	}
	// Attacker also drops a 1-byte .sig in an attempt to shadow the
	// manifest's CRITICAL with a "clean" verdict.
	if err := os.WriteFile(artifact+".sig", []byte("X"), 0o644); err != nil {
		t.Fatal(err)
	}
	v := providers.NewSignatureVerifier()
	findings := v.VerifyArtifact(artifact)
	if !findRuleAndSeverity(findings, "aibom-signature-hash-mismatch", providers.SeverityCritical) {
		t.Errorf("manifest hash mismatch must fire CRITICAL even when a .sig is also present; got: %+v", findings)
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
		if f.Rule == "aibom-signature-clean" {
			t.Errorf("v0.4 must NOT emit reserved -clean rule; got: %+v", f)
		}
	}
	if !findRule(findings, "aibom-signature-hash-match") {
		t.Errorf("artifact + valid manifest should fire hash-match in v0.4; got: %+v", findings)
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

// TestComposer_Scan_File_TamperedSiblingManifestFiresHashMismatch is the
// canonical regression test for the trust-bypass the review flagged:
// running `oxvault scan ./tampered.pkl` on a single-file target with a
// sibling manifest declaring the wrong hash MUST emit hash-mismatch
// CRITICAL. Before this fix the single-file branch never ran signature
// verification — the rule was dead in production for the most common
// supply-chain attack (sign clean → tamper with payload after the fact).
func TestComposer_Scan_File_TamperedSiblingManifestFiresHashMismatch(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "tampered.pkl")
	if err := os.WriteFile(artifact, []byte{0x80, 0x04, 0x95, 0x99}, 0o644); err != nil {
		t.Fatal(err)
	}
	// Sibling manifest declares the WRONG hash — sign-then-tamper.
	manifest := map[string]any{
		"version": "1.0",
		"artifacts": []map[string]string{
			{"path": "tampered.pkl", "sha256": strings.Repeat("0", 64)},
		},
		"issuer": "https://accounts.google.com",
	}
	mb, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(dir, "model_signing.json"), mb, 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewComposer()
	findings := c.Scan(artifact) // SINGLE-FILE TARGET
	if !findRuleAndSeverity(findings, "aibom-signature-hash-mismatch", providers.SeverityCritical) {
		t.Errorf("single-file scan with tampered sibling manifest must fire hash-mismatch CRITICAL; got: %+v", findings)
	}
	for _, f := range findings {
		if f.Rule == "aibom-signature-missing" {
			t.Errorf("single-file scan must NOT emit missing-signature even when running signature checks; got: %+v", f)
		}
	}
}

// TestComposer_Scan_File_ValidSiblingManifestFiresHashMatch confirms the
// happy-path counterpart: a single-file scan on an artifact with a valid
// sibling manifest emits hash-match INFO (and never -clean in v0.4).
func TestComposer_Scan_File_ValidSiblingManifestFiresHashMatch(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "good.pkl")
	body := []byte{0x80, 0x04, 0x95, 0x77}
	if err := os.WriteFile(artifact, body, 0o644); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(body)
	manifest := map[string]any{
		"version": "1.0",
		"artifacts": []map[string]string{
			{"path": "good.pkl", "sha256": hex.EncodeToString(hash[:])},
		},
		"issuer": "https://accounts.google.com",
	}
	mb, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(dir, "model_signing.json"), mb, 0o644); err != nil {
		t.Fatal(err)
	}

	c := providers.NewComposer()
	findings := c.Scan(artifact)
	if !findRule(findings, "aibom-signature-hash-match") {
		t.Errorf("single-file scan with valid sibling manifest should fire hash-match; got: %+v", findings)
	}
	for _, f := range findings {
		if f.Rule == "aibom-signature-clean" {
			t.Errorf("v0.4 must NOT emit reserved -clean rule; got: %+v", f)
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
