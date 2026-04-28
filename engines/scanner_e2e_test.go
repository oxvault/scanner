package engines_test

// End-to-end tests that invoke the built oxvault binary via os/exec.
// Verifies the full CLI surface — resolver -> engine -> composer -> reporter
// — for both MCP (v0.3) and AIBOM (v0.4) paths.
//
// Run with `go test ./engines/ -run TestE2E`. Tests skip if `bin/oxvault`
// is not built; CI runs `make build` before tests.

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot returns the absolute path to the scanner repo root.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	// Tests run from engines/, repo root is one level up.
	return filepath.Dir(wd)
}

// oxvaultBinary returns the path to the built binary, or skips the test
// when it is not present.
func oxvaultBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(repoRoot(t), "bin", "oxvault")
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("bin/oxvault not built; run `make build` (skip: %v)", err)
	}
	return bin
}

// runScan invokes `oxvault scan <args...>` and returns combined stdout/stderr.
// Exit code is captured but not asserted — callers verify via output text.
func runScan(t *testing.T, args ...string) (string, int) {
	t.Helper()
	bin := oxvaultBinary(t)
	cmd := exec.Command(bin, append([]string{"scan"}, args...)...)
	cmd.Dir = repoRoot(t)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	exit := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			t.Fatalf("exec failed: %v\nout: %s", err, buf.String())
		}
	}
	return buf.String(), exit
}

// ── MCP regression — verifies v0.3 paths still work after AIBOM additions ──

func TestE2E_MCP_ToolPoisoning(t *testing.T) {
	out, _ := runScan(t, "./examples/vulnerable-servers/tool-poisoning/", "--skip-manifest")
	// Expected MCP rules from `make scan-demo` baseline.
	for _, want := range []string{"mcp-cmd-injection", "mcp-hardcoded-secret", "CRITICAL"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got:\n%s", want, out)
		}
	}
}

func TestE2E_MCP_CmdInjection(t *testing.T) {
	out, _ := runScan(t, "./examples/vulnerable-servers/cmd-injection/", "--skip-manifest")
	if !strings.Contains(out, "mcp-hardcoded-secret") && !strings.Contains(out, "mcp-cmd-injection") {
		t.Errorf("expected MCP rule in output, got:\n%s", out)
	}
}

func TestE2E_MCP_CVEs(t *testing.T) {
	out, _ := runScan(t, "./testdata/cve/", "--skip-manifest")
	// Sanity check: at least one CRITICAL fires from the CVE corpus.
	if !strings.Contains(out, "CRITICAL") {
		t.Errorf("expected at least one CRITICAL from CVE corpus, got:\n%s", out)
	}
}

func TestE2E_MCP_SkipSAST(t *testing.T) {
	out, _ := runScan(t, "./examples/vulnerable-servers/cmd-injection/", "--skip-sast", "--skip-manifest")
	// With SAST skipped, the source-code-derived findings should be absent.
	// We do NOT assert zero findings (other engines may still flag) — we
	// assert the SAST rule prefix doesn't dominate.
	sastHits := strings.Count(out, "mcp-cmd-injection")
	if sastHits > 0 {
		t.Errorf("expected no mcp-cmd-injection findings with --skip-sast, got %d:\n%s", sastHits, out)
	}
}

// ── AIBOM happy paths — single artifact per format ─────────────────────────

func TestE2E_AIBOM_PickleRCE(t *testing.T) {
	out, _ := runScan(t, "./testdata/aibom/pickle/malicious/os_system.pkl")
	for _, want := range []string{"aibom-pickle-os-system", "CRITICAL", "CWE-502"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q, got:\n%s", want, out)
		}
	}
}

func TestE2E_AIBOM_SafetensorsOverflow(t *testing.T) {
	out, _ := runScan(t, "./testdata/aibom/safetensors/malicious/header_overflow.safetensors")
	for _, want := range []string{"aibom-safetensors-header-overflow", "CRITICAL"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q, got:\n%s", want, out)
		}
	}
}

func TestE2E_AIBOM_ONNXMalformed(t *testing.T) {
	out, _ := runScan(t, "./testdata/aibom/onnx/malicious/garbage.onnx")
	if !strings.Contains(out, "aibom-onnx-malformed-protobuf") {
		t.Errorf("expected aibom-onnx-malformed-protobuf, got:\n%s", out)
	}
}

func TestE2E_AIBOM_ModelCardPoisoning(t *testing.T) {
	// Model cards are surfaced via directory walk when at least one model
	// artifact lives alongside them — a bare directory of cards is not a
	// "model directory" by the resolver's definition. Build a temp dir
	// pairing a real pickle artifact with the poisoned card fixture.
	root := repoRoot(t)
	pkl, err := os.ReadFile(filepath.Join(root, "testdata/aibom/pickle/safe/torch_state_dict.pkl"))
	if err != nil {
		t.Fatalf("read pickle fixture: %v", err)
	}
	card, err := os.ReadFile(filepath.Join(root, "testdata/aibom/modelcard/malicious/poisoned_card.md"))
	if err != nil {
		t.Fatalf("read modelcard fixture: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "weights.pkl"), pkl, 0o644); err != nil {
		t.Fatalf("write pkl: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), card, 0o644); err != nil {
		t.Fatalf("write card: %v", err)
	}
	out, _ := runScan(t, dir)
	if !strings.Contains(out, "aibom-modelcard-suspicious-instructions") {
		t.Errorf("expected aibom-modelcard-suspicious-instructions, got:\n%s", out)
	}
}

func TestE2E_AIBOM_SignatureHashMismatch(t *testing.T) {
	out, _ := runScan(t, "./testdata/aibom/signature/malicious/hash_mismatch/")
	if !strings.Contains(out, "aibom-signature-hash-mismatch") {
		t.Errorf("expected aibom-signature-hash-mismatch, got:\n%s", out)
	}
}

func TestE2E_AIBOM_DirectoryWalk(t *testing.T) {
	out, _ := runScan(t, "./testdata/aibom/pickle/malicious/")
	// Directory walk should flag multiple malicious pickles.
	for _, want := range []string{"aibom-pickle-os-system", "aibom-pickle-subprocess"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in directory walk, got:\n%s", want, out)
		}
	}
}

// ── Skip flags ─────────────────────────────────────────────────────────────

func TestE2E_AIBOM_SkipPickle(t *testing.T) {
	out, _ := runScan(t, "./testdata/aibom/pickle/malicious/", "--skip-pickle")
	if strings.Contains(out, "aibom-pickle-os-system") {
		t.Errorf("expected pickle findings filtered by --skip-pickle, got:\n%s", out)
	}
}

func TestE2E_AIBOM_SkipSignature(t *testing.T) {
	out, _ := runScan(t, "./testdata/aibom/signature/malicious/hash_mismatch/", "--skip-signature")
	if strings.Contains(out, "aibom-signature-hash-mismatch") {
		t.Errorf("expected signature findings filtered by --skip-signature, got:\n%s", out)
	}
}

// ── Output formats ─────────────────────────────────────────────────────────

func TestE2E_AIBOM_JSONFormat(t *testing.T) {
	out, _ := runScan(t, "./testdata/aibom/pickle/malicious/os_system.pkl", "--format=json")
	// Must be valid JSON.
	var report any
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		// Try to find the JSON portion if there is preamble.
		idx := strings.Index(out, "{")
		if idx < 0 {
			t.Fatalf("--format=json produced no JSON object:\n%s", out)
		}
		if err := json.Unmarshal([]byte(out[idx:]), &report); err != nil {
			t.Fatalf("--format=json output is not valid JSON: %v\n%s", err, out)
		}
	}
}

func TestE2E_AIBOM_SARIFFormat(t *testing.T) {
	out, _ := runScan(t, "./testdata/aibom/pickle/malicious/os_system.pkl", "--format=sarif")
	if !strings.Contains(out, "\"version\"") || !strings.Contains(out, "sarif") {
		t.Errorf("--format=sarif should produce SARIF JSON with version + sarif schema, got:\n%s", out)
	}
}

// ── No-crash regression on empty / nonexistent targets ─────────────────────

func TestE2E_NonexistentTarget(t *testing.T) {
	bin := oxvaultBinary(t)
	cmd := exec.Command(bin, "scan", "/no/such/path/anywhere")
	cmd.Dir = repoRoot(t)
	out, _ := cmd.CombinedOutput()
	// Should return non-zero exit but NOT crash. We only assert no panic stack.
	if strings.Contains(string(out), "runtime error:") || strings.Contains(string(out), "panic:") {
		t.Errorf("scanner panicked on nonexistent target:\n%s", out)
	}
}
