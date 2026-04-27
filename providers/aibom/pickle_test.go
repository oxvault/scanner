package aibom_test

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oxvault/scanner/providers"
	"github.com/oxvault/scanner/providers/aibom"
)

// fixtureRoot returns the absolute path to testdata/aibom/pickle/<rel>.
func pickleFixture(t *testing.T, rel string) string {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "aibom", "pickle", rel)
	if _, err := os.Stat(path); err != nil {
		t.Skipf("fixture %s missing — run scripts/gen_aibom_fixtures.py: %v", rel, err)
	}
	return path
}

// ── repo fixture suite ──────────────────────────────────────────────────────
//
// Each fixture is paired with at least one expected (rule, severity) tuple.
// Some fixtures legitimately produce multiple findings — the test only
// asserts the diagnostic that uniquely identifies the attack class.

func TestPickleAnalyzer_Fixtures(t *testing.T) {
	tests := []struct {
		name         string
		fixture      string
		wantRule     string
		wantSeverity providers.Severity
	}{
		{
			name:         "safe torch state_dict surfaces allowlisted INFO",
			fixture:      "safe/torch_state_dict.pkl",
			wantRule:     "aibom-pickle-allowlisted",
			wantSeverity: providers.SeverityInfo,
		},
		{
			name:         "safe numpy array surfaces allowlisted INFO",
			fixture:      "safe/numpy_array.pkl",
			wantRule:     "aibom-pickle-allowlisted",
			wantSeverity: providers.SeverityInfo,
		},
		{
			name:         "os.system payload flagged CRITICAL",
			fixture:      "malicious/os_system.pkl",
			wantRule:     "aibom-pickle-os-system",
			wantSeverity: providers.SeverityCritical,
		},
		{
			name:         "subprocess.Popen payload flagged CRITICAL",
			fixture:      "malicious/subprocess_popen.pkl",
			wantRule:     "aibom-pickle-subprocess",
			wantSeverity: providers.SeverityCritical,
		},
		{
			name:         "builtins.eval payload flagged CRITICAL",
			fixture:      "malicious/eval_payload.pkl",
			wantRule:     "aibom-pickle-eval-exec",
			wantSeverity: providers.SeverityCritical,
		},
		{
			name:         "__import__ smuggle flagged CRITICAL",
			fixture:      "malicious/import_smuggle.pkl",
			wantRule:     "aibom-pickle-import",
			wantSeverity: providers.SeverityCritical,
		},
		{
			name:         "requests.get exfil flagged HIGH",
			fixture:      "malicious/network_call.pkl",
			wantRule:     "aibom-pickle-network",
			wantSeverity: providers.SeverityHigh,
		},
		{
			name:         "truncated stream flagged WARNING",
			fixture:      "malicious/truncated.pkl",
			wantRule:     "aibom-pickle-truncated",
			wantSeverity: providers.SeverityWarning,
		},
		{
			name:         "PyTorch ZIP wrapping malicious data.pkl flagged CRITICAL",
			fixture:      "malicious/pytorch_zip_evil.pt",
			wantRule:     "aibom-pickle-os-system",
			wantSeverity: providers.SeverityCritical,
		},
		{
			name:         "deeply-nested ZIP bomb flagged WARNING",
			fixture:      "malicious/zip_bomb_nested.pt",
			wantRule:     "aibom-pickle-truncated",
			wantSeverity: providers.SeverityWarning,
		},
		{
			name:         "ZIP archive with > maxInnerPickles entries flagged WARNING",
			fixture:      "malicious/many_inner_pkls.pt",
			wantRule:     "aibom-pickle-truncated",
			wantSeverity: providers.SeverityWarning,
		},
		{
			name:         "oversized pickle file flagged WARNING",
			fixture:      "malicious/oversized_file.pkl",
			wantRule:     "aibom-pickle-truncated",
			wantSeverity: providers.SeverityWarning,
		},
	}

	a := aibom.NewPickleAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := pickleFixture(t, tt.fixture)
			findings := a.AnalyzeFile(path)
			if !findRuleAndSeverity(findings, tt.wantRule, tt.wantSeverity) {
				t.Errorf("expected rule %q at severity %v, got %d findings: %+v",
					tt.wantRule, tt.wantSeverity, len(findings), findings)
			}
		})
	}
}

// TestPickleAnalyzer_OversizedFileSkipsDisassembly asserts that a 3 GiB pickle
// file emits ONLY the truncation finding and never tries to read the entire
// stream. (Reading 3 GiB into memory in CI would cripple the runner.)
func TestPickleAnalyzer_OversizedFileSkipsDisassembly(t *testing.T) {
	path := pickleFixture(t, "malicious/oversized_file.pkl")
	a := aibom.NewPickleAnalyzer()

	findings := a.AnalyzeFile(path)
	if len(findings) != 1 {
		t.Fatalf("oversized fixture: expected exactly 1 finding (truncated), got %d (%+v)",
			len(findings), findings)
	}
	if findings[0].Rule != "aibom-pickle-truncated" {
		t.Errorf("oversized fixture: rule = %q, want aibom-pickle-truncated", findings[0].Rule)
	}
	if !strings.Contains(findings[0].Message, "safety cap") {
		t.Errorf("oversized fixture: message should mention size cap, got %q", findings[0].Message)
	}
}

// TestPickleAnalyzer_ZipBombNestedExceedsRecursionDepth verifies the
// recursion-depth guard fires for the 6-layer ZIP bomb fixture.
func TestPickleAnalyzer_ZipBombNestedExceedsRecursionDepth(t *testing.T) {
	path := pickleFixture(t, "malicious/zip_bomb_nested.pt")
	a := aibom.NewPickleAnalyzer()

	findings := a.AnalyzeFile(path)
	if !findRule(findings, "aibom-pickle-truncated") {
		t.Errorf("expected aibom-pickle-truncated for nested ZIP bomb, got: %+v", findings)
	}
	// Sanity: the deepest layer would have surfaced an aibom-pickle-os-system
	// finding had recursion been allowed. The guard should prevent it.
	for _, f := range findings {
		if f.Rule == "aibom-pickle-os-system" {
			t.Errorf("recursion depth guard failed — deep payload was reached: %+v", f)
		}
	}
}

// TestPickleAnalyzer_ManyInnerPicklesEnforcesEntryCap verifies the inner-ZIP
// entry count cap caps analysis even if every entry is independently small.
func TestPickleAnalyzer_ManyInnerPicklesEnforcesEntryCap(t *testing.T) {
	path := pickleFixture(t, "malicious/many_inner_pkls.pt")
	a := aibom.NewPickleAnalyzer()

	findings := a.AnalyzeFile(path)
	// Truncation finding MUST be present.
	if !findRule(findings, "aibom-pickle-truncated") {
		t.Errorf("expected aibom-pickle-truncated for over-cap archive, got: %+v", findings)
	}
	// We still expect the first batch of entries to fire os-system findings —
	// just not all 100. Count them.
	osSysCount := 0
	for _, f := range findings {
		if f.Rule == "aibom-pickle-os-system" {
			osSysCount++
		}
	}
	if osSysCount == 0 {
		t.Errorf("expected at least one os-system finding before cap, got 0 (%+v)", findings)
	}
	if osSysCount >= 100 {
		t.Errorf("entry cap not enforced — saw %d os-system findings (>= 100)", osSysCount)
	}
}

// ── synthesised opcode-level edge-case suite ────────────────────────────────
//
// These tests build pickle byte streams in-process so we can exercise byte-
// level edge cases (STACK_GLOBAL guards, MEMOIZE id collisions, prefix
// allowlist) without requiring fixture files.

const (
	opPROTO            = byte(0x80)
	opFRAME            = byte(0x95)
	opSTOP             = byte('.')
	opSHORT_BINUNICODE = byte(0x8c)
	opSTACK_GLOBAL     = byte(0x93)
	opMEMOIZE          = byte(0x94)
	opEMPTY_TUPLE      = byte(')')
	opTUPLE1           = byte(0x85)
	opREDUCE           = byte('R')
	opNONE             = byte('N')
	opBINPUT           = byte('q')
	opBINGET           = byte('h')
)

// buildPickle wraps body with the standard PROTO 4 + FRAME header + STOP.
func buildPickle(body []byte) []byte {
	inner := make([]byte, 0, len(body)+1)
	inner = append(inner, body...)
	inner = append(inner, opSTOP)
	out := make([]byte, 0, len(inner)+10)
	out = append(out, opPROTO, 0x04)
	out = append(out, opFRAME)
	frameLen := make([]byte, 8)
	binary.LittleEndian.PutUint64(frameLen, uint64(len(inner)))
	out = append(out, frameLen...)
	out = append(out, inner...)
	return out
}

// shortBinunicode emits a SHORT_BINUNICODE opcode for the given UTF-8 string.
func shortBinunicode(s string) []byte {
	if len(s) >= 256 {
		panic("test helper: string too long for SHORT_BINUNICODE")
	}
	out := []byte{opSHORT_BINUNICODE, byte(len(s))}
	out = append(out, []byte(s)...)
	return out
}

// stackGlobal emits two SHORT_BINUNICODE strings and STACK_GLOBAL.
func stackGlobal(module, name string) []byte {
	out := shortBinunicode(module)
	out = append(out, shortBinunicode(name)...)
	out = append(out, opSTACK_GLOBAL)
	return out
}

func writeTempPickle(t *testing.T, body []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pkl")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestPickleAnalyzer_StackGlobalValid(t *testing.T) {
	// STACK_GLOBAL with two valid kindString entries — should classify the
	// resulting GLOBAL ref. We use builtins.eval to force a CRITICAL finding.
	body := stackGlobal("builtins", "eval") // STACK_GLOBAL on stack
	body = append(body, opMEMOIZE)
	body = append(body, opEMPTY_TUPLE)
	body = append(body, opREDUCE)
	body = append(body, opMEMOIZE)

	path := writeTempPickle(t, buildPickle(body))
	findings := aibom.NewPickleAnalyzer().AnalyzeFile(path)
	if !findRuleAndSeverity(findings, "aibom-pickle-eval-exec", providers.SeverityCritical) {
		t.Errorf("expected eval-exec CRITICAL, got: %+v", findings)
	}
}

func TestPickleAnalyzer_StackGlobalMalformedStack(t *testing.T) {
	// Pop two non-string entries: NONE NONE STACK_GLOBAL. The fixed
	// disassembler must refuse to synthesise a "." reference and emit
	// truncated WARNING instead.
	body := []byte{opNONE, opNONE, opSTACK_GLOBAL}

	path := writeTempPickle(t, buildPickle(body))
	findings := aibom.NewPickleAnalyzer().AnalyzeFile(path)
	if !findRuleAndSeverity(findings, "aibom-pickle-truncated", providers.SeverityWarning) {
		t.Errorf("expected truncated WARNING for malformed STACK_GLOBAL, got: %+v", findings)
	}
}

func TestPickleAnalyzer_AllowlistSuppressesPerRefFindings(t *testing.T) {
	// torch._utils._rebuild_tensor_v2 is in the allowlist. A bare GLOBAL
	// reference to it (with REDUCE) MUST NOT fire reduce-suspicious — only
	// the file-level allowlisted INFO summary should appear.
	body := stackGlobal("torch._utils", "_rebuild_tensor_v2")
	body = append(body, opMEMOIZE)
	body = append(body, opEMPTY_TUPLE)
	body = append(body, opREDUCE)
	body = append(body, opMEMOIZE)

	path := writeTempPickle(t, buildPickle(body))
	findings := aibom.NewPickleAnalyzer().AnalyzeFile(path)

	if findRule(findings, "aibom-pickle-reduce-suspicious") {
		t.Errorf("allowlisted ref should not fire reduce-suspicious, got: %+v", findings)
	}
	if !findRule(findings, "aibom-pickle-allowlisted") {
		t.Errorf("expected aibom-pickle-allowlisted INFO, got: %+v", findings)
	}
}

func TestPickleAnalyzer_PrefixAllowlistSuppressesFindings(t *testing.T) {
	// torch.nn.modules.linear.Linear matches the AllowedMLGlobalPrefixes
	// entry "torch.nn.modules.". A bare GLOBAL ref must be suppressed.
	body := stackGlobal("torch.nn.modules.linear", "Linear")
	body = append(body, opMEMOIZE)

	path := writeTempPickle(t, buildPickle(body))
	findings := aibom.NewPickleAnalyzer().AnalyzeFile(path)

	for _, f := range findings {
		if f.Rule == "aibom-pickle-reduce-suspicious" {
			t.Errorf("prefix-allowlisted ref should not fire reduce-suspicious: %+v", f)
		}
		if f.Rule == "aibom-pickle-network" || f.Rule == "aibom-pickle-os-system" {
			t.Errorf("prefix-allowlisted ref should not fire any dangerous rule: %+v", f)
		}
	}
	if !findRule(findings, "aibom-pickle-allowlisted") {
		t.Errorf("expected aibom-pickle-allowlisted INFO, got: %+v", findings)
	}
}

func TestPickleAnalyzer_MemoizeIDDoesNotCollideWithBinput(t *testing.T) {
	// Regression test for the opMEMOIZE id-allocation bug.
	//
	// With the buggy code (memoID := len(d.memo)), the first MEMOIZE picks
	// id == len(memo). If BINPUT had previously written to id 0, then
	// len(memo)==1 — so MEMOIZE would write to id 1. Subsequent MEMOIZEs
	// pick the same id (1) until len(memo) grows. The collision is subtle
	// but lets a crafted stream confuse the disassembler's GET resolution.
	//
	// With the fix (separate nextMemoID counter starting at 0), MEMOIZE
	// writes to id 0 first — and OVERWRITES the previous BINPUT(0) entry.
	//
	// Build:
	//   1. SHORT_BINUNICODE("safe_value") BINPUT(0)  — store kindString at id 0
	//   2. SHORT_BINUNICODE("os")          MEMOIZE   — fix: stores at id 0,
	//                                                  overwriting "safe_value"
	//   3. SHORT_BINUNICODE("system")      MEMOIZE   — fix: stores at id 1
	//   4. BINGET 0  BINGET 1  STACK_GLOBAL
	//
	// The resulting STACK_GLOBAL sees ("os", "system") → "os.system" → CRITICAL.
	//
	// In the buggy code, MEMOIZE at step 2 would write to id 1 (not 0), so
	// step 4's BINGET 0 would retrieve "safe_value" and BINGET 1 would
	// retrieve "os" — yielding "safe_value.os", which is unrecognised and
	// fires no finding. The test asserts the CORRECT behaviour: os.system
	// CRITICAL must fire.
	body := append([]byte{}, shortBinunicode("safe_value")...)
	body = append(body, opBINPUT, 0x00)
	body = append(body, shortBinunicode("os")...)
	body = append(body, opMEMOIZE)
	body = append(body, shortBinunicode("system")...)
	body = append(body, opMEMOIZE)
	body = append(body, opBINGET, 0x00)
	body = append(body, opBINGET, 0x01)
	body = append(body, opSTACK_GLOBAL, opMEMOIZE)
	body = append(body, opEMPTY_TUPLE, opREDUCE, opMEMOIZE)

	path := writeTempPickle(t, buildPickle(body))
	findings := aibom.NewPickleAnalyzer().AnalyzeFile(path)

	if !findRuleAndSeverity(findings, "aibom-pickle-os-system", providers.SeverityCritical) {
		t.Errorf("expected os-system CRITICAL after MEMOIZE id allocation, got: %+v", findings)
	}
	for _, f := range findings {
		// Crucial: there must be NO finding referencing "safe_value." — that
		// would indicate MEMOIZE wrote to the wrong id, leaking the previous
		// BINPUT entry into the GLOBAL ref.
		if strings.Contains(f.Message, "safe_value.") {
			t.Errorf("MEMOIZE id collision regression: %+v", f)
		}
	}
}

// TestPickleAnalyzer_RecursionDepthBypassed asserts that crafting a ZIP
// archive whose inner pickle is itself a deep ZIP chain fires the depth
// guard. This is the regression test for the depth-bypass-via-analyzeBytes
// fix.
func TestPickleAnalyzer_RecursionDepthEnforcedFromZipPath(t *testing.T) {
	// Build a malicious leaf pickle (os.system).
	leafBody := stackGlobal("os", "system")
	leafBody = append(leafBody, opMEMOIZE)
	leafBody = append(leafBody, shortBinunicode("id")...)
	leafBody = append(leafBody, opTUPLE1)
	leafBody = append(leafBody, opREDUCE, opMEMOIZE)
	leaf := buildPickle(leafBody)

	// Wrap in 6 layers of ZIP — each layer puts the previous bytes in
	// archive/data.pkl.
	payload := leaf
	for i := 0; i < 6; i++ {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		w, err := zw.Create("archive/data.pkl")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		payload = buf.Bytes()
	}

	path := writeTempPickle(t, payload)
	findings := aibom.NewPickleAnalyzer().AnalyzeFile(path)

	if !findRule(findings, "aibom-pickle-truncated") {
		t.Errorf("expected aibom-pickle-truncated when ZIP chain exceeds depth, got: %+v", findings)
	}
	for _, f := range findings {
		if f.Rule == "aibom-pickle-os-system" {
			t.Errorf("depth guard failed — leaf payload reached: %+v", f)
		}
	}
}

// TestPickleAnalyzer_ZipReaderPanicHandled wraps the analyzer in a malformed
// ZIP archive that historically tripped panics in archive/zip. Even if no
// known panic input is supplied, the recover path should handle anything.
func TestPickleAnalyzer_HandlesMalformedZipGracefully(t *testing.T) {
	// A truncated ZIP header — starts with PK but missing the rest.
	body := []byte{'P', 'K', 0x03, 0x04, 0x00, 0x00, 0x00, 0x00}
	path := writeTempPickle(t, body)

	findings := aibom.NewPickleAnalyzer().AnalyzeFile(path)
	// Truncation finding MUST be present (either from ZIP-parse failure or
	// the recover path).
	if !findRule(findings, "aibom-pickle-truncated") {
		t.Errorf("expected aibom-pickle-truncated for malformed ZIP, got: %+v", findings)
	}
}

// TestPickleAnalyzer_EmptyFile ensures empty pickle files don't crash.
func TestPickleAnalyzer_EmptyFile(t *testing.T) {
	path := writeTempPickle(t, nil)
	findings := aibom.NewPickleAnalyzer().AnalyzeFile(path)
	// An empty stream is "truncated — stream ended before STOP".
	if !findRule(findings, "aibom-pickle-truncated") {
		t.Errorf("expected aibom-pickle-truncated for empty file, got: %+v", findings)
	}
}

// TestPickleAnalyzer_AnalyzeDirectory_WalksAndDispatches verifies that the
// directory walker delegates to AnalyzeFile per-format.
func TestPickleAnalyzer_AnalyzeDirectory_WalksAllPickles(t *testing.T) {
	dir := t.TempDir()
	// Two pickles, one decoy.
	body := stackGlobal("os", "system")
	body = append(body, opMEMOIZE, opEMPTY_TUPLE, opREDUCE, opMEMOIZE)
	full := buildPickle(body)

	if err := os.WriteFile(filepath.Join(dir, "a.pkl"), full, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.pkl"), full, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "decoy.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}

	findings := aibom.NewPickleAnalyzer().AnalyzeDirectory(dir)

	osSysCount := 0
	for _, f := range findings {
		if f.Rule == "aibom-pickle-os-system" {
			osSysCount++
		}
	}
	if osSysCount != 2 {
		t.Errorf("expected 2 os-system findings (one per pickle), got %d (%+v)", osSysCount, findings)
	}
}

// TestPickleAnalyzer_NonexistentFile asserts a nil return for missing files.
func TestPickleAnalyzer_NonexistentFile(t *testing.T) {
	findings := aibom.NewPickleAnalyzer().AnalyzeFile("/no/such/file/anywhere.pkl")
	if findings != nil {
		t.Errorf("expected nil for missing file, got %+v", findings)
	}
}
