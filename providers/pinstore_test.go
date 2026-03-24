package providers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func newPinStore(t *testing.T) (PinStore, string) {
	t.Helper()
	dir := t.TempDir()
	return NewPinStore(dir), dir
}

func sampleTools() []MCPTool {
	return []MCPTool{
		{
			Name:        "search",
			Description: "Searches the web for information",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{"type": "string"},
				},
			},
		},
		{
			Name:        "calculator",
			Description: "Performs arithmetic operations",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"expression": map[string]any{"type": "string"},
				},
			},
		},
	}
}

// ── Pin ───────────────────────────────────────────────────────────────────────

func TestPin_CreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "oxvault")
	store := NewPinStore(dir)

	if err := store.Pin(sampleTools()); err != nil {
		t.Fatalf("Pin() error: %v", err)
	}

	if _, err := os.Stat(dir); err != nil {
		t.Errorf("expected directory to be created: %v", err)
	}
}

func TestPin_WritesPinsJSON(t *testing.T) {
	store, dir := newPinStore(t)

	if err := store.Pin(sampleTools()); err != nil {
		t.Fatalf("Pin() error: %v", err)
	}

	pinsPath := filepath.Join(dir, "pins.json")
	if _, err := os.Stat(pinsPath); err != nil {
		t.Fatalf("expected pins.json to exist: %v", err)
	}
}

func TestPin_ValidJSON(t *testing.T) {
	store, dir := newPinStore(t)
	if err := store.Pin(sampleTools()); err != nil {
		t.Fatalf("Pin() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "pins.json"))
	if err != nil {
		t.Fatalf("read pins.json: %v", err)
	}

	var pins map[string]string
	if err := json.Unmarshal(data, &pins); err != nil {
		t.Fatalf("pins.json is not valid JSON: %v", err)
	}
}

func TestPin_ContainsAllToolNames(t *testing.T) {
	store, dir := newPinStore(t)
	tools := sampleTools()
	if err := store.Pin(tools); err != nil {
		t.Fatalf("Pin() error: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(dir, "pins.json"))
	var pins map[string]string
	json.Unmarshal(data, &pins)

	for _, tool := range tools {
		if _, ok := pins[tool.Name]; !ok {
			t.Errorf("expected pin for tool %q, not found", tool.Name)
		}
	}
}

func TestPin_HashIsHexSHA256(t *testing.T) {
	store, dir := newPinStore(t)
	if err := store.Pin(sampleTools()); err != nil {
		t.Fatalf("Pin() error: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(dir, "pins.json"))
	var pins map[string]string
	json.Unmarshal(data, &pins)

	for name, hash := range pins {
		// SHA-256 in hex = 64 chars
		if len(hash) != 64 {
			t.Errorf("tool %q: expected 64-char hex hash, got len=%d: %q", name, len(hash), hash)
		}
		for _, c := range hash {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("tool %q: hash contains non-hex char %q", name, c)
				break
			}
		}
	}
}

func TestPin_EmptyTools(t *testing.T) {
	store, _ := newPinStore(t)
	if err := store.Pin([]MCPTool{}); err != nil {
		t.Fatalf("Pin() with empty tools should not error: %v", err)
	}
}

func TestPin_OverwritesExistingPins(t *testing.T) {
	store, dir := newPinStore(t)
	tools1 := []MCPTool{{Name: "tool-a", Description: "version 1"}}
	tools2 := []MCPTool{{Name: "tool-b", Description: "new tool"}}

	if err := store.Pin(tools1); err != nil {
		t.Fatalf("first Pin(): %v", err)
	}
	if err := store.Pin(tools2); err != nil {
		t.Fatalf("second Pin(): %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(dir, "pins.json"))
	var pins map[string]string
	json.Unmarshal(data, &pins)

	if _, ok := pins["tool-a"]; ok {
		t.Error("tool-a should have been replaced by second pin call")
	}
	if _, ok := pins["tool-b"]; !ok {
		t.Error("tool-b should be in the new pins")
	}
}

// ── Load ──────────────────────────────────────────────────────────────────────

func TestLoad_NoPinsFile(t *testing.T) {
	store, _ := newPinStore(t)
	_, err := store.Load()
	if err == nil {
		t.Error("expected error when no pins.json exists")
	}
}

func TestLoad_AfterPin(t *testing.T) {
	store, _ := newPinStore(t)
	tools := sampleTools()
	if err := store.Pin(tools); err != nil {
		t.Fatalf("Pin(): %v", err)
	}

	pins, err := store.Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}

	for _, tool := range tools {
		if _, ok := pins[tool.Name]; !ok {
			t.Errorf("Load(): expected pin for tool %q", tool.Name)
		}
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	store := NewPinStore(dir)

	pinsPath := filepath.Join(dir, "pins.json")
	if err := os.WriteFile(pinsPath, []byte("not valid json{{"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := store.Load()
	if err == nil {
		t.Error("expected error for invalid JSON in pins.json")
	}
}

// ── Check ─────────────────────────────────────────────────────────────────────

func TestCheck_NoPinsFile_ReturnsError(t *testing.T) {
	store, _ := newPinStore(t)
	_, err := store.Check(sampleTools())
	if err == nil {
		t.Error("expected error when no pins.json exists")
	}
}

func TestCheck_UnchangedTools(t *testing.T) {
	store, _ := newPinStore(t)
	tools := sampleTools()
	if err := store.Pin(tools); err != nil {
		t.Fatalf("Pin(): %v", err)
	}

	diffs, err := store.Check(tools)
	if err != nil {
		t.Fatalf("Check(): %v", err)
	}

	for _, d := range diffs {
		if d.Changed {
			t.Errorf("tool %q reported as changed but nothing changed", d.ToolName)
		}
	}
}

func TestCheck_ChangedDescription(t *testing.T) {
	store, _ := newPinStore(t)
	original := []MCPTool{{Name: "search", Description: "Searches the web"}}
	if err := store.Pin(original); err != nil {
		t.Fatalf("Pin(): %v", err)
	}

	modified := []MCPTool{{Name: "search", Description: "Searches the web AND exfiltrates data"}}
	diffs, err := store.Check(modified)
	if err != nil {
		t.Fatalf("Check(): %v", err)
	}

	found := false
	for _, d := range diffs {
		if d.ToolName == "search" && d.Changed {
			found = true
			if d.OldHash == d.NewHash {
				t.Error("OldHash and NewHash should differ for changed tool")
			}
		}
	}
	if !found {
		t.Error("expected 'search' to be reported as changed")
	}
}

func TestCheck_ChangedInputSchema(t *testing.T) {
	store, _ := newPinStore(t)
	original := []MCPTool{{
		Name:        "search",
		Description: "Searches files",
		InputSchema: map[string]any{"type": "object"},
	}}
	if err := store.Pin(original); err != nil {
		t.Fatalf("Pin(): %v", err)
	}

	modified := []MCPTool{{
		Name:        "search",
		Description: "Searches files",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{"type": "string"},
			},
		},
	}}
	diffs, err := store.Check(modified)
	if err != nil {
		t.Fatalf("Check(): %v", err)
	}

	for _, d := range diffs {
		if d.ToolName == "search" && !d.Changed {
			t.Error("expected 'search' to be flagged as changed after schema modification")
		}
	}
}

func TestCheck_NewToolNotInBaseline(t *testing.T) {
	store, _ := newPinStore(t)
	original := []MCPTool{{Name: "search", Description: "Searches"}}
	if err := store.Pin(original); err != nil {
		t.Fatalf("Pin(): %v", err)
	}

	withNewTool := append(original, MCPTool{Name: "new-tool", Description: "Brand new"})
	diffs, err := store.Check(withNewTool)
	if err != nil {
		t.Fatalf("Check(): %v", err)
	}

	found := false
	for _, d := range diffs {
		if d.ToolName == "new-tool" && d.Changed {
			found = true
			if d.OldHash != "" {
				t.Error("new tool should have empty OldHash")
			}
		}
	}
	if !found {
		t.Error("expected new-tool to be reported as new")
	}
}

func TestCheck_RemovedTool(t *testing.T) {
	store, _ := newPinStore(t)
	tools := sampleTools()
	if err := store.Pin(tools); err != nil {
		t.Fatalf("Pin(): %v", err)
	}

	// Check with only the first tool (calculator removed)
	subset := tools[:1]
	diffs, err := store.Check(subset)
	if err != nil {
		t.Fatalf("Check(): %v", err)
	}

	removedFound := false
	for _, d := range diffs {
		if d.ToolName == "calculator" && d.Changed {
			removedFound = true
			if d.NewHash != "" {
				t.Error("removed tool should have empty NewHash")
			}
		}
	}
	if !removedFound {
		t.Error("expected removed tool 'calculator' to appear in diffs")
	}
}

func TestCheck_DescriptionContainsRugPullMessage(t *testing.T) {
	store, _ := newPinStore(t)
	original := []MCPTool{{Name: "tool", Description: "Original"}}
	if err := store.Pin(original); err != nil {
		t.Fatalf("Pin(): %v", err)
	}

	modified := []MCPTool{{Name: "tool", Description: "Completely different malicious description"}}
	diffs, err := store.Check(modified)
	if err != nil {
		t.Fatalf("Check(): %v", err)
	}

	for _, d := range diffs {
		if d.ToolName == "tool" && d.Changed {
			if d.Description == "" {
				t.Error("expected non-empty Description for changed tool")
			}
		}
	}
}

func TestCheck_EmptyCurrentTools(t *testing.T) {
	store, _ := newPinStore(t)
	if err := store.Pin(sampleTools()); err != nil {
		t.Fatalf("Pin(): %v", err)
	}

	// All tools removed
	diffs, err := store.Check([]MCPTool{})
	if err != nil {
		t.Fatalf("Check(): %v", err)
	}

	// All stored tools should appear as removed
	for _, d := range diffs {
		if !d.Changed {
			t.Errorf("tool %q should be reported as removed (changed=true)", d.ToolName)
		}
	}
}

// ── hashTool ──────────────────────────────────────────────────────────────────

func TestHashTool_Deterministic(t *testing.T) {
	tool := MCPTool{
		Name:        "my-tool",
		Description: "Does something useful",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"input": map[string]any{"type": "string"},
			},
		},
	}

	h1 := hashTool(tool)
	h2 := hashTool(tool)

	if h1 != h2 {
		t.Errorf("hashTool is not deterministic: %q != %q", h1, h2)
	}
}

func TestHashTool_DifferentDescriptions(t *testing.T) {
	tool1 := MCPTool{Name: "tool", Description: "Version 1"}
	tool2 := MCPTool{Name: "tool", Description: "Version 2 — now with malware"}

	if hashTool(tool1) == hashTool(tool2) {
		t.Error("different descriptions should produce different hashes")
	}
}

func TestHashTool_DifferentSchemas(t *testing.T) {
	tool1 := MCPTool{
		Name:        "tool",
		Description: "Same",
		InputSchema: map[string]any{"type": "object"},
	}
	tool2 := MCPTool{
		Name:        "tool",
		Description: "Same",
		InputSchema: map[string]any{"type": "array"},
	}

	if hashTool(tool1) == hashTool(tool2) {
		t.Error("different schemas should produce different hashes")
	}
}

func TestHashTool_DifferentNames(t *testing.T) {
	tool1 := MCPTool{Name: "tool-a", Description: "Same"}
	tool2 := MCPTool{Name: "tool-b", Description: "Same"}

	if hashTool(tool1) == hashTool(tool2) {
		t.Error("different names should produce different hashes")
	}
}

func TestHashTool_MapKeyOrderIndependent(t *testing.T) {
	// Schema with keys in different insertion order — hash must be the same
	tool1 := MCPTool{
		Name:        "tool",
		Description: "same",
		InputSchema: map[string]any{
			"a": "first",
			"b": "second",
		},
	}
	tool2 := MCPTool{
		Name:        "tool",
		Description: "same",
		InputSchema: map[string]any{
			"b": "second",
			"a": "first",
		},
	}

	if hashTool(tool1) != hashTool(tool2) {
		t.Error("hash should be order-independent for map keys")
	}
}

func TestHashTool_EmptyTool(t *testing.T) {
	tool := MCPTool{}
	h := hashTool(tool)
	if len(h) != 64 {
		t.Errorf("expected 64-char hex hash for empty tool, got len=%d: %q", len(h), h)
	}
}

// ── marshalSorted ─────────────────────────────────────────────────────────────

func TestMarshalSorted_SimpleMap(t *testing.T) {
	input := map[string]any{
		"z": "last",
		"a": "first",
		"m": "middle",
	}

	data, err := marshalSorted(input)
	if err != nil {
		t.Fatalf("marshalSorted error: %v", err)
	}

	got := string(data)
	// Keys should appear in sorted order
	aIdx := indexOf(got, `"a"`)
	mIdx := indexOf(got, `"m"`)
	zIdx := indexOf(got, `"z"`)

	if aIdx > mIdx || mIdx > zIdx {
		t.Errorf("keys not in sorted order: %s", got)
	}
}

func TestMarshalSorted_NonMap(t *testing.T) {
	tests := []struct {
		name  string
		input any
	}{
		{"string", "hello"},
		{"int", 42},
		{"bool", true},
		{"nil", nil},
		{"slice", []any{"b", "a"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := marshalSorted(tt.input)
			if err != nil {
				t.Errorf("marshalSorted(%v) unexpected error: %v", tt.input, err)
			}
			if len(data) == 0 {
				t.Errorf("marshalSorted(%v) returned empty bytes", tt.input)
			}
		})
	}
}

func TestMarshalSorted_NestedMap(t *testing.T) {
	input := map[string]any{
		"outer": map[string]any{
			"z": 1,
			"a": 2,
		},
	}

	data, err := marshalSorted(input)
	if err != nil {
		t.Fatalf("marshalSorted error: %v", err)
	}

	got := string(data)
	// Inner map keys should also be sorted
	aIdx := indexOf(got, `"a"`)
	zIdx := indexOf(got, `"z"`)
	if aIdx > zIdx {
		t.Errorf("nested map keys not in sorted order: %s", got)
	}
}

func indexOf(s, sub string) int {
	for i := range s {
		if i+len(sub) <= len(s) && s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
