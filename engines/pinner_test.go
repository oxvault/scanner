package engines

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/oxvault/scanner/providers"
	"github.com/oxvault/scanner/testutil"
)

// newTestPinner wires up a pinner with the given mocks and a discard logger.
func newTestPinner(mcpClient *testutil.MockMCPClient, pinStore *testutil.MockPinStore) PinEngine {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewPinner(mcpClient, pinStore, logger)
}

func TestPinner_Pin_Success(t *testing.T) {
	tools := []providers.MCPTool{
		{Name: "tool_a", Description: "does something"},
		{Name: "tool_b", Description: "does something else"},
	}
	mcpClient := &testutil.MockMCPClient{
		ConnectResult:   defaultSession(),
		ListToolsResult: tools,
	}
	pinStore := &testutil.MockPinStore{}

	eng := newTestPinner(mcpClient, pinStore)
	count, err := eng.Pin("node", []string{"server.js"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected count=2, got %d", count)
	}
	if mcpClient.ConnectCount.Load() != 1 {
		t.Errorf("expected 1 Connect call, got %d", mcpClient.ConnectCount.Load())
	}
	if mcpClient.ListToolsCount.Load() != 1 {
		t.Errorf("expected 1 ListTools call, got %d", mcpClient.ListToolsCount.Load())
	}
	if mcpClient.CloseCount.Load() != 1 {
		t.Errorf("expected 1 Close call (defer), got %d", mcpClient.CloseCount.Load())
	}
	if pinStore.PinCount.Load() != 1 {
		t.Errorf("expected 1 Pin call, got %d", pinStore.PinCount.Load())
	}
}

func TestPinner_Pin_ConnectError(t *testing.T) {
	mcpClient := &testutil.MockMCPClient{
		ConnectErr: errors.New("refused"),
	}
	pinStore := &testutil.MockPinStore{}

	eng := newTestPinner(mcpClient, pinStore)
	_, err := eng.Pin("node", []string{"server.js"})

	if err == nil {
		t.Fatal("expected error from connect failure")
	}
	if !errors.Is(err, mcpClient.ConnectErr) {
		t.Errorf("expected wrapped connect error, got: %v", err)
	}
	// Pin should never be called if connect fails
	if pinStore.PinCount.Load() != 0 {
		t.Errorf("PinStore.Pin should not be called on connect error")
	}
}

func TestPinner_Pin_ListToolsError(t *testing.T) {
	mcpClient := &testutil.MockMCPClient{
		ConnectResult: defaultSession(),
		ListToolsErr:  errors.New("protocol error"),
	}
	pinStore := &testutil.MockPinStore{}

	eng := newTestPinner(mcpClient, pinStore)
	_, err := eng.Pin("node", []string{"server.js"})

	if err == nil {
		t.Fatal("expected error from ListTools failure")
	}
	if !errors.Is(err, mcpClient.ListToolsErr) {
		t.Errorf("expected wrapped ListTools error, got: %v", err)
	}
	if pinStore.PinCount.Load() != 0 {
		t.Errorf("PinStore.Pin should not be called on ListTools error")
	}
	// Close should still be called via defer
	if mcpClient.CloseCount.Load() != 1 {
		t.Errorf("expected Close to be called via defer, got %d", mcpClient.CloseCount.Load())
	}
}

func TestPinner_Pin_StoreError(t *testing.T) {
	mcpClient := &testutil.MockMCPClient{
		ConnectResult:   defaultSession(),
		ListToolsResult: []providers.MCPTool{{Name: "tool_a"}},
	}
	pinStore := &testutil.MockPinStore{
		PinErr: errors.New("disk full"),
	}

	eng := newTestPinner(mcpClient, pinStore)
	_, err := eng.Pin("node", []string{"server.js"})

	if err == nil {
		t.Fatal("expected error from PinStore.Pin failure")
	}
	if !errors.Is(err, pinStore.PinErr) {
		t.Errorf("expected wrapped PinStore error, got: %v", err)
	}
}

func TestPinner_Pin_EmptyToolList(t *testing.T) {
	mcpClient := &testutil.MockMCPClient{
		ConnectResult:   defaultSession(),
		ListToolsResult: []providers.MCPTool{},
	}
	pinStore := &testutil.MockPinStore{}

	eng := newTestPinner(mcpClient, pinStore)
	count, err := eng.Pin("node", []string{"server.js"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected count=0 for empty tool list, got %d", count)
	}
	if pinStore.PinCount.Load() != 1 {
		t.Errorf("PinStore.Pin should still be called with empty slice")
	}
}

func TestPinner_Check_NoChanges(t *testing.T) {
	tools := []providers.MCPTool{
		{Name: "tool_a", Description: "stable"},
	}
	mcpClient := &testutil.MockMCPClient{
		ConnectResult:   defaultSession(),
		ListToolsResult: tools,
	}
	// No diffs, no changes
	pinStore := &testutil.MockPinStore{
		CheckResult: []providers.PinDiff{
			{ToolName: "tool_a", Changed: false},
		},
	}

	eng := newTestPinner(mcpClient, pinStore)
	report, err := eng.Check("node", []string{"server.js"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Changed {
		t.Error("expected Changed=false when no diffs")
	}
	if len(report.Diffs) != 1 {
		t.Errorf("expected 1 diff, got %d", len(report.Diffs))
	}
	if mcpClient.CloseCount.Load() != 1 {
		t.Errorf("expected 1 Close call, got %d", mcpClient.CloseCount.Load())
	}
}

func TestPinner_Check_HasChanges(t *testing.T) {
	tools := []providers.MCPTool{
		{Name: "tool_a", Description: "new description — CHANGED"},
	}
	mcpClient := &testutil.MockMCPClient{
		ConnectResult:   defaultSession(),
		ListToolsResult: tools,
	}
	pinStore := &testutil.MockPinStore{
		CheckResult: []providers.PinDiff{
			{
				ToolName:    "tool_a",
				OldHash:     "abc123",
				NewHash:     "def456",
				Changed:     true,
				Description: "description changed",
			},
		},
	}

	eng := newTestPinner(mcpClient, pinStore)
	report, err := eng.Check("node", []string{"server.js"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.Changed {
		t.Error("expected Changed=true when at least one diff has Changed=true")
	}
	if len(report.Diffs) != 1 {
		t.Errorf("expected 1 diff, got %d", len(report.Diffs))
	}
	d := report.Diffs[0]
	if d.ToolName != "tool_a" {
		t.Errorf("expected ToolName='tool_a', got %q", d.ToolName)
	}
	if d.OldHash != "abc123" {
		t.Errorf("expected OldHash='abc123', got %q", d.OldHash)
	}
	if d.NewHash != "def456" {
		t.Errorf("expected NewHash='def456', got %q", d.NewHash)
	}
}

func TestPinner_Check_MultipleDiffs_OneChanged(t *testing.T) {
	mcpClient := &testutil.MockMCPClient{
		ConnectResult:   defaultSession(),
		ListToolsResult: []providers.MCPTool{{Name: "a"}, {Name: "b"}, {Name: "c"}},
	}
	pinStore := &testutil.MockPinStore{
		CheckResult: []providers.PinDiff{
			{ToolName: "a", Changed: false},
			{ToolName: "b", Changed: true},
			{ToolName: "c", Changed: false},
		},
	}

	eng := newTestPinner(mcpClient, pinStore)
	report, err := eng.Check("node", []string{"server.js"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.Changed {
		t.Error("expected Changed=true when at least one diff has Changed=true")
	}
	if len(report.Diffs) != 3 {
		t.Errorf("expected 3 diffs, got %d", len(report.Diffs))
	}
}

func TestPinner_Check_ConnectError(t *testing.T) {
	mcpClient := &testutil.MockMCPClient{
		ConnectErr: errors.New("timeout"),
	}
	pinStore := &testutil.MockPinStore{}

	eng := newTestPinner(mcpClient, pinStore)
	_, err := eng.Check("node", []string{"server.js"})

	if err == nil {
		t.Fatal("expected error from connect failure")
	}
	if !errors.Is(err, mcpClient.ConnectErr) {
		t.Errorf("expected wrapped connect error, got: %v", err)
	}
	if pinStore.CheckCount.Load() != 0 {
		t.Error("PinStore.Check should not be called on connect error")
	}
}

func TestPinner_Check_ListToolsError(t *testing.T) {
	mcpClient := &testutil.MockMCPClient{
		ConnectResult: defaultSession(),
		ListToolsErr:  errors.New("malformed response"),
	}
	pinStore := &testutil.MockPinStore{}

	eng := newTestPinner(mcpClient, pinStore)
	_, err := eng.Check("node", []string{"server.js"})

	if err == nil {
		t.Fatal("expected error from ListTools failure")
	}
	if pinStore.CheckCount.Load() != 0 {
		t.Error("PinStore.Check should not be called on ListTools error")
	}
	// Close should still be called via defer
	if mcpClient.CloseCount.Load() != 1 {
		t.Errorf("expected Close to be called via defer, got %d", mcpClient.CloseCount.Load())
	}
}

func TestPinner_Check_StoreCheckError(t *testing.T) {
	mcpClient := &testutil.MockMCPClient{
		ConnectResult:   defaultSession(),
		ListToolsResult: []providers.MCPTool{{Name: "tool"}},
	}
	pinStore := &testutil.MockPinStore{
		CheckErr: errors.New("no pins found"),
	}

	eng := newTestPinner(mcpClient, pinStore)
	_, err := eng.Check("node", []string{"server.js"})

	if err == nil {
		t.Fatal("expected error from PinStore.Check failure")
	}
	if !errors.Is(err, pinStore.CheckErr) {
		t.Errorf("expected wrapped check error, got: %v", err)
	}
}

func TestPinner_Check_EmptyDiffs_NotChanged(t *testing.T) {
	mcpClient := &testutil.MockMCPClient{
		ConnectResult:   defaultSession(),
		ListToolsResult: []providers.MCPTool{{Name: "tool"}},
	}
	pinStore := &testutil.MockPinStore{
		CheckResult: []providers.PinDiff{}, // empty slice
	}

	eng := newTestPinner(mcpClient, pinStore)
	report, err := eng.Check("node", []string{"server.js"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Changed {
		t.Error("expected Changed=false for empty diffs")
	}
	if len(report.Diffs) != 0 {
		t.Errorf("expected 0 diffs, got %d", len(report.Diffs))
	}
}
