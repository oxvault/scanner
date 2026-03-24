// Package testutil provides mock implementations of provider interfaces for use in tests.
package testutil

import (
	"sync/atomic"
	"time"

	"github.com/oxvault/scanner/providers"
)

// MockResolver is a configurable mock for providers.Resolver.
type MockResolver struct {
	ResolveResult *providers.ResolvedPackage
	ResolveErr    error
	CallCount     atomic.Int32
}

func (m *MockResolver) Resolve(target string) (*providers.ResolvedPackage, error) {
	m.CallCount.Add(1)
	return m.ResolveResult, m.ResolveErr
}

// MockMCPClient is a configurable mock for providers.MCPClient.
type MockMCPClient struct {
	ConnectResult  *providers.MCPSession
	ConnectErr     error
	ListToolsResult []providers.MCPTool
	ListToolsErr   error
	CloseErr       error

	ConnectCount    atomic.Int32
	ListToolsCount  atomic.Int32
	CloseCount      atomic.Int32
}

func (m *MockMCPClient) Connect(cmd string, args []string) (*providers.MCPSession, error) {
	m.ConnectCount.Add(1)
	return m.ConnectResult, m.ConnectErr
}

func (m *MockMCPClient) ListTools(session *providers.MCPSession) ([]providers.MCPTool, error) {
	m.ListToolsCount.Add(1)
	return m.ListToolsResult, m.ListToolsErr
}

func (m *MockMCPClient) Close(session *providers.MCPSession) error {
	m.CloseCount.Add(1)
	return m.CloseErr
}

// MockRuleMatcher is a configurable mock for providers.RuleMatcher.
type MockRuleMatcher struct {
	ScanDescriptionResult []providers.Finding
	ScanArgumentsResult   []providers.Finding
	ScanResponseResult    []providers.Finding
	ClassifyToolResult    providers.RiskTier

	ScanDescriptionCount atomic.Int32
	ScanArgumentsCount   atomic.Int32
	ScanResponseCount    atomic.Int32
	ClassifyToolCount    atomic.Int32
}

func (m *MockRuleMatcher) ScanDescription(description string) []providers.Finding {
	m.ScanDescriptionCount.Add(1)
	return m.ScanDescriptionResult
}

func (m *MockRuleMatcher) ScanArguments(args map[string]any) []providers.Finding {
	m.ScanArgumentsCount.Add(1)
	return m.ScanArgumentsResult
}

func (m *MockRuleMatcher) ScanResponse(response string) []providers.Finding {
	m.ScanResponseCount.Add(1)
	return m.ScanResponseResult
}

func (m *MockRuleMatcher) ClassifyTool(tool providers.MCPTool, sourceCode string) providers.RiskTier {
	m.ClassifyToolCount.Add(1)
	return m.ClassifyToolResult
}

// MockSASTAnalyzer is a configurable mock for providers.SASTAnalyzer.
type MockSASTAnalyzer struct {
	AnalyzeFileResult      []providers.Finding
	AnalyzeDirectoryResult []providers.Finding
	DetectEgressResult     []providers.EgressFinding

	AnalyzeFileCount      atomic.Int32
	AnalyzeDirectoryCount atomic.Int32
	DetectEgressCount     atomic.Int32
}

func (m *MockSASTAnalyzer) AnalyzeFile(path string, lang providers.Language) []providers.Finding {
	m.AnalyzeFileCount.Add(1)
	return m.AnalyzeFileResult
}

func (m *MockSASTAnalyzer) AnalyzeDirectory(dir string) []providers.Finding {
	m.AnalyzeDirectoryCount.Add(1)
	return m.AnalyzeDirectoryResult
}

func (m *MockSASTAnalyzer) DetectEgress(dir string) []providers.EgressFinding {
	m.DetectEgressCount.Add(1)
	return m.DetectEgressResult
}

// MockReporter is a configurable mock for providers.Reporter.
type MockReporter struct {
	ReportResult []byte
	ReportErr    error
	CallCount    atomic.Int32
}

func (m *MockReporter) Report(findings []providers.Finding, format providers.OutputFormat) ([]byte, error) {
	m.CallCount.Add(1)
	return m.ReportResult, m.ReportErr
}

// MockDepAuditor is a configurable mock for providers.DepAuditor.
type MockDepAuditor struct {
	AuditDirectoryResult []providers.Finding
	CallCount            atomic.Int32
}

func (m *MockDepAuditor) AuditDirectory(dir string) []providers.Finding {
	m.CallCount.Add(1)
	return m.AuditDirectoryResult
}

// MockHookAnalyzer is a configurable mock for providers.HookAnalyzer.
type MockHookAnalyzer struct {
	AnalyzeDirectoryResult []providers.Finding
	CallCount              atomic.Int32
}

func (m *MockHookAnalyzer) AnalyzeDirectory(dir string) []providers.Finding {
	m.CallCount.Add(1)
	return m.AnalyzeDirectoryResult
}

// MockNetProbe is a configurable mock for providers.NetProbe.
type MockNetProbe struct {
	ProbeResult []providers.NetActivity
	ProbeErr    error
	CallCount   atomic.Int32
	// LastCmd and LastArgs capture the most recent Probe invocation for assertions.
	LastCmd  string
	LastArgs []string
}

func (m *MockNetProbe) Probe(cmd string, args []string, _ time.Duration) ([]providers.NetActivity, error) {
	m.CallCount.Add(1)
	m.LastCmd = cmd
	m.LastArgs = args
	return m.ProbeResult, m.ProbeErr
}

// MockPinStore is a configurable mock for providers.PinStore.
type MockPinStore struct {
	PinErr       error
	CheckResult  []providers.PinDiff
	CheckErr     error
	LoadResult   map[string]string
	LoadErr      error

	PinCount   atomic.Int32
	CheckCount atomic.Int32
	LoadCount  atomic.Int32
}

func (m *MockPinStore) Pin(tools []providers.MCPTool) error {
	m.PinCount.Add(1)
	return m.PinErr
}

func (m *MockPinStore) Check(tools []providers.MCPTool) ([]providers.PinDiff, error) {
	m.CheckCount.Add(1)
	return m.CheckResult, m.CheckErr
}

func (m *MockPinStore) Load() (map[string]string, error) {
	m.LoadCount.Add(1)
	return m.LoadResult, m.LoadErr
}
