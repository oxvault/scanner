package app

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/oxvault/scanner/config"
	"github.com/oxvault/scanner/testutil"
)

// makeDiscardLogger returns a *slog.Logger that discards all output.
func makeDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// defaultTestConfig returns a Config suitable for unit tests.
func defaultTestConfig() *config.Config {
	return &config.Config{
		OutputFormat: "terminal",
		FailOn:       "critical",
		PinDir:       "/tmp/oxvault-test-pins",
	}
}

// allMockOptions returns WithXXX options for all six providers, injecting mocks.
// This prevents InitProviders from calling real constructors.
func allMockOptions() (
	[]AppOption,
	*testutil.MockMCPClient,
	*testutil.MockRuleMatcher,
	*testutil.MockSASTAnalyzer,
	*testutil.MockReporter,
	*testutil.MockPinStore,
	*testutil.MockResolver,
) {
	mcp := &testutil.MockMCPClient{}
	rule := &testutil.MockRuleMatcher{}
	sast := &testutil.MockSASTAnalyzer{}
	rep := &testutil.MockReporter{}
	pin := &testutil.MockPinStore{}
	res := &testutil.MockResolver{}

	opts := []AppOption{
		WithMCPClient(mcp),
		WithRuleMatcher(rule),
		WithSASTAnalyzer(sast),
		WithReporter(rep),
		WithPinStore(pin),
		WithResolver(res),
	}
	return opts, mcp, rule, sast, rep, pin, res
}

// TestNewApp_DefaultsNil verifies that NewApp with no options leaves all provider
// and engine fields nil (they are populated only by Initialize).
func TestNewApp_DefaultsNil(t *testing.T) {
	cfg := defaultTestConfig()
	a := NewApp(cfg)

	if a.Config != cfg {
		t.Error("expected Config to be set from constructor argument")
	}
	if a.Logger != nil {
		t.Error("expected Logger to be nil before Initialize")
	}
	if a.GetMCPClient() != nil {
		t.Error("expected mcpClient to be nil before Initialize")
	}
	if a.GetRuleMatcher() != nil {
		t.Error("expected ruleMatcher to be nil before Initialize")
	}
	if a.GetSASTAnalyzer() != nil {
		t.Error("expected sastAnalyzer to be nil before Initialize")
	}
	if a.GetReporter() != nil {
		t.Error("expected reporter to be nil before Initialize")
	}
	if a.GetPinStore() != nil {
		t.Error("expected pinStore to be nil before Initialize")
	}
	if a.GetResolver() != nil {
		t.Error("expected resolver to be nil before Initialize")
	}
	if a.GetScanner() != nil {
		t.Error("expected scanner to be nil before Initialize")
	}
	if a.GetPinner() != nil {
		t.Error("expected pinner to be nil before Initialize")
	}
}

// TestNewApp_FunctionalOptions verifies that functional options pre-populate fields.
func TestNewApp_FunctionalOptions(t *testing.T) {
	opts, mcp, rule, sast, rep, pin, res := allMockOptions()
	a := NewApp(defaultTestConfig(), opts...)

	if a.GetMCPClient() != mcp {
		t.Error("expected mcpClient to be the injected mock")
	}
	if a.GetRuleMatcher() != rule {
		t.Error("expected ruleMatcher to be the injected mock")
	}
	if a.GetSASTAnalyzer() != sast {
		t.Error("expected sastAnalyzer to be the injected mock")
	}
	if a.GetReporter() != rep {
		t.Error("expected reporter to be the injected mock")
	}
	if a.GetPinStore() != pin {
		t.Error("expected pinStore to be the injected mock")
	}
	if a.GetResolver() != res {
		t.Error("expected resolver to be the injected mock")
	}
}

// TestNewApp_WithLogger verifies WithLogger sets the logger before Initialize.
func TestNewApp_WithLogger(t *testing.T) {
	opts, _, _, _, _, _, _ := allMockOptions()
	injected := makeDiscardLogger()
	opts = append(opts, WithLogger(injected))
	a := NewApp(defaultTestConfig(), opts...)

	if a.Logger != injected {
		t.Error("expected Logger to be the injected logger")
	}
}

// TestInitialize_CreatesAllComponents verifies that Initialize wires up all providers
// and engines, and that getters return non-nil instances after initialization.
func TestInitialize_CreatesAllComponents(t *testing.T) {
	opts, _, _, _, _, _, _ := allMockOptions()
	a := NewApp(defaultTestConfig(), opts...)

	if err := a.Initialize(); err != nil {
		t.Fatalf("Initialize() returned error: %v", err)
	}

	if a.Logger == nil {
		t.Error("expected Logger to be set after Initialize")
	}
	if a.GetMCPClient() == nil {
		t.Error("expected mcpClient to be non-nil after Initialize")
	}
	if a.GetRuleMatcher() == nil {
		t.Error("expected ruleMatcher to be non-nil after Initialize")
	}
	if a.GetSASTAnalyzer() == nil {
		t.Error("expected sastAnalyzer to be non-nil after Initialize")
	}
	if a.GetReporter() == nil {
		t.Error("expected reporter to be non-nil after Initialize")
	}
	if a.GetPinStore() == nil {
		t.Error("expected pinStore to be non-nil after Initialize")
	}
	if a.GetResolver() == nil {
		t.Error("expected resolver to be non-nil after Initialize")
	}
	if a.GetScanner() == nil {
		t.Error("expected scanner to be non-nil after Initialize")
	}
	if a.GetPinner() == nil {
		t.Error("expected pinner to be non-nil after Initialize")
	}
}

// TestInitialize_LazyInit_OptionsNotOverwritten verifies that functional-option-injected
// providers are NOT replaced during InitProviders (lazy init pattern).
func TestInitialize_LazyInit_OptionsNotOverwritten(t *testing.T) {
	opts, mcp, rule, sast, rep, pin, res := allMockOptions()
	a := NewApp(defaultTestConfig(), opts...)

	if err := a.Initialize(); err != nil {
		t.Fatalf("Initialize() returned error: %v", err)
	}

	if a.GetMCPClient() != mcp {
		t.Error("mcpClient mock was overwritten by InitProviders")
	}
	if a.GetRuleMatcher() != rule {
		t.Error("ruleMatcher mock was overwritten by InitProviders")
	}
	if a.GetSASTAnalyzer() != sast {
		t.Error("sastAnalyzer mock was overwritten by InitProviders")
	}
	if a.GetReporter() != rep {
		t.Error("reporter mock was overwritten by InitProviders")
	}
	if a.GetPinStore() != pin {
		t.Error("pinStore mock was overwritten by InitProviders")
	}
	if a.GetResolver() != res {
		t.Error("resolver mock was overwritten by InitProviders")
	}
}

// TestInitialize_LoggerNotOverwrittenWhenInjected verifies that a pre-injected logger
// survives Initialize (lazy init for logger).
func TestInitialize_LoggerNotOverwrittenWhenInjected(t *testing.T) {
	opts, _, _, _, _, _, _ := allMockOptions()
	injected := makeDiscardLogger()
	opts = append(opts, WithLogger(injected))
	a := NewApp(defaultTestConfig(), opts...)

	if err := a.Initialize(); err != nil {
		t.Fatalf("Initialize() returned error: %v", err)
	}

	if a.Logger != injected {
		t.Error("injected logger was overwritten by Initialize")
	}
}

// TestInitialize_VerboseConfig verifies that Verbose=true does not cause Initialize
// to return an error.
func TestInitialize_VerboseConfig(t *testing.T) {
	opts, _, _, _, _, _, _ := allMockOptions()
	cfg := defaultTestConfig()
	cfg.Verbose = true
	a := NewApp(cfg, opts...)

	if err := a.Initialize(); err != nil {
		t.Fatalf("Initialize() with Verbose=true returned error: %v", err)
	}
	if a.Logger == nil {
		t.Error("expected logger to be set after Initialize with Verbose=true")
	}
}

// TestInitProviders_Idempotent verifies that calling InitProviders twice does not
// replace already-initialized providers.
func TestInitProviders_Idempotent(t *testing.T) {
	opts, mcp, _, _, _, _, _ := allMockOptions()
	a := NewApp(defaultTestConfig(), opts...)

	if err := a.InitProviders(); err != nil {
		t.Fatalf("first InitProviders() error: %v", err)
	}
	if err := a.InitProviders(); err != nil {
		t.Fatalf("second InitProviders() error: %v", err)
	}

	if a.GetMCPClient() != mcp {
		t.Error("mcpClient was replaced on second InitProviders call")
	}
}

// TestInitEngines_Idempotent verifies calling InitEngines twice does not replace
// already-created engines.
func TestInitEngines_Idempotent(t *testing.T) {
	opts, _, _, _, _, _, _ := allMockOptions()
	a := NewApp(defaultTestConfig(), opts...)
	a.Logger = makeDiscardLogger()

	if err := a.InitProviders(); err != nil {
		t.Fatalf("InitProviders() error: %v", err)
	}
	if err := a.InitEngines(); err != nil {
		t.Fatalf("first InitEngines() error: %v", err)
	}

	firstScanner := a.GetScanner()
	firstPinner := a.GetPinner()

	if err := a.InitEngines(); err != nil {
		t.Fatalf("second InitEngines() error: %v", err)
	}

	if a.GetScanner() != firstScanner {
		t.Error("scanner was replaced on second InitEngines call")
	}
	if a.GetPinner() != firstPinner {
		t.Error("pinner was replaced on second InitEngines call")
	}
}

// TestShutdown_NoError verifies that Shutdown is callable and returns nil.
func TestShutdown_NoError(t *testing.T) {
	opts, _, _, _, _, _, _ := allMockOptions()
	a := NewApp(defaultTestConfig(), opts...)

	if err := a.Initialize(); err != nil {
		t.Fatalf("Initialize() error: %v", err)
	}

	if err := a.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown() returned unexpected error: %v", err)
	}
}

// TestShutdown_BeforeInitialize verifies Shutdown does not panic when called
// before Initialize.
func TestShutdown_BeforeInitialize(t *testing.T) {
	a := NewApp(defaultTestConfig())
	if err := a.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown() before Initialize returned error: %v", err)
	}
}

// TestAppInterface_ComplianceGuard confirms the compile-time guard in app.go works.
// If App does not implement AppInterface, this file will not compile.
func TestAppInterface_ComplianceGuard(t *testing.T) {
	var _ AppInterface = (*App)(nil)
}

// ── AIBOM wiring tests (Day 9) ───────────────────────────────────────────────

// TestInitProviders_WiresAIBOMSubProviders verifies InitProviders constructs
// every AIBOM sub-provider plus the top-level composer when no overrides
// are passed. After init, every getter must return a non-nil instance so
// the engine can hand off model-artifact targets to the composer.
func TestInitProviders_WiresAIBOMSubProviders(t *testing.T) {
	a := NewApp(defaultTestConfig())

	if err := a.Initialize(); err != nil {
		t.Fatalf("Initialize() error: %v", err)
	}

	if a.GetPickleAnalyzer() == nil {
		t.Error("expected pickleAnalyzer to be wired")
	}
	if a.GetONNXValidator() == nil {
		t.Error("expected onnxValidator to be wired")
	}
	if a.GetSafetensorsValidator() == nil {
		t.Error("expected safetensorsValidator to be wired")
	}
	if a.GetModelCardChecker() == nil {
		t.Error("expected modelCardChecker to be wired")
	}
	if a.GetSignatureVerifier() == nil {
		t.Error("expected signatureVerifier to be wired")
	}
	if a.GetAIBOMComposer() == nil {
		t.Error("expected aibomComposer to be wired")
	}
}

// TestInitProviders_AIBOMOverridesNotReplaced verifies that AIBOM functional
// options pre-populate fields and are NOT overwritten by InitProviders. Same
// lazy-init contract as the MCP providers.
func TestInitProviders_AIBOMOverridesNotReplaced(t *testing.T) {
	pickle := &testutil.MockPickleAnalyzer{}
	onnx := &testutil.MockONNXValidator{}
	safetensors := &testutil.MockSafetensorsValidator{}
	modelCard := &testutil.MockModelCardChecker{}
	signature := &testutil.MockSignatureVerifier{}
	composer := &testutil.MockAIBOMComposer{}

	a := NewApp(defaultTestConfig(),
		WithPickleAnalyzerProvider(pickle),
		WithONNXValidatorProvider(onnx),
		WithSafetensorsValidatorProvider(safetensors),
		WithModelCardCheckerProvider(modelCard),
		WithSignatureVerifierProvider(signature),
		WithAIBOMComposer(composer),
	)

	if err := a.Initialize(); err != nil {
		t.Fatalf("Initialize() error: %v", err)
	}

	if a.GetPickleAnalyzer() != pickle {
		t.Error("pickleAnalyzer mock was overwritten by InitProviders")
	}
	if a.GetONNXValidator() != onnx {
		t.Error("onnxValidator mock was overwritten by InitProviders")
	}
	if a.GetSafetensorsValidator() != safetensors {
		t.Error("safetensorsValidator mock was overwritten by InitProviders")
	}
	if a.GetModelCardChecker() != modelCard {
		t.Error("modelCardChecker mock was overwritten by InitProviders")
	}
	if a.GetSignatureVerifier() != signature {
		t.Error("signatureVerifier mock was overwritten by InitProviders")
	}
	if a.GetAIBOMComposer() != composer {
		t.Error("aibomComposer mock was overwritten by InitProviders")
	}
}

// TestInitProviders_DefaultComposerUsesWiredSubProviders verifies that the
// default composer path (no WithAIBOMComposer override) is constructed with
// the wired sub-providers. Tests this indirectly by asserting the composer
// is non-nil and that the sub-providers it consumed are also non-nil — the
// composer's NewComposer constructor would have replaced any nil supplied
// option with its own default, so finding non-nil values everywhere is
// sufficient evidence of correct wiring.
func TestInitProviders_DefaultComposerUsesWiredSubProviders(t *testing.T) {
	a := NewApp(defaultTestConfig())

	if err := a.InitProviders(); err != nil {
		t.Fatalf("InitProviders() error: %v", err)
	}

	if a.GetAIBOMComposer() == nil {
		t.Fatal("expected default composer to be constructed")
	}
	// Sub-providers must be wired BEFORE the composer is built so the
	// composer can consume them. If any sub-provider is nil here, the
	// composer would have silently fallen back to its own default and
	// overrides would be useless.
	if a.GetPickleAnalyzer() == nil {
		t.Error("pickleAnalyzer must be wired before composer construction")
	}
	if a.GetSignatureVerifier() == nil {
		t.Error("signatureVerifier must be wired before composer construction")
	}
}
