package app

import (
	"context"
	"log/slog"
	"os"

	"github.com/oxvault/scanner/config"
	"github.com/oxvault/scanner/engines"
	"github.com/oxvault/scanner/providers"
)

// AppInterface defines the contract for the application container
type AppInterface interface {
	Initialize() error
	Shutdown(ctx context.Context) error

	// Engines
	GetScanner() engines.ScannerEngine
	GetPinner() engines.PinEngine

	// Providers (exposed for testing)
	GetMCPClient() providers.MCPClient
	GetRuleMatcher() providers.RuleMatcher
	GetSASTAnalyzer() providers.SASTAnalyzer
	GetDepAuditor() providers.DepAuditor
	GetHookAnalyzer() providers.HookAnalyzer
	GetReporter() providers.Reporter
	GetPinStore() providers.PinStore
	GetResolver() providers.Resolver
	GetNetProbe() providers.NetProbe
	GetSuppressor() providers.Suppressor

	// AIBOM providers (v0.4)
	GetPickleAnalyzer() providers.PickleAnalyzer
	GetONNXValidator() providers.ONNXValidator
	GetSafetensorsValidator() providers.SafetensorsValidator
	GetModelCardChecker() providers.ModelCardChecker
	GetSignatureVerifier() providers.SignatureVerifier
	GetAIBOMComposer() providers.AIBOMComposer

	// Init steps
	InitProviders() error
	InitEngines() error
}

var _ AppInterface = (*App)(nil)

// App is the DI container that wires all providers and engines
type App struct {
	Config *config.Config
	Logger *slog.Logger

	// Providers
	mcpClient    providers.MCPClient
	ruleMatcher  providers.RuleMatcher
	sastAnalyzer providers.SASTAnalyzer
	depAuditor   providers.DepAuditor
	hookAnalyzer providers.HookAnalyzer
	reporter     providers.Reporter
	pinStore     providers.PinStore
	resolver     providers.Resolver
	netProbe     providers.NetProbe
	suppressor   providers.Suppressor

	// AIBOM sub-providers (v0.4) and the composer that fans out to them.
	// Wired in InitProviders. Each is overridable via WithXxx so tests can
	// inject mocks without touching the rest of the container.
	pickleAnalyzer       providers.PickleAnalyzer
	onnxValidator        providers.ONNXValidator
	safetensorsValidator providers.SafetensorsValidator
	modelCardChecker     providers.ModelCardChecker
	signatureVerifier    providers.SignatureVerifier
	aibomComposer        providers.AIBOMComposer

	// Engines
	scanner engines.ScannerEngine
	pinner  engines.PinEngine
}

// AppOption is a functional option for configuring the App
type AppOption func(*App)

func WithMCPClient(c providers.MCPClient) AppOption {
	return func(a *App) { a.mcpClient = c }
}

func WithRuleMatcher(r providers.RuleMatcher) AppOption {
	return func(a *App) { a.ruleMatcher = r }
}

func WithSASTAnalyzer(s providers.SASTAnalyzer) AppOption {
	return func(a *App) { a.sastAnalyzer = s }
}

func WithDepAuditor(d providers.DepAuditor) AppOption {
	return func(a *App) { a.depAuditor = d }
}

func WithHookAnalyzer(h providers.HookAnalyzer) AppOption {
	return func(a *App) { a.hookAnalyzer = h }
}

func WithReporter(r providers.Reporter) AppOption {
	return func(a *App) { a.reporter = r }
}

func WithPinStore(s providers.PinStore) AppOption {
	return func(a *App) { a.pinStore = s }
}

func WithResolver(r providers.Resolver) AppOption {
	return func(a *App) { a.resolver = r }
}

func WithNetProbeOption(p providers.NetProbe) AppOption {
	return func(a *App) { a.netProbe = p }
}

func WithSuppressor(s providers.Suppressor) AppOption {
	return func(a *App) { a.suppressor = s }
}

func WithLogger(l *slog.Logger) AppOption {
	return func(a *App) { a.Logger = l }
}

// ── AIBOM functional options (v0.4) ────────────────────────────────────────

// WithPickleAnalyzerProvider injects a PickleAnalyzer. Named with the
// "Provider" suffix to avoid colliding with providers.WithPickleAnalyzer
// (the composer-level option) — both are valid identifiers in their own
// packages but `WithPickleAnalyzer` would shadow at call sites that import
// both, e.g. tests in cmd/.
func WithPickleAnalyzerProvider(p providers.PickleAnalyzer) AppOption {
	return func(a *App) { a.pickleAnalyzer = p }
}

// WithONNXValidatorProvider injects an ONNXValidator.
func WithONNXValidatorProvider(o providers.ONNXValidator) AppOption {
	return func(a *App) { a.onnxValidator = o }
}

// WithSafetensorsValidatorProvider injects a SafetensorsValidator.
func WithSafetensorsValidatorProvider(s providers.SafetensorsValidator) AppOption {
	return func(a *App) { a.safetensorsValidator = s }
}

// WithModelCardCheckerProvider injects a ModelCardChecker.
func WithModelCardCheckerProvider(m providers.ModelCardChecker) AppOption {
	return func(a *App) { a.modelCardChecker = m }
}

// WithSignatureVerifierProvider injects a SignatureVerifier.
func WithSignatureVerifierProvider(s providers.SignatureVerifier) AppOption {
	return func(a *App) { a.signatureVerifier = s }
}

// WithAIBOMComposer injects an AIBOMComposer. When supplied, the sub-
// provider options above are still honoured for direct getter access (for
// example a test that wants to assert the composer was constructed with a
// specific PickleAnalyzer mock can inject both), but InitProviders will not
// re-wrap the sub-providers into a fresh composer.
func WithAIBOMComposer(c providers.AIBOMComposer) AppOption {
	return func(a *App) { a.aibomComposer = c }
}

// NewApp creates a new App with the given config and options
func NewApp(cfg *config.Config, opts ...AppOption) *App {
	app := &App{
		Config: cfg,
	}

	for _, opt := range opts {
		opt(app)
	}

	return app
}

// Initialize sets up all providers and engines in order
func (a *App) Initialize() error {
	if a.Logger == nil {
		level := slog.LevelWarn
		if a.Config.Verbose {
			level = slog.LevelInfo
		}
		a.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: level,
		}))
	}

	if err := a.InitProviders(); err != nil {
		return err
	}

	if err := a.InitEngines(); err != nil {
		return err
	}

	return nil
}

// InitProviders creates all provider instances (lazy — skips if already set via options)
func (a *App) InitProviders() error {
	if a.resolver == nil {
		a.resolver = providers.NewResolverWithOptions(a.Logger,
			providers.WithHFConfig(providers.HFConfig{
				Token:         a.Config.HF.Token,
				Revision:      a.Config.HF.Revision,
				CacheDir:      a.Config.HF.CacheDir,
				MaxFileBytes:  a.Config.HF.MaxFileBytes,
				MaxCacheBytes: a.Config.HF.MaxCacheBytes,
			}),
		)
	}
	if a.mcpClient == nil {
		a.mcpClient = providers.NewMCPClient(a.Logger)
	}
	if a.ruleMatcher == nil {
		a.ruleMatcher = providers.NewRuleMatcher()
	}
	if a.sastAnalyzer == nil {
		a.sastAnalyzer = providers.NewSASTAnalyzer()
	}
	if a.depAuditor == nil {
		a.depAuditor = providers.NewDepAuditor()
	}
	if a.hookAnalyzer == nil {
		a.hookAnalyzer = providers.NewHookAnalyzer()
	}
	if a.reporter == nil {
		a.reporter = providers.NewReporter()
	}
	if a.pinStore == nil {
		a.pinStore = providers.NewPinStore(a.Config.PinDir)
	}
	if a.netProbe == nil {
		a.netProbe = providers.NewNetProbe(a.Logger)
	}
	if a.suppressor == nil {
		a.suppressor = providers.NewSuppressor()
	}

	// ── AIBOM sub-providers (v0.4) ──────────────────────────────────────────
	//
	// Each sub-provider follows the same lazy-init pattern as the MCP
	// providers above: only create a default when the caller has not
	// supplied one via a functional option. This lets tests stub out an
	// individual analyzer without rewiring the whole container.
	if a.pickleAnalyzer == nil {
		var pickleOpts []providers.PickleAnalyzerOption
		if a.Config != nil && a.Config.AIBOM.MaxPickleBytes > 0 {
			pickleOpts = append(pickleOpts, providers.WithPickleMaxFileBytes(a.Config.AIBOM.MaxPickleBytes))
		}
		a.pickleAnalyzer = providers.NewPickleAnalyzer(pickleOpts...)
	}
	if a.onnxValidator == nil {
		a.onnxValidator = providers.NewONNXValidator()
	}
	if a.safetensorsValidator == nil {
		a.safetensorsValidator = providers.NewSafetensorsValidator()
	}
	if a.modelCardChecker == nil {
		a.modelCardChecker = providers.NewModelCardChecker()
	}
	if a.signatureVerifier == nil {
		var sigOpts []providers.SignatureVerifierOption
		if a.Config != nil {
			if len(a.Config.AIBOM.TrustedIssuers) > 0 {
				sigOpts = append(sigOpts, providers.WithTrustedIssuers(a.Config.AIBOM.TrustedIssuers))
			}
			if len(a.Config.AIBOM.AdditionalTrustedIssuers) > 0 {
				sigOpts = append(sigOpts, providers.WithAdditionalTrustedIssuers(a.Config.AIBOM.AdditionalTrustedIssuers))
			}
		}
		a.signatureVerifier = providers.NewSignatureVerifier(sigOpts...)
	}
	if a.aibomComposer == nil {
		a.aibomComposer = providers.NewComposer(
			providers.WithPickleAnalyzer(a.pickleAnalyzer),
			providers.WithONNXValidator(a.onnxValidator),
			providers.WithSafetensorsValidator(a.safetensorsValidator),
			providers.WithModelCardChecker(a.modelCardChecker),
			providers.WithSignatureVerifier(a.signatureVerifier),
		)
	}
	return nil
}

// InitEngines creates all engine instances, injecting providers
func (a *App) InitEngines() error {
	if a.scanner == nil {
		a.scanner = engines.NewScanner(
			a.resolver,
			a.mcpClient,
			a.ruleMatcher,
			a.sastAnalyzer,
			a.depAuditor,
			a.hookAnalyzer,
			a.reporter,
			a.suppressor,
			a.netProbe,
			a.aibomComposer,
			a.Logger,
		)
	}
	if a.pinner == nil {
		a.pinner = engines.NewPinner(
			a.mcpClient,
			a.pinStore,
			a.Logger,
		)
	}
	return nil
}

// Shutdown cleans up resources
func (a *App) Shutdown(_ context.Context) error {
	return nil
}

// Getters

func (a *App) GetScanner() engines.ScannerEngine       { return a.scanner }
func (a *App) GetPinner() engines.PinEngine            { return a.pinner }
func (a *App) GetMCPClient() providers.MCPClient       { return a.mcpClient }
func (a *App) GetRuleMatcher() providers.RuleMatcher   { return a.ruleMatcher }
func (a *App) GetSASTAnalyzer() providers.SASTAnalyzer { return a.sastAnalyzer }
func (a *App) GetDepAuditor() providers.DepAuditor     { return a.depAuditor }
func (a *App) GetHookAnalyzer() providers.HookAnalyzer { return a.hookAnalyzer }
func (a *App) GetReporter() providers.Reporter         { return a.reporter }
func (a *App) GetPinStore() providers.PinStore         { return a.pinStore }
func (a *App) GetResolver() providers.Resolver         { return a.resolver }
func (a *App) GetNetProbe() providers.NetProbe         { return a.netProbe }
func (a *App) GetSuppressor() providers.Suppressor     { return a.suppressor }

// AIBOM getters (v0.4) — each returns the wired sub-provider so tests and
// integrations can assert / interact with them without reaching into App
// fields directly.

func (a *App) GetPickleAnalyzer() providers.PickleAnalyzer { return a.pickleAnalyzer }
func (a *App) GetONNXValidator() providers.ONNXValidator   { return a.onnxValidator }
func (a *App) GetSafetensorsValidator() providers.SafetensorsValidator {
	return a.safetensorsValidator
}
func (a *App) GetModelCardChecker() providers.ModelCardChecker   { return a.modelCardChecker }
func (a *App) GetSignatureVerifier() providers.SignatureVerifier { return a.signatureVerifier }
func (a *App) GetAIBOMComposer() providers.AIBOMComposer         { return a.aibomComposer }
