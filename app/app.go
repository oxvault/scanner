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
	GetReporter() providers.Reporter
	GetPinStore() providers.PinStore
	GetResolver() providers.Resolver

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
	reporter     providers.Reporter
	pinStore     providers.PinStore
	resolver     providers.Resolver

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

func WithReporter(r providers.Reporter) AppOption {
	return func(a *App) { a.reporter = r }
}

func WithPinStore(s providers.PinStore) AppOption {
	return func(a *App) { a.pinStore = s }
}

func WithResolver(r providers.Resolver) AppOption {
	return func(a *App) { a.resolver = r }
}

func WithLogger(l *slog.Logger) AppOption {
	return func(a *App) { a.Logger = l }
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
		a.resolver = providers.NewResolver(a.Logger)
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
	if a.reporter == nil {
		a.reporter = providers.NewReporter()
	}
	if a.pinStore == nil {
		a.pinStore = providers.NewPinStore(a.Config.PinDir)
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
			a.reporter,
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

func (a *App) GetScanner() engines.ScannerEngine   { return a.scanner }
func (a *App) GetPinner() engines.PinEngine         { return a.pinner }
func (a *App) GetMCPClient() providers.MCPClient    { return a.mcpClient }
func (a *App) GetRuleMatcher() providers.RuleMatcher { return a.ruleMatcher }
func (a *App) GetSASTAnalyzer() providers.SASTAnalyzer { return a.sastAnalyzer }
func (a *App) GetReporter() providers.Reporter       { return a.reporter }
func (a *App) GetPinStore() providers.PinStore        { return a.pinStore }
func (a *App) GetResolver() providers.Resolver        { return a.resolver }
