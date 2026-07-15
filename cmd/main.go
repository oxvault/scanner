package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/oxvault/scanner/app"
	"github.com/oxvault/scanner/config"
	"github.com/oxvault/scanner/engines"
	"github.com/oxvault/scanner/internal/lastscan"
	"github.com/oxvault/scanner/internal/userconfig"
	iversion "github.com/oxvault/scanner/internal/version"
	"github.com/oxvault/scanner/providers"
	"github.com/spf13/cobra"
)

// persistLastScan saves the most recent scan to ~/.oxvault/last-scan.json so
// `oxvault push` can upload it without re-running. Best-effort.
func persistLastScan(target string, report *engines.ScanReport, started, completed time.Time) error {
	artifactName := deriveArtifactName(target)
	artifactType := artifactTypeFor(report.Package)
	f := lastscan.FromReport(target, artifactName, artifactType, started, completed, version, report.Findings)
	return lastscan.Save(f)
}

// artifactTypeFor maps the resolver's PackageKind onto the platform's
// dashboard artifact_type ("mcp" / "model" / "rag"). A nil package or any
// unrecognised kind defaults to "mcp" to preserve the historical behaviour
// of the scanner (MCP was the only artifact class before v0.4).
//
// Earlier this lived inline in persistLastScan as a stringified switch on
// hyphenated literals like "model-artifact" — but the typed constants are
// what we actually care about, and the explicit default makes the
// fallback intentional and testable.
func artifactTypeFor(pkg *providers.ResolvedPackage) string {
	if pkg == nil {
		return "mcp"
	}
	switch pkg.Kind {
	case providers.KindModelArtifact, providers.KindModelDirectory:
		return "model"
	case providers.KindRAGCorpus:
		return "rag"
	default:
		return "mcp"
	}
}

// deriveArtifactName turns a scan target ("./node_modules/asana-mcp",
// "@company/mcp-server", "github:user/repo") into a stable display name used
// as the (workspace_id, name) upsert key on the platform.
func deriveArtifactName(target string) string {
	t := strings.TrimSpace(target)
	switch {
	// Keep the scheme — the name is the agent's rescan target; stripping "github:" made it look local and broke remote rescans.
	case strings.HasPrefix(t, "github:") || strings.HasPrefix(t, "hf:") || strings.HasPrefix(t, "@"):
		return t
	default:
		return filepath.Base(filepath.Clean(t))
	}
}

// version defaults to the canonical version from internal/version but can be
// overridden via ldflags:
//
//	go build -ldflags "-X github.com/oxvault/scanner/internal/version.Version=x.y.z"
var version = iversion.Version

func main() {
	root := &cobra.Command{
		Use:     "oxvault",
		Short:   "Security scanner for the AI supply chain — MCP servers, ML models & more",
		Version: version,
		Run: func(cmd *cobra.Command, args []string) {
			printLogo()
			_ = cmd.Help()
		},
	}

	root.AddCommand(
		newScanCmd(),
		newPinCmd(),
		newCheckCmd(),
		newLoginCmd(),
		newPushCmd(),
		newInitCmd(),
		newAgentCmd(),
		newUpgradeCmd(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func printLogo() {
	dim := color.New(color.Faint)
	bold := color.New(color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)

	fmt.Fprintf(os.Stderr, "\n  %s %s  %s\n",
		cyan.Sprint("◉"),
		bold.Sprint("Oxvault Scanner"),
		dim.Sprint(version))
	fmt.Fprintf(os.Stderr, "  %s\n\n",
		dim.Sprint("Security scanner for the AI supply chain — MCP servers, ML models & more"))
}

// printProgress writes a styled progress line to stderr.
// Writing to stderr keeps stdout clean for --format=json|sarif piping.
func printProgress(step, total int, msg string) {
	dim := color.New(color.Faint)
	counter := color.New(color.FgCyan, color.Bold).Sprintf("[%d/%d]", step, total)
	fmt.Fprintf(os.Stderr, "  %s %s\n", counter, dim.Sprint(msg))
}

// printBanner writes the scanner header and target to stderr.
func printBanner(target string) {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	cyan := color.New(color.FgCyan, color.Bold)

	fmt.Fprintf(os.Stderr, "\n  %s %s\n\n",
		cyan.Sprint("◉"),
		bold.Sprintf("Oxvault Scanner %s", version))

	fmt.Fprintf(os.Stderr, "  %s %s\n\n",
		dim.Sprint("Scanning:"),
		bold.Sprint(target))
}

// parseMinConfidence converts a string flag value to a Confidence level.
// Unknown values fall back to ConfidenceLow (show all).
func parseMinConfidence(s string) providers.Confidence {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return providers.ConfidenceHigh
	case "medium":
		return providers.ConfidenceMedium
	default:
		return providers.ConfidenceLow
	}
}

// filterByConfidence removes findings below the given minimum confidence level.
func filterByConfidence(findings []providers.Finding, min providers.Confidence) []providers.Finding {
	if min <= providers.ConfidenceLow {
		return findings
	}
	out := make([]providers.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Confidence >= min {
			out = append(out, f)
		}
	}
	return out
}

func newScanCmd() *cobra.Command {
	var (
		format         string
		failOn         string
		minConfidence  string
		verbose        bool
		skipSAST       bool
		skipManifest   bool
		skipEgress     bool
		probeNetwork   bool
		noColor        bool
		configPath     string
		showSuppressed bool

		// HF (v0.4 AIBOM)
		hfToken         string
		hfRevision      string
		hfCacheDir      string
		hfMaxFileBytes  int64
		hfMaxCacheBytes int64

		// AIBOM sub-provider toggles (v0.4)
		skipPickle      bool
		skipONNX        bool
		skipSafetensors bool
		skipModelCard   bool
		skipSignature   bool

		// AIBOM tuning (v0.4)
		maxPickleBytes              int64
		trustedIssuersCSV           string
		additionalTrustedIssuersCSV string

		// Push integration — auto-upload to the platform after the scan.
		pushAfterScan  bool
		pushAPIKey     string
		pushAPIURL     string
		pushConsoleURL string
		pushQuiet      bool
	)

	cmd := &cobra.Command{
		Use:   "scan [target]",
		Short: "Scan MCP servers and AI model artifacts for security vulnerabilities",
		Long: `Scan MCP servers, npm packages, GitHub repos, or ML model artifacts for
security vulnerabilities.

Run with no target to scan every MCP server already installed on this machine
(Claude Code, Claude Desktop, Cursor, VS Code, Windsurf) — same as --config auto.

Targets:
  (none)                         Auto-detect and scan all installed MCP servers
  ./my-server                    Local project directory or file
  @company/mcp-server            npm package (downloaded to temp dir)
  github:user/repo               GitHub repository (cloned)
  github:user/repo/sub/dir       GitHub sub-directory (sparse-fetched)

Config-based scanning:
  --config <path>                Scan all servers in a specific config file
  --config auto                  Auto-detect all known MCP config files`,
		Args: cobra.RangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// No target and no --config: scan everything already installed.
			if configPath == "" && len(args) == 0 {
				configPath = "auto"
			}

			cfg := config.DefaultConfig()
			cfg.OutputFormat = providers.OutputFormat(format)
			cfg.FailOn = failOn
			cfg.Verbose = verbose
			cfg.SkipSAST = skipSAST
			cfg.SkipManifest = skipManifest
			cfg.SkipEgress = skipEgress
			cfg.ProbeNetwork = probeNetwork
			cfg.NoColor = noColor
			cfg.ShowSuppressed = showSuppressed

			// HF resolver options (v0.4 AIBOM)
			if hfToken != "" {
				cfg.HF.Token = hfToken
			}
			if hfRevision != "" {
				cfg.HF.Revision = hfRevision
			}
			if hfCacheDir != "" {
				cfg.HF.CacheDir = hfCacheDir
			}
			if hfMaxFileBytes > 0 {
				cfg.HF.MaxFileBytes = hfMaxFileBytes
			}
			if hfMaxCacheBytes > 0 {
				cfg.HF.MaxCacheBytes = hfMaxCacheBytes
			}

			// AIBOM tuning (v0.4)
			if maxPickleBytes > 0 {
				cfg.AIBOM.MaxPickleBytes = maxPickleBytes
			}
			if issuers := splitAndTrimCSV(trustedIssuersCSV); len(issuers) > 0 {
				cfg.AIBOM.TrustedIssuers = issuers
			}
			if issuers := splitAndTrimCSV(additionalTrustedIssuersCSV); len(issuers) > 0 {
				cfg.AIBOM.AdditionalTrustedIssuers = issuers
			}

			// Apply no-color globally before any output
			if noColor || cfg.OutputFormat != providers.FormatTerminal {
				color.NoColor = true
			}

			application := app.NewApp(cfg)
			if err := application.Initialize(); err != nil {
				return fmt.Errorf("initialize: %w", err)
			}

			scanOpts := engines.ScanOptions{
				SkipSAST:        cfg.SkipSAST,
				SkipManifest:    cfg.SkipManifest,
				SkipEgress:      cfg.SkipEgress,
				ProbeNetwork:    cfg.ProbeNetwork,
				FailOn:          cfg.FailOn,
				SkipPickle:      skipPickle,
				SkipONNX:        skipONNX,
				SkipSafetensors: skipSafetensors,
				SkipModelCard:   skipModelCard,
				SkipSignature:   skipSignature,
			}

			minConf := parseMinConfidence(minConfidence)

			pushOpts := pushOptions{
				enabled:    pushAfterScan,
				apiKey:     pushAPIKey,
				apiURL:     pushAPIURL,
				consoleURL: pushConsoleURL,
				quiet:      pushQuiet,
			}
			// [push].auto in ~/.oxvault/config.toml flips --push on by default.
			// An explicit --push=false on the command line still wins because
			// it's already been parsed into pushAfterScan above; userconfig
			// only fills in when the flag was left at its default.
			//
			// Auto-push is gated to terminal output mode so CI / scripted
			// invocations (--format=json|sarif) keep stdout pure and don't
			// accidentally upload scans against whatever API key is set in
			// the runner's env. Pass --push explicitly to override.
			isTerminalFormat := cfg.OutputFormat == providers.FormatTerminal
			if !pushOpts.enabled && !cmd.Flags().Changed("push") && isTerminalFormat {
				if uc, err := userconfig.Load(); err == nil && uc != nil && uc.Push.Auto {
					pushOpts.enabled = true
				}
			}

			// --config mode: scan all servers from one or more config files
			if configPath != "" {
				return runConfigScan(application, cfg, scanOpts, configPath, minConf, pushOpts)
			}

			// Traditional single-target mode
			return runSingleScan(application, cfg, scanOpts, args[0], minConf, pushOpts)
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "terminal", "Output format: terminal, sarif, json")
	cmd.Flags().StringVar(&failOn, "fail-on", "critical", "Exit non-zero at this severity: critical, high, warning, info")
	cmd.Flags().StringVar(&minConfidence, "min-confidence", "low", "Minimum confidence level to report: low, medium, high")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	cmd.Flags().BoolVar(&skipSAST, "skip-sast", false, "Skip source code analysis")
	cmd.Flags().BoolVar(&skipManifest, "skip-manifest", false, "Skip tool description analysis")
	cmd.Flags().BoolVar(&skipEgress, "skip-egress", false, "Skip network egress detection")
	cmd.Flags().BoolVar(&probeNetwork, "probe-network", false, "Spawn server and monitor outbound connections (requires strace on Linux)")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable color output (for CI or piping)")
	cmd.Flags().StringVar(&configPath, "config", "", "MCP client config file to scan (path or \"auto\"; auto is the default when no target is given)")
	cmd.Flags().BoolVar(&showSuppressed, "show-suppressed", false, "Print suppressed findings in a separate section")

	// HF resolver flags (v0.4 AIBOM)
	cmd.Flags().StringVar(&hfToken, "hf-token", "", "Hugging Face API token (env: HF_TOKEN)")
	cmd.Flags().StringVar(&hfRevision, "hf-revision", "", "Hugging Face revision/branch/SHA (default: main)")
	cmd.Flags().StringVar(&hfCacheDir, "hf-cache-dir", "", "Hugging Face cache directory (default: ~/.cache/oxvault/hf)")
	cmd.Flags().Int64Var(&hfMaxFileBytes, "hf-max-file-bytes", 0, "Max bytes per HF file (default: 4 GiB)")
	cmd.Flags().Int64Var(&hfMaxCacheBytes, "hf-max-cache-bytes", 0, "Max total HF cache bytes (default: 16 GiB)")

	// AIBOM sub-provider toggles (v0.4) — each flag drops findings produced
	// by the matching sub-provider after the composer returns. The composer
	// itself stays untouched, mirroring how SkipSAST / SkipManifest gate
	// MCP-side analyzers.
	cmd.Flags().BoolVar(&skipPickle, "skip-pickle", false, "Skip pickle disassembler findings (aibom-pickle-*)")
	cmd.Flags().BoolVar(&skipONNX, "skip-onnx", false, "Skip ONNX validator findings (aibom-onnx-*)")
	cmd.Flags().BoolVar(&skipSafetensors, "skip-safetensors", false, "Skip safetensors validator findings (aibom-safetensors-*)")
	cmd.Flags().BoolVar(&skipModelCard, "skip-modelcard", false, "Skip model card checker findings (aibom-modelcard-*)")
	cmd.Flags().BoolVar(&skipSignature, "skip-signature", false, "Skip signature verifier findings (aibom-signature-*)")

	// AIBOM tuning (v0.4)
	cmd.Flags().Int64Var(&maxPickleBytes, "max-pickle-size", 0, "Max bytes for pickle disassembly (default: 2 GiB; values above the default are clamped)")
	cmd.Flags().StringVar(&trustedIssuersCSV, "trusted-issuers", "", "Comma-separated OIDC issuer URLs that REPLACE the default trusted-issuer list for signature verification")
	cmd.Flags().StringVar(&additionalTrustedIssuersCSV, "additional-trusted-issuers", "", "Comma-separated OIDC issuer URLs that MERGE into the default trusted-issuer list")

	// Push integration — explicit opt-in to upload the scan to the Oxvault
	// platform after a successful run. Free tier stays local-only.
	cmd.Flags().BoolVar(&pushAfterScan, "push", false, "After the scan completes, upload the result to the Oxvault platform (requires OXVAULT_API_KEY)")
	cmd.Flags().StringVar(&pushAPIKey, "api-key", "", "Workspace API key for --push (default: $OXVAULT_API_KEY)")
	cmd.Flags().StringVar(&pushAPIURL, "api-url", "", "Platform base URL for --push (default: $OXVAULT_API_URL or https://platform.oxvault.dev)")
	cmd.Flags().StringVar(&pushConsoleURL, "console-url", "", "Console base URL for the success link when --push is set")
	cmd.Flags().BoolVar(&pushQuiet, "push-quiet", false, "Suppress the push success banner (only meaningful with --push)")

	return cmd
}

// splitAndTrimCSV splits a comma-separated string and trims whitespace from
// each element. Empty entries are dropped. Used by --trusted-issuers and
// --additional-trusted-issuers so users can paste a list directly without
// worrying about stray spaces.
func splitAndTrimCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// pushOptions carries the post-scan upload flags through runSingleScan /
// runConfigScan so each path can fire `oxvault push` without re-parsing
// cobra flags.
type pushOptions struct {
	enabled    bool
	apiKey     string
	apiURL     string
	consoleURL string
	quiet      bool
}

// pushAfterPersist uploads the just-saved last-scan.json to the platform.
// Called from the success paths of runSingleScan / runConfigScan when
// --push was passed. Errors here surface but do not unwind the scan exit
// code — the local result is still authoritative.
func pushAfterPersist(opts pushOptions) error {
	scan, err := lastscan.Load()
	if err != nil {
		return fmt.Errorf("read last-scan.json: %w", err)
	}
	if scan == nil {
		return fmt.Errorf("no last scan on disk to push")
	}
	return runPushFlow(scan, opts.apiKey, opts.apiURL, opts.consoleURL, opts.quiet)
}

// runSingleScan handles the traditional `oxvault scan <target>` path.
func runSingleScan(application *app.App, cfg *config.Config, opts engines.ScanOptions, target string, minConf providers.Confidence, push pushOptions) error {
	if cfg.OutputFormat == providers.FormatTerminal {
		printBanner(target)

		totalSteps := 4
		if cfg.SkipSAST {
			totalSteps--
		}
		if cfg.SkipEgress {
			totalSteps--
		}
		if cfg.SkipManifest {
			totalSteps--
		}
		if cfg.ProbeNetwork {
			totalSteps++
		}

		step := 1
		printProgress(step, totalSteps, "Resolving target...")
		step++
		if !cfg.SkipSAST {
			printProgress(step, totalSteps, "Analyzing source code...")
			step++
		}
		if !cfg.SkipEgress {
			printProgress(step, totalSteps, "Detecting network egress...")
			step++
		}
		if !cfg.SkipManifest {
			printProgress(step, totalSteps, "Scanning tool descriptions...")
			step++
		}
		if cfg.ProbeNetwork {
			printProgress(step, totalSteps, "Running runtime network probe...")
			step++
		}
		_ = step
		fmt.Fprintln(os.Stderr)
	}

	startedAt := time.Now().UTC()
	report, err := application.GetScanner().Scan(target, opts)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	completedAt := time.Now().UTC()

	report.Findings = filterByConfidence(report.Findings, minConf)

	// Persist for `oxvault push`. Best-effort — failure to write the cache
	// must not fail the scan itself.
	if perr := persistLastScan(target, report, startedAt, completedAt); perr != nil {
		fmt.Fprintf(os.Stderr, "  %s\n", color.New(color.Faint).Sprintf("(warning: could not persist last scan: %v)", perr))
	}

	output, err := application.GetReporter().Report(report.Findings, cfg.OutputFormat)
	if err != nil {
		return fmt.Errorf("report: %w", err)
	}

	fmt.Print(string(output))

	// Print suppressed findings section when requested (terminal format only)
	if cfg.ShowSuppressed && len(report.Suppressed) > 0 && cfg.OutputFormat == providers.FormatTerminal {
		printSuppressedSection(report.Suppressed)
	}

	// Append suppressed count to terminal summary line when some were filtered
	if len(report.Suppressed) > 0 && cfg.OutputFormat == providers.FormatTerminal {
		dim := color.New(color.Faint)
		fmt.Printf("  %s\n\n", dim.Sprintf("(%d suppressed — run with --show-suppressed to view)", len(report.Suppressed)))
	}

	// --push: upload the just-persisted scan to the platform. Done after
	// terminal output so the user sees their findings first; failure here
	// is surfaced but doesn't override the scan's own exit code.
	if push.enabled {
		if err := pushAfterPersist(push); err != nil {
			fmt.Fprintf(os.Stderr, "  %s %s\n",
				color.New(color.FgRed, color.Bold).Sprint("✗"),
				fmt.Sprintf("push failed: %v", err))
		}
	}

	if report.HasSeverity(cfg.FailOn) {
		os.Exit(1)
	}
	return nil
}

// printSuppressedSection writes all suppressed findings under a styled header.
func printSuppressedSection(findings []providers.Finding) {
	dim := color.New(color.Faint)
	bold := color.New(color.Bold)
	header := color.New(color.Bold)

	const totalWidth = 60
	prefix := "  ── "
	title := "Suppressed Findings"
	suffix := " "
	fill := strings.Repeat("─", totalWidth-len(prefix)-len(title)-len(suffix))
	fmt.Printf("\n%s\n\n", header.Sprintf("%s%s%s%s", prefix, title, suffix, fill))

	for _, f := range findings {
		location := ""
		if f.File != "" {
			if f.Line > 0 {
				location = fmt.Sprintf("%s:%d", f.File, f.Line)
			} else {
				location = f.File
			}
		} else if f.Tool != "" {
			location = fmt.Sprintf("Tool: %s", f.Tool)
		}
		fmt.Printf("  %s %s",
			dim.Sprint("○"),
			bold.Sprint(f.Rule),
		)
		if location != "" {
			fmt.Printf(" %s", dim.Sprint(location))
		}
		fmt.Println()
	}
	fmt.Println()
}

// runConfigScan handles `oxvault scan --config <path|auto>`.
// It discovers all configured MCP servers, scans each one individually,
// and aggregates findings with per-server headers in terminal mode.
func runConfigScan(application *app.App, cfg *config.Config, opts engines.ScanOptions, configPath string, minConf providers.Confidence, push pushOptions) error {
	result, err := config.Discover(configPath)
	if err != nil {
		return fmt.Errorf("discover config: %w", err)
	}

	if len(result.Servers) == 0 {
		if configPath == "auto" {
			fmt.Fprintf(os.Stderr, "  No installed MCP servers found.\n\n"+
				"  Point at a target directly:  oxvault scan github:user/repo\n"+
				"  Or a specific config file:   oxvault scan --config <path>\n")
		} else {
			fmt.Fprintf(os.Stderr, "  No MCP servers found in config.\n")
		}
		return nil
	}

	if cfg.OutputFormat == providers.FormatTerminal {
		bold := color.New(color.Bold)
		dim := color.New(color.Faint)
		cyan := color.New(color.FgCyan, color.Bold)

		fmt.Fprintf(os.Stderr, "\n  %s %s\n\n",
			cyan.Sprint("◉"),
			bold.Sprintf("Oxvault Scanner %s", version))

		sourceLabel := configPath
		if configPath == "auto" && len(result.SourceFiles) > 0 {
			sourceLabel = fmt.Sprintf("%d config file(s)", len(result.SourceFiles))
		}
		fmt.Fprintf(os.Stderr, "  %s %s\n\n",
			dim.Sprint("Scanning:"),
			bold.Sprintf("%d servers from %s", len(result.Servers), sourceLabel))
	}

	var allFindings []providers.Finding
	anyFailed := false

	for _, srv := range result.Servers {
		// Remote (http/sse) servers expose only a URL — nothing local to scan.
		if srv.Command == "" {
			if cfg.OutputFormat == providers.FormatTerminal {
				transport := srv.Transport
				if transport == "" {
					transport = "remote"
				}
				fmt.Fprintf(os.Stderr, "  %s %s %s\n\n",
					color.New(color.FgYellow).Sprint("──"),
					color.New(color.Bold).Sprint(srv.Name),
					color.New(color.Faint).Sprintf("(%s transport — static scan not applicable)", transport))
			}
			continue
		}

		startedAt := time.Now().UTC()
		// Build the target string that the resolver understands.
		// For config-defined servers the command IS the target — we pass it
		// through as a synthetic "command:args" target and let the scanner
		// treat it as a local/npm/github ref based on the command value.
		// We use the command + first arg to form a human-readable label.
		target := buildTargetFromServer(srv)

		if cfg.OutputFormat == providers.FormatTerminal {
			dim := color.New(color.Faint)
			bold := color.New(color.Bold)
			fmt.Fprintf(os.Stderr, "  %s %s %s\n\n",
				color.New(color.FgCyan).Sprint("──"),
				bold.Sprint(srv.Name),
				dim.Sprintf("(%s)", target))
		}

		report, scanErr := application.GetScanner().Scan(target, opts)
		if scanErr != nil {
			fmt.Fprintf(os.Stderr, "  scan error for %q: %v\n\n", srv.Name, scanErr)
			continue
		}
		completedAt := time.Now().UTC()

		// Filter by minimum confidence before reporting
		report.Findings = filterByConfidence(report.Findings, minConf)

		// --push: persist + upload this server's scan as its own artifact
		// before moving on. Failures are surfaced but don't abort the loop.
		if push.enabled {
			if perr := persistLastScan(target, report, startedAt, completedAt); perr != nil {
				fmt.Fprintf(os.Stderr, "  %s\n", color.New(color.Faint).Sprintf("(warning: persist last scan: %v)", perr))
			} else if uerr := pushAfterPersist(push); uerr != nil {
				fmt.Fprintf(os.Stderr, "  %s push failed for %q: %v\n",
					color.New(color.FgRed, color.Bold).Sprint("✗"),
					srv.Name, uerr)
			}
		}

		// Tag every finding with the server name for aggregation display
		for i := range report.Findings {
			if report.Findings[i].Tool == "" {
				report.Findings[i].Tool = srv.Name
			}
		}

		if cfg.OutputFormat == providers.FormatTerminal {
			output, repErr := application.GetReporter().Report(report.Findings, cfg.OutputFormat)
			if repErr != nil {
				return fmt.Errorf("report %q: %w", srv.Name, repErr)
			}
			fmt.Print(string(output))
			fmt.Fprintln(os.Stderr)
		}

		allFindings = append(allFindings, report.Findings...)
		if report.HasSeverity(opts.FailOn) {
			anyFailed = true
		}
	}

	// For non-terminal formats, emit a single combined report at the end.
	if cfg.OutputFormat != providers.FormatTerminal {
		output, err := application.GetReporter().Report(allFindings, cfg.OutputFormat)
		if err != nil {
			return fmt.Errorf("report: %w", err)
		}
		fmt.Print(string(output))
	} else {
		// Print summary line
		printConfigSummary(allFindings)
	}

	if anyFailed {
		os.Exit(1)
	}
	return nil
}

// buildTargetFromServer constructs a scan-target string from an MCPServerConfig.
// When the command is "npx" with args like ["-y", "@pkg/name"], the target is
// the npm package name so the resolver can download it. For other commands the
// target is built from command + args as a displayable label; the scanner will
// attempt to treat it as a local path and fall back gracefully.
func buildTargetFromServer(srv config.MCPServerConfig) string {
	if srv.Command == "npx" {
		// Find the first arg that looks like a package name (skip flags like -y)
		for _, arg := range srv.Args {
			if len(arg) > 0 && arg[0] != '-' {
				return arg
			}
		}
	}

	// For other commands, concatenate command + first non-flag arg
	if len(srv.Args) > 0 {
		for _, arg := range srv.Args {
			if len(arg) > 0 && arg[0] != '-' {
				return arg
			}
		}
	}

	return srv.Command
}

// printConfigSummary writes a final severity-count summary to stderr.
func printConfigSummary(findings []providers.Finding) {
	counts := map[providers.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow)

	fmt.Fprintf(os.Stderr, "  %s %s\n",
		color.New(color.FgCyan).Sprint("──"),
		bold.Sprint("Summary (all servers)"))

	if len(findings) == 0 {
		fmt.Fprintf(os.Stderr, "  %s\n\n", dim.Sprint("No findings."))
		return
	}

	parts := []string{}
	if n := counts[providers.SeverityCritical]; n > 0 {
		parts = append(parts, red.Sprintf("%d CRITICAL", n))
	}
	if n := counts[providers.SeverityHigh]; n > 0 {
		parts = append(parts, red.Sprintf("%d HIGH", n))
	}
	if n := counts[providers.SeverityWarning]; n > 0 {
		parts = append(parts, yellow.Sprintf("%d WARNING", n))
	}
	if n := counts[providers.SeverityInfo]; n > 0 {
		parts = append(parts, dim.Sprintf("%d INFO", n))
	}

	line := ""
	for i, p := range parts {
		if i > 0 {
			line += dim.Sprint(" · ")
		}
		line += p
	}
	fmt.Fprintf(os.Stderr, "  %s\n\n", line)
}

func newPinCmd() *cobra.Command {
	var (
		verbose bool
		noColor bool
	)

	cmd := &cobra.Command{
		Use:   "pin [command] [args...]",
		Short: "Pin tool description hashes for rug pull detection",
		Long: `Connect to an MCP server, retrieve its tools, and store SHA-256 hashes
of each tool's description and schema. Use 'oxvault check' later to detect changes.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.DefaultConfig()
			cfg.Verbose = verbose
			cfg.NoColor = noColor

			if noColor {
				color.NoColor = true
			}

			application := app.NewApp(cfg)
			if err := application.Initialize(); err != nil {
				return fmt.Errorf("initialize: %w", err)
			}

			serverCmd := args[0]
			serverArgs := args[1:]

			count, err := application.GetPinner().Pin(serverCmd, serverArgs)
			if err != nil {
				return fmt.Errorf("pin: %w", err)
			}

			bold := color.New(color.Bold)
			green := color.New(color.FgGreen)
			fmt.Printf("  %s Pinned %s tools. Hashes saved to .oxvault/pins.json\n",
				green.Sprint("✓"),
				bold.Sprintf("%d", count))
			return nil
		},
	}

	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable color output")
	cmd.Flags().SetInterspersed(false)
	return cmd
}

func newCheckCmd() *cobra.Command {
	var (
		verbose bool
		noColor bool
	)

	cmd := &cobra.Command{
		Use:   "check [command] [args...]",
		Short: "Check for rug pulls (tool description changes since last pin)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.DefaultConfig()
			cfg.Verbose = verbose
			cfg.NoColor = noColor

			if noColor {
				color.NoColor = true
			}

			application := app.NewApp(cfg)
			if err := application.Initialize(); err != nil {
				return fmt.Errorf("initialize: %w", err)
			}

			serverCmd := args[0]
			serverArgs := args[1:]

			report, err := application.GetPinner().Check(serverCmd, serverArgs)
			if err != nil {
				return err
			}

			red := color.New(color.FgRed, color.Bold)
			green := color.New(color.FgGreen)
			dim := color.New(color.Faint)

			for _, diff := range report.Diffs {
				if diff.Changed {
					fmt.Printf("  %s %s: %s\n",
						red.Sprint("✗"),
						color.New(color.Bold).Sprint(diff.ToolName),
						diff.Description)
				} else {
					fmt.Printf("  %s %s: %s\n",
						green.Sprint("✓"),
						dim.Sprint(diff.ToolName),
						dim.Sprint("hash unchanged"))
				}
			}

			if report.Changed {
				fmt.Printf("\n  %s Tool descriptions have changed since last pin.\n",
					red.Sprint("⚠"))
				os.Exit(1)
			} else {
				fmt.Printf("\n  %s All tools match pinned hashes.\n",
					green.Sprint("✓"))
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable color output")
	cmd.Flags().SetInterspersed(false)
	return cmd
}
