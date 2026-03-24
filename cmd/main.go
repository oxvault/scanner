package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/oxvault/scanner/app"
	"github.com/oxvault/scanner/config"
	"github.com/oxvault/scanner/engines"
	"github.com/oxvault/scanner/providers"
	"github.com/spf13/cobra"
)

var version = "0.1.0"

const asciiLogo = `
             *+                                +*
             +.*                              *.+
             *..-%                          %=..*
              +....+%%    %*=:.:=*#%    %%+....+
                %=.....-*#-.-=*##*=-.-#*-.....-%
                   %#-.....:*%        %*:...-#%
                    #+#-....-%        %-...-**#
                    #.:@%#-..*        #..:*%@:.#
                    #..%@@@#-#        #-#@@@%..#
                    %:.#@@@@@@        @@@@@@#.:%
                    %-.+@@@@@@        @@@@@@+.-%
                    %+..%@@@@@@      @@@@@@%:.=%
                     %=..+%@@@@      @@@@%+..=%
                       %:.:*@@@@    @@@@*:.:#
                         %*..:#@@  @@#:..*%
                           *...*%  %#:..*
                             *:.:+*:.:*%
                               #:..:#%
                                 %%

              %%%%  %%  %%  %  %%%  %%  %%%  %%
              *:+*=:*@%=:*-*@%--@%=-%@%::=%@@=:@@
              :+@@@=-@@%:.+%@@%:=+:%@%-=%:+@@=:@@
              #.=*=:#@%-=%-=@@@#..#@%=:#*+.*@#.=+
               %%%@@@%%@@@%@@@@%%@@@%@@@@%%@@@%%`

func main() {
	root := &cobra.Command{
		Use:     "oxvault",
		Short:   "MCP security scanner — detect vulnerabilities in AI tool integrations",
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
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func printLogo() {
	cyan := color.New(color.FgCyan, color.Bold)
	dim := color.New(color.Faint)
	bold := color.New(color.Bold)

	_, _ = cyan.Fprintln(os.Stderr, asciiLogo)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  %s  %s\n",
		bold.Sprint("Oxvault Scanner"),
		dim.Sprintf("v%s", version))
	fmt.Fprintf(os.Stderr, "  %s\n\n",
		dim.Sprint("MCP security scanner — detect vulnerabilities in AI tool integrations"))
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
		bold.Sprintf("Oxvault Scanner v%s", version))

	fmt.Fprintf(os.Stderr, "  %s %s\n\n",
		dim.Sprint("Scanning:"),
		bold.Sprint(target))
}

func newScanCmd() *cobra.Command {
	var (
		format       string
		failOn       string
		verbose      bool
		skipSAST     bool
		skipManifest bool
		skipEgress   bool
		probeNetwork bool
		noColor      bool
		configPath   string
	)

	cmd := &cobra.Command{
		Use:   "scan [target]",
		Short: "Scan an MCP server for security vulnerabilities",
		Long: `Scan an MCP server project, npm package, or GitHub repo for security vulnerabilities.

Targets:
  ./my-server                    Local project directory or file
  @company/mcp-server            npm package (downloaded to temp dir)
  github:user/repo               GitHub repository (cloned)

Config-based scanning:
  --config ~/.claude/claude_desktop_config.json   Scan all servers in a config file
  --config auto                                   Auto-detect all known MCP config files`,
		Args: cobra.RangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" && len(args) == 0 {
				return fmt.Errorf("provide a scan target or --config flag\n\nRun 'oxvault scan --help' for usage")
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

			// Apply no-color globally before any output
			if noColor || cfg.OutputFormat != providers.FormatTerminal {
				color.NoColor = true
			}

			application := app.NewApp(cfg)
			if err := application.Initialize(); err != nil {
				return fmt.Errorf("initialize: %w", err)
			}

			scanOpts := engines.ScanOptions{
				SkipSAST:     cfg.SkipSAST,
				SkipManifest: cfg.SkipManifest,
				SkipEgress:   cfg.SkipEgress,
				ProbeNetwork: cfg.ProbeNetwork,
				FailOn:       cfg.FailOn,
			}

			// --config mode: scan all servers from one or more config files
			if configPath != "" {
				return runConfigScan(application, cfg, scanOpts, configPath)
			}

			// Traditional single-target mode
			return runSingleScan(application, cfg, scanOpts, args[0])
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "terminal", "Output format: terminal, sarif, json")
	cmd.Flags().StringVar(&failOn, "fail-on", "critical", "Exit non-zero at this severity: critical, high, warning, info")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	cmd.Flags().BoolVar(&skipSAST, "skip-sast", false, "Skip source code analysis")
	cmd.Flags().BoolVar(&skipManifest, "skip-manifest", false, "Skip tool description analysis")
	cmd.Flags().BoolVar(&skipEgress, "skip-egress", false, "Skip network egress detection")
	cmd.Flags().BoolVar(&probeNetwork, "probe-network", false, "Spawn server and monitor outbound connections (requires strace on Linux)")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable color output (for CI or piping)")
	cmd.Flags().StringVar(&configPath, "config", "", "MCP client config file to scan (path or \"auto\")")

	return cmd
}

// runSingleScan handles the traditional `oxvault scan <target>` path.
func runSingleScan(application *app.App, cfg *config.Config, opts engines.ScanOptions, target string) error {
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

	report, err := application.GetScanner().Scan(target, opts)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	output, err := application.GetReporter().Report(report.Findings, cfg.OutputFormat)
	if err != nil {
		return fmt.Errorf("report: %w", err)
	}

	fmt.Print(string(output))

	if report.HasSeverity(cfg.FailOn) {
		os.Exit(1)
	}
	return nil
}

// runConfigScan handles `oxvault scan --config <path|auto>`.
// It discovers all configured MCP servers, scans each one individually,
// and aggregates findings with per-server headers in terminal mode.
func runConfigScan(application *app.App, cfg *config.Config, opts engines.ScanOptions, configPath string) error {
	result, err := config.Discover(configPath)
	if err != nil {
		return fmt.Errorf("discover config: %w", err)
	}

	if len(result.Servers) == 0 {
		fmt.Fprintf(os.Stderr, "  No MCP servers found in config.\n")
		return nil
	}

	if cfg.OutputFormat == providers.FormatTerminal {
		bold := color.New(color.Bold)
		dim := color.New(color.Faint)
		cyan := color.New(color.FgCyan, color.Bold)

		fmt.Fprintf(os.Stderr, "\n  %s %s\n\n",
			cyan.Sprint("◉"),
			bold.Sprintf("Oxvault Scanner v%s", version))

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
	return cmd
}
