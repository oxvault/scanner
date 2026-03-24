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
			cmd.Help()
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

	cyan.Fprintln(os.Stderr, asciiLogo)
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
		noColor      bool
	)

	cmd := &cobra.Command{
		Use:   "scan [target]",
		Short: "Scan an MCP server for security vulnerabilities",
		Long: `Scan an MCP server project, npm package, or GitHub repo for security vulnerabilities.

Targets:
  ./my-server                    Local project directory or file
  @company/mcp-server            npm package (downloaded to temp dir)
  github:user/repo               GitHub repository (cloned)`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.DefaultConfig()
			cfg.OutputFormat = providers.OutputFormat(format)
			cfg.FailOn = failOn
			cfg.Verbose = verbose
			cfg.SkipSAST = skipSAST
			cfg.SkipManifest = skipManifest
			cfg.SkipEgress = skipEgress
			cfg.NoColor = noColor

			// Apply no-color globally before any output
			if noColor || cfg.OutputFormat != providers.FormatTerminal {
				color.NoColor = true
			}

			application := app.NewApp(cfg)
			if err := application.Initialize(); err != nil {
				return fmt.Errorf("initialize: %w", err)
			}

			// Show banner + progress only in terminal mode
			if cfg.OutputFormat == providers.FormatTerminal {
				printBanner(args[0])

				// Calculate total steps based on skip flags
				totalSteps := 4
				if skipSAST {
					totalSteps--
				}
				if skipEgress {
					totalSteps--
				}
				if skipManifest {
					totalSteps--
				}

				step := 1
				printProgress(step, totalSteps, "Resolving target...")
				step++

				if !skipSAST {
					printProgress(step, totalSteps, "Analyzing source code...")
					step++
				}
				if !skipEgress {
					printProgress(step, totalSteps, "Detecting network egress...")
					step++
				}
				if !skipManifest {
					printProgress(step, totalSteps, "Scanning tool descriptions...")
					step++
				}
				_ = step
				fmt.Fprintln(os.Stderr)
			}

			report, err := application.GetScanner().Scan(args[0], engines.ScanOptions{
				SkipSAST:     cfg.SkipSAST,
				SkipManifest: cfg.SkipManifest,
				SkipEgress:   cfg.SkipEgress,
				FailOn:       cfg.FailOn,
			})
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
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "terminal", "Output format: terminal, sarif, json")
	cmd.Flags().StringVar(&failOn, "fail-on", "critical", "Exit non-zero at this severity: critical, high, warning, info")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	cmd.Flags().BoolVar(&skipSAST, "skip-sast", false, "Skip source code analysis")
	cmd.Flags().BoolVar(&skipManifest, "skip-manifest", false, "Skip tool description analysis")
	cmd.Flags().BoolVar(&skipEgress, "skip-egress", false, "Skip network egress detection")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable color output (for CI or piping)")

	return cmd
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
