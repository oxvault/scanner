package main

import (
	"fmt"
	"os"

	"github.com/oxvault/scanner/app"
	"github.com/oxvault/scanner/config"
	"github.com/oxvault/scanner/engines"
	"github.com/oxvault/scanner/providers"
	"github.com/spf13/cobra"
)

var version = "dev"

func main() {
	root := &cobra.Command{
		Use:     "oxvault",
		Short:   "MCP security scanner — detect vulnerabilities in AI tool integrations",
		Version: version,
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

func newScanCmd() *cobra.Command {
	var (
		format       string
		failOn       string
		verbose      bool
		skipSAST     bool
		skipManifest bool
		skipEgress   bool
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

			application := app.NewApp(cfg)
			if err := application.Initialize(); err != nil {
				return fmt.Errorf("initialize: %w", err)
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

	return cmd
}

func newPinCmd() *cobra.Command {
	var verbose bool

	cmd := &cobra.Command{
		Use:   "pin [command] [args...]",
		Short: "Pin tool description hashes for rug pull detection",
		Long: `Connect to an MCP server, retrieve its tools, and store SHA-256 hashes
of each tool's description and schema. Use 'oxvault check' later to detect changes.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.DefaultConfig()
			cfg.Verbose = verbose

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

			fmt.Printf("Pinned %d tools. Hashes saved to .oxvault/pins.json\n", count)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	return cmd
}

func newCheckCmd() *cobra.Command {
	var verbose bool

	cmd := &cobra.Command{
		Use:   "check [command] [args...]",
		Short: "Check for rug pulls (tool description changes since last pin)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.DefaultConfig()
			cfg.Verbose = verbose

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

			for _, diff := range report.Diffs {
				if diff.Changed {
					fmt.Printf("  ✗ %s: %s\n", diff.ToolName, diff.Description)
				} else {
					fmt.Printf("  ✓ %s: hash unchanged\n", diff.ToolName)
				}
			}

			if report.Changed {
				fmt.Println("\n  WARNING: Tool descriptions have changed since last pin.")
				os.Exit(1)
			} else {
				fmt.Println("\n  All tools match pinned hashes.")
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	return cmd
}
