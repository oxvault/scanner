package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/oxvault/scanner/internal/userconfig"
	"github.com/spf13/cobra"
)

// newInitCmd builds `oxvault init` — writes a starter config.toml skeleton
// to ~/.oxvault/config.toml so the user can flip [push].auto = true and
// have every scan auto-upload without re-typing flags.
//
// Refuses to overwrite an existing file unless --force is passed. Prints
// the next-step instructions on success.
func newInitCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create ~/.oxvault/config.toml with sensible defaults",
		Long: `Create a starter Oxvault config file at ~/.oxvault/config.toml.

The file is commented; flip [push].auto = true to make every 'oxvault scan'
also push the result to the Oxvault platform automatically (requires
OXVAULT_API_KEY).

  Examples:
    oxvault init           # create ~/.oxvault/config.toml (errors if it exists)
    oxvault init --force   # overwrite an existing file`,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := userconfig.Path()
			if err != nil {
				return fmt.Errorf("resolve config path: %w", err)
			}

			if _, err := os.Stat(path); err == nil && !force {
				return fmt.Errorf("%s already exists — pass --force to overwrite", path)
			}

			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return fmt.Errorf("create config dir: %w", err)
			}
			if err := os.WriteFile(path, []byte(starterConfig), 0o644); err != nil {
				return fmt.Errorf("write config: %w", err)
			}

			printInitSuccess(path)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Overwrite an existing config file")
	return cmd
}

// starterConfig is the body written by `oxvault init`. Keys are commented
// out so the file is inert by default — turning push.auto on requires the
// user to delete the leading "#".
const starterConfig = `# Oxvault CLI configuration
# Lives at ~/.oxvault/config.toml. See https://oxvault.dev/docs/cli for full reference.

[push]
# auto: when true, every 'oxvault scan' also uploads the result to the
# Oxvault platform (equivalent to passing --push on every run).
# Requires OXVAULT_API_KEY (or [push].api_key below).
# auto = true

# api_key: workspace API key minted at /settings/api-keys.
# Prefer OXVAULT_API_KEY env var so the file stays safe to commit. Anything
# you do put here, do NOT check into a public repo.
# api_key = "ox_..."

# api_url: platform base URL. Defaults to https://platform.oxvault.dev.
# Override for local dev:
# api_url = "http://localhost:8080"

# console_url: console base URL used for the success-banner link.
# Defaults to a heuristic derived from api_url (localhost → :5173,
# platform.* → console.*).
# console_url = "http://localhost:5173"

# quiet: silences the post-push success banner.
# quiet = false
`

func printInitSuccess(path string) {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	emerald := color.New(color.FgGreen, color.Bold)

	fmt.Fprintf(os.Stderr, "\n  %s %s\n",
		emerald.Sprint("✓"),
		bold.Sprintf("Wrote %s", path))

	fmt.Fprintf(os.Stderr, "\n  %s\n", bold.Sprint("Next:"))
	fmt.Fprintf(os.Stderr, "  %s open the file and uncomment the keys you want\n", dim.Sprint("1."))
	fmt.Fprintf(os.Stderr, "  %s mint an API key at %s\n",
		dim.Sprint("2."),
		bold.Sprint("https://console.oxvault.dev/settings/api-keys"))
	fmt.Fprintf(os.Stderr, "  %s export OXVAULT_API_KEY=ox_… in your shell\n", dim.Sprint("3."))
	fmt.Fprintf(os.Stderr, "  %s run %s — every scan will auto-push if you turned [push].auto on\n\n",
		dim.Sprint("4."),
		bold.Sprint("oxvault scan ./your-target"))
}
