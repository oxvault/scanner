package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/oxvault/scanner/internal/userconfig"
	"github.com/spf13/cobra"
)

// newLoginCmd builds `oxvault login` - the first step of the onboarding flow
// (create key in the Console → login → scan → push). It validates a
// workspace-scoped API key against the platform, then persists it to
// ~/.oxvault/config.toml so subsequent `scan --push` / `push` runs pick it up
// without re-typing flags.
//
// The key is resolved in priority order: --api-key flag → OXVAULT_API_KEY env
// → interactive prompt read from /dev/tty (so it never lands in shell history
// as a command argument).
func newLoginCmd() *cobra.Command {
	var (
		apiKey     string
		apiURL     string
		consoleURL string
	)

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate the CLI with the Oxvault platform",
		Long: `Validate a workspace API key against the Oxvault platform and store it
locally so 'oxvault push' (and 'oxvault scan --push') work without flags.

Mint a key in the Console at /settings/api-keys, then:

  Examples:
    oxvault login                                  # prompt for the key (hidden from shell history)
    oxvault login --api-key ox_…
    OXVAULT_API_KEY=ox_… oxvault login
    oxvault login --api-key ox_… --api-url http://localhost:8080

The key is verified via GET <api-url>/api/v1/auth/me before anything is
written - an invalid key exits non-zero and leaves the config untouched. On
success the key is saved to ~/.oxvault/config.toml under [push].`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLoginFlow(apiKey, apiURL, consoleURL, readAPIKeyFromTTY)
		},
	}

	cmd.Flags().StringVar(&apiKey, "api-key", "", "Workspace API key (default: prompt, or $OXVAULT_API_KEY)")
	cmd.Flags().StringVar(&apiURL, "api-url", "", "Platform base URL (default: $OXVAULT_API_URL or "+defaultAPIURL+")")
	cmd.Flags().StringVar(&consoleURL, "console-url", "", "Console base URL (default: $OXVAULT_CONSOLE_URL or "+defaultConsoleURL+")")

	return cmd
}

// meResponse is the subset of the platform's GET /api/v1/auth/me payload
// (models.MeResponse) that we surface in the success banner.
type meResponse struct {
	User struct {
		Email string `json:"email"`
	} `json:"user"`
	Workspace struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	} `json:"workspace"`
}

// runLoginFlow resolves the key + URLs, validates the key against the
// platform, and persists it only on success. prompt is injected so tests can
// exercise the interactive path without a real terminal.
func runLoginFlow(apiKey, apiURL, consoleURL string, prompt func() (string, error)) error {
	// 1. Resolve the key: flag → env → interactive prompt.
	if apiKey == "" {
		apiKey = os.Getenv("OXVAULT_API_KEY")
	}
	if apiKey == "" {
		got, err := prompt()
		if err != nil {
			return err
		}
		apiKey = got
	}
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return fmt.Errorf("no API key provided (pass --api-key, set OXVAULT_API_KEY, or enter it when prompted)")
	}
	if !strings.HasPrefix(apiKey, "ox_") {
		return fmt.Errorf("api key looks malformed (expected prefix \"ox_\"); refusing to send")
	}

	// 2. Resolve URLs: flag → env → shared default.
	if apiURL == "" {
		apiURL = os.Getenv("OXVAULT_API_URL")
	}
	if apiURL == "" {
		apiURL = defaultAPIURL
	}
	if consoleURL == "" {
		consoleURL = os.Getenv("OXVAULT_CONSOLE_URL")
	}
	if consoleURL == "" {
		consoleURL = deriveConsoleURL(apiURL)
	}

	// 3. Validate BEFORE persisting anything.
	me, err := verifyAPIKey(apiURL, apiKey)
	if err != nil {
		return err
	}

	// 4. Persist only on success.
	if err := saveLoginConfig(apiKey, apiURL, consoleURL); err != nil {
		return err
	}

	path, _ := userconfig.Path()
	printLoginSuccess(me, apiKey, path)
	return nil
}

// verifyAPIKey calls GET <apiURL>/api/v1/auth/me with the key in the Bearer
// header. The platform dispatches on the "ox_" prefix, so a workspace key is
// accepted here just like a session JWT. 200 → valid; 401/403 → invalid key.
func verifyAPIKey(apiURL, apiKey string) (*meResponse, error) {
	endpoint, err := url.JoinPath(apiURL, "/api/v1/auth/me")
	if err != nil {
		return nil, fmt.Errorf("build endpoint: %w", err)
	}

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("User-Agent", "oxvault-cli/"+version)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get /api/v1/auth/me: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var me meResponse
		if err := json.Unmarshal(body, &me); err != nil {
			return nil, fmt.Errorf("parse /api/v1/auth/me response: %w\nbody: %s", err, snippet(body, 256))
		}
		return &me, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("invalid API key: the platform rejected it (%d); mint a fresh key at <console>/settings/api-keys", resp.StatusCode)
	default:
		return nil, formatHTTPError(resp.StatusCode, body)
	}
}

// saveLoginConfig merges the credential into ~/.oxvault/config.toml, leaving
// unrelated settings (e.g. [push].auto / quiet) intact. A missing or corrupt
// file starts from a fresh Config so login always succeeds in writing.
func saveLoginConfig(apiKey, apiURL, consoleURL string) error {
	uc, err := userconfig.Load()
	if err != nil || uc == nil {
		uc = &userconfig.Config{}
	}
	uc.Push.APIKey = apiKey
	uc.Push.APIURL = apiURL
	uc.Push.ConsoleURL = consoleURL
	return userconfig.Save(uc)
}

// readAPIKeyFromTTY prompts on stderr and reads a single line from /dev/tty -
// not stdin - so the key is never taken from a pipe and never appears in shell
// history. Mirrors the gateway's TTY-read pattern.
func readAPIKeyFromTTY() (string, error) {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return "", fmt.Errorf("no API key provided and no interactive terminal available; pass --api-key or set OXVAULT_API_KEY")
	}
	defer func() { _ = tty.Close() }()

	fmt.Fprint(os.Stderr, "Enter your Oxvault API key (ox_…): ")
	var key string
	if _, err := fmt.Fscanln(tty, &key); err != nil {
		return "", fmt.Errorf("read API key from terminal: %w", err)
	}
	return strings.TrimSpace(key), nil
}

// redactKey returns a display-safe form of an API key: the "ox_" prefix and
// the last four characters only. The full key is never logged.
func redactKey(k string) string {
	if len(k) <= 8 {
		return "ox_…"
	}
	return k[:3] + "…" + k[len(k)-4:]
}

func printLoginSuccess(me *meResponse, apiKey, path string) {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	emerald := color.New(color.FgGreen, color.Bold)

	who := me.User.Email
	if me.Workspace.Name != "" {
		who = fmt.Sprintf("%s (workspace %s)", me.User.Email, me.Workspace.Name)
	}

	fmt.Fprintf(os.Stderr, "\n  %s %s\n",
		emerald.Sprint("✓"),
		bold.Sprintf("Logged in as %s", who))
	fmt.Fprintf(os.Stderr, "  %s %s\n", dim.Sprint("Key:   "), redactKey(apiKey))
	fmt.Fprintf(os.Stderr, "  %s %s\n\n", dim.Sprint("Config:"), path)
}
