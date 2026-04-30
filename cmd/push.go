package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/oxvault/scanner/internal/lastscan"
	"github.com/spf13/cobra"
)

// newPushCmd builds `oxvault push` — uploads the most recent local scan to
// the Oxvault platform. Source of truth is ~/.oxvault/last-scan.json,
// written by `oxvault scan` after every successful run.
//
// Auth: workspace-scoped API key via OXVAULT_API_KEY env or --api-key flag.
// Mint one in the console at /settings/api-keys.
func newPushCmd() *cobra.Command {
	var (
		apiKey  string
		apiURL  string
		scanFile string
		quiet   bool
	)

	cmd := &cobra.Command{
		Use:   "push",
		Short: "Upload the most recent scan to the Oxvault platform",
		Long: `Upload the most recent local scan result to the Oxvault platform so the
Console can render it.

The scan is read from ~/.oxvault/last-scan.json (written automatically by
'oxvault scan'). Override with --scan-file to push a specific file.

Authentication uses a workspace-scoped API key — mint one in the Console at
/settings/api-keys, then set OXVAULT_API_KEY in your environment.

  Examples:
    OXVAULT_API_KEY=ox_… oxvault push
    oxvault push --api-key ox_… --api-url https://platform.oxvault.dev
    oxvault push --scan-file ./scan.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if apiKey == "" {
				apiKey = os.Getenv("OXVAULT_API_KEY")
			}
			if apiKey == "" {
				return fmt.Errorf("OXVAULT_API_KEY not set; mint a key at <api-url>/settings/api-keys (or pass --api-key)")
			}
			if !strings.HasPrefix(apiKey, "ox_") {
				return fmt.Errorf("api key looks malformed (expected prefix \"ox_\"); refusing to send")
			}

			if apiURL == "" {
				apiURL = os.Getenv("OXVAULT_API_URL")
			}
			if apiURL == "" {
				apiURL = "https://platform.oxvault.dev"
			}

			scan, err := loadScanFile(scanFile)
			if err != nil {
				return err
			}
			if scan == nil {
				return fmt.Errorf("no scan to push — run 'oxvault scan <target>' first")
			}

			return doPush(apiURL, apiKey, scan, quiet)
		},
	}

	cmd.Flags().StringVar(&apiKey, "api-key", "", "Workspace API key (default: $OXVAULT_API_KEY)")
	cmd.Flags().StringVar(&apiURL, "api-url", "", "Platform base URL (default: $OXVAULT_API_URL or https://platform.oxvault.dev)")
	cmd.Flags().StringVar(&scanFile, "scan-file", "", "Path to a saved scan JSON (default: ~/.oxvault/last-scan.json)")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress the success banner")

	return cmd
}

func loadScanFile(override string) (*lastscan.File, error) {
	if override != "" {
		data, err := os.ReadFile(override)
		if err != nil {
			return nil, fmt.Errorf("read --scan-file: %w", err)
		}
		var f lastscan.File
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("parse --scan-file: %w", err)
		}
		return &f, nil
	}
	return lastscan.Load()
}

// pushResponse mirrors the platform's 201 JSON shape — a serialized
// models.Scan. We only care about a couple of fields for the user-facing
// banner; the rest are passed through.
type pushResponse struct {
	ID         string `json:"id"`
	ArtifactID string `json:"artifact_id"`
	CreatedAt  string `json:"created_at"`
}

func doPush(apiURL, apiKey string, scan *lastscan.File, quiet bool) error {
	body, err := json.Marshal(scan)
	if err != nil {
		return fmt.Errorf("marshal scan: %w", err)
	}

	endpoint, err := url.JoinPath(apiURL, "/api/v1/scans")
	if err != nil {
		return fmt.Errorf("build endpoint: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("User-Agent", "oxvault-cli/"+version)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post /api/v1/scans: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return formatHTTPError(resp.StatusCode, respBody)
	}

	var pr pushResponse
	if err := json.Unmarshal(respBody, &pr); err != nil {
		// Backend may evolve the response shape; surface what we got.
		return fmt.Errorf("parse response (status %d): %w\nbody: %s", resp.StatusCode, err, snippet(respBody, 256))
	}

	if !quiet {
		printPushSuccess(apiURL, scan, &pr)
	}
	return nil
}

func formatHTTPError(status int, body []byte) error {
	var apiErr struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &apiErr); err == nil && apiErr.Message != "" {
		return fmt.Errorf("platform rejected push: %d %s — %s", status, apiErr.Code, apiErr.Message)
	}
	return fmt.Errorf("platform rejected push: %d\nbody: %s", status, snippet(body, 512))
}

func snippet(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}

func printPushSuccess(apiURL string, scan *lastscan.File, resp *pushResponse) {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	emerald := color.New(color.FgGreen, color.Bold)

	fmt.Fprintf(os.Stderr, "\n  %s %s\n",
		emerald.Sprint("✓"),
		bold.Sprintf("Pushed %d findings for %s", len(scan.Findings), scan.ArtifactName),
	)

	consoleURL := strings.Replace(apiURL, "platform.", "console.", 1)
	if resp.ArtifactID != "" {
		fmt.Fprintf(os.Stderr, "  %s %s/inventory/%s\n",
			dim.Sprint("View:"),
			consoleURL,
			resp.ArtifactID,
		)
	}
	if resp.ID != "" {
		fmt.Fprintf(os.Stderr, "  %s %s\n\n",
			dim.Sprint("Scan:"),
			resp.ID,
		)
	} else {
		fmt.Fprintln(os.Stderr)
	}
}
