package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/oxvault/scanner/app"
	"github.com/oxvault/scanner/config"
	"github.com/oxvault/scanner/engines"
	"github.com/oxvault/scanner/internal/lastscan"
	"github.com/oxvault/scanner/internal/userconfig"
	"github.com/oxvault/scanner/providers"
	"github.com/spf13/cobra"
)

// newAgentCmd builds `oxvault agent` — long-running daemon that long-polls
// the Oxvault platform for queued scan jobs and runs them locally.
//
// Architecture:
//
//  1. Open outbound HTTPS to platform (no inbound port required).
//  2. GET /api/v1/scan-jobs/pending?agent_id=<host> — blocks ~25s.
//     • 204 → nothing to do, immediately re-poll.
//     • 200 → server hands us a claimed ScanJob.
//  3. Resolve the artifact name to a local target — caller can pin via
//     `--target-map=<artifact_name>=<path>` (repeatable) or use the
//     default heuristic (artifact_name = directory under cwd).
//  4. Run the scanner against the target.
//  5. POST the resulting findings to /api/v1/scans (same path push uses).
//  6. POST /api/v1/scan-jobs/:id/complete with the new scan id.
//  7. Loop forever (SIGINT to quit).
//
// The agent is the inverse of `oxvault push` — push uploads a scan that's
// already on disk, agent runs the scan that the dashboard asked for.
func newAgentCmd() *cobra.Command {
	var (
		apiKey     string
		apiURL     string
		consoleURL string
		agentID    string
		targetMaps []string
		oneShot    bool
		verbose    bool
	)

	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Long-poll the Oxvault platform for queued scans and run them locally",
		Long: `Run a long-poll loop against the Oxvault platform. Picks up scan jobs
queued from the console (Re-scan button) and runs them against your local
working directory — code never leaves your machine.

Map artifact names to local paths so the agent knows what to scan when a
job comes in:

  oxvault agent \
    --target-map=asana-mcp=./node_modules/@asana/mcp-server \
    --target-map=cloudflare-mcp=./vendor/cloudflare-mcp

Without --target-map the agent falls back to scanning a directory under
cwd named after the artifact.

Auth uses a workspace API key, same as 'oxvault push'.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			uc, _ := userconfig.Load()

			// Resolve URLs first so the missing-key error can point users
			// at the right console URL instead of a placeholder.
			if apiURL == "" {
				apiURL = os.Getenv("OXVAULT_API_URL")
			}
			if apiURL == "" && uc != nil {
				apiURL = uc.Push.APIURL
			}
			if apiURL == "" {
				apiURL = "https://platform.oxvault.dev"
			}

			if apiKey == "" {
				apiKey = os.Getenv("OXVAULT_API_KEY")
			}
			if apiKey == "" && uc != nil {
				apiKey = uc.Push.APIKey
			}
			if apiKey == "" {
				return fmt.Errorf(
					"OXVAULT_API_KEY not set; mint a key at %s/settings/api-keys (or pass --api-key)",
					strings.TrimSuffix(deriveConsoleURL(apiURL), "/"),
				)
			}
			if !strings.HasPrefix(apiKey, "ox_") {
				return fmt.Errorf("api key looks malformed (expected prefix \"ox_\"); refusing to start agent")
			}

			if consoleURL == "" {
				consoleURL = os.Getenv("OXVAULT_CONSOLE_URL")
			}
			if consoleURL == "" && uc != nil {
				consoleURL = uc.Push.ConsoleURL
			}
			if consoleURL == "" {
				consoleURL = deriveConsoleURL(apiURL)
			}

			if agentID == "" {
				if h, err := os.Hostname(); err == nil && h != "" {
					agentID = h
				} else {
					agentID = "agent"
				}
			}

			targets, err := parseTargetMaps(targetMaps)
			if err != nil {
				return err
			}

			cfg := config.DefaultConfig()
			cfg.OutputFormat = providers.FormatJSON
			cfg.Verbose = verbose
			color.NoColor = true // agent output is structured logs, not pretty

			application := app.NewApp(cfg)
			if err := application.Initialize(); err != nil {
				return fmt.Errorf("initialize scanner: %w", err)
			}

			a := &agentLoop{
				apiURL:     apiURL,
				consoleURL: consoleURL,
				apiKey:     apiKey,
				agentID:    agentID,
				targets:    targets,
				app:        application,
				verbose:    verbose,
			}
			return a.run(cmd.Context(), oneShot)
		},
	}

	cmd.Flags().StringVar(&apiKey, "api-key", "", "Workspace API key (default: $OXVAULT_API_KEY or ~/.oxvault/config.toml)")
	cmd.Flags().StringVar(&apiURL, "api-url", "", "Platform base URL (default: $OXVAULT_API_URL or https://platform.oxvault.dev)")
	cmd.Flags().StringVar(&consoleURL, "console-url", "", "Console base URL for log lines (default: derived from --api-url)")
	cmd.Flags().StringVar(&agentID, "agent-id", "", "Agent identifier surfaced in audit logs (default: hostname)")
	cmd.Flags().StringSliceVar(&targetMaps, "target-map", nil, "Map artifact name to local path: name=path. Repeatable.")
	cmd.Flags().BoolVar(&oneShot, "one-shot", false, "Process at most one job, then exit (useful in CI)")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose log output")
	return cmd
}

// agentLoop holds the run-time state and the http client for one agent.
type agentLoop struct {
	apiURL     string
	consoleURL string
	apiKey     string
	agentID    string
	targets    map[string]string
	app        *app.App
	verbose    bool
}

// run is the daemon entry point. Loops until SIGINT/SIGTERM or the context
// is cancelled. one-shot mode exits after the first successful job.
func (a *agentLoop) run(ctx context.Context, oneShot bool) error {
	logf := newAgentLogger()
	logf.Info("agent up — polling %s as %s", a.apiURL, a.agentID)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)

	for {
		select {
		case <-stop:
			logf.Info("shutting down")
			return nil
		default:
		}

		job, err := a.poll()
		if err != nil {
			logf.Warn("poll failed: %v — retrying in 5s", err)
			if !sleepOrStop(5*time.Second, stop) {
				return nil
			}
			continue
		}
		if job == nil {
			// 204 — no work. Tight re-poll; the long-poll already absorbed the wait.
			continue
		}

		logf.Info("claimed job %s for artifact %s", job.ID, job.ArtifactName)
		if err := a.processJob(job, logf); err != nil {
			logf.Warn("job %s failed: %v", job.ID, err)
			// Failure path also benefits from retry — otherwise a transient
			// /complete blip on a failed scan leaves the job stuck claimed
			// and the user has no audit trail of the failure.
			if cerr := a.completeWithRetry(job.ID, nil, ptrString(err.Error()), logf); cerr != nil {
				logf.Warn("job %s could not be marked failed after retries: %v", job.ID, cerr)
			}
		}

		if oneShot {
			return nil
		}
	}
}

// pendingJob mirrors the bits of models.ScanJob the agent cares about,
// plus the artifact_name we need so the agent knows what to scan. The
// platform doesn't currently embed that — to keep the wire small we fetch
// the artifact separately when needed. Future tweak: have the platform
// inline { artifact: { name, type, source } } in the long-poll response.
type pendingJob struct {
	ID           string `json:"id"`
	ArtifactID   string `json:"artifact_id"`
	ArtifactName string `json:"-"` // filled in by resolveTarget
}

// poll long-polls /scan-jobs/pending. Returns a claimed job, or nil when
// the server replies 204 (no work). Errors only on real network/protocol
// failures — empty 204 is the happy "nothing pending" path.
func (a *agentLoop) poll() (*pendingJob, error) {
	endpoint, err := url.JoinPath(a.apiURL, "/api/v1/scan-jobs/pending")
	if err != nil {
		return nil, fmt.Errorf("build endpoint: %w", err)
	}
	endpoint += "?agent_id=" + url.QueryEscape(a.agentID)

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+a.apiKey)
	req.Header.Set("User-Agent", "oxvault-agent/"+version)

	client := &http.Client{Timeout: 35 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("poll: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))

	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, nil
	case http.StatusOK:
		// Envelope unwrap.
		var env struct {
			State string       `json:"state"`
			Data  pendingJob   `json:"data"`
			Error *envelopeErr `json:"error,omitempty"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			return nil, fmt.Errorf("decode response: %w (body: %s)", err, snippet(body, 256))
		}
		if env.State == "error" && env.Error != nil {
			return nil, fmt.Errorf("platform error: %s — %s", env.Error.Code, env.Error.Message)
		}
		return &env.Data, nil
	default:
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, snippet(body, 256))
	}
}

// processJob resolves the artifact, runs the scan locally, posts the
// scan via /scans, then marks the job complete. Failures bubble up so
// run() can mark the job as failed.
func (a *agentLoop) processJob(job *pendingJob, logf *agentLogger) error {
	target, err := a.resolveTarget(job)
	if err != nil {
		return fmt.Errorf("resolve target: %w", err)
	}

	logf.Info("scanning %s …", target)
	startedAt := time.Now().UTC()
	report, err := a.app.GetScanner().Scan(target, engines.ScanOptions{})
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	completedAt := time.Now().UTC()

	// Persist + push the scan via the same code path as `oxvault push`.
	artifactName := job.ArtifactName
	if artifactName == "" {
		artifactName = deriveArtifactName(target)
	}
	f := lastscan.FromReport(target, artifactName, "mcp", startedAt, completedAt, version, report.Findings)
	if err := lastscan.Save(f); err != nil {
		return fmt.Errorf("persist last scan: %w", err)
	}

	scanID, err := a.pushScan(f)
	if err != nil {
		return fmt.Errorf("push scan: %w", err)
	}

	// Once the scan is uploaded, the only way to clear the job from
	// `claimed` state is the /complete call. Transient network errors
	// here would orphan a real result. Retry with bounded backoff and
	// surface a loud, recoverable error if every attempt fails.
	if err := a.completeWithRetry(job.ID, &scanID, nil, logf); err != nil {
		return fmt.Errorf(
			"scan %s pushed for job %s but /complete failed (job stuck in claimed state — re-run manually): %w",
			scanID, job.ID, err,
		)
	}
	logf.Info("job %s done — scan %s · %d findings", job.ID, scanID, len(report.Findings))
	return nil
}

// resolveTarget maps a job's artifact onto a local path the scanner can
// read. Priority:
//
//  1. Explicit --target-map=<artifact_name>=<path>      (always wins)
//  2. First match from a list of probed candidate paths under cwd:
//     <cwd>/<name>
//     <cwd>/examples/<name>
//     <cwd>/vendor/<name>
//     <cwd>/node_modules/<name>
//     <cwd>/node_modules/@*/<name>            (any npm scope)
//
// Returns a clear error listing every candidate it tried so the user
// knows exactly which paths to add to --target-map.
func (a *agentLoop) resolveTarget(job *pendingJob) (string, error) {
	name := job.ArtifactName
	if name == "" {
		got, err := a.fetchArtifactName(job.ArtifactID)
		if err != nil {
			return "", err
		}
		name = got
		job.ArtifactName = got
	}

	// Defence-in-depth: even though the platform should only emit safe
	// names, treat the value as untrusted at this boundary. A malicious
	// or compromised platform could otherwise drive the agent into
	// scanning sensitive files outside cwd via "../../etc/shadow".
	if err := validateArtifactName(name); err != nil {
		return "", err
	}

	if t, ok := a.targets[name]; ok {
		return t, nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getwd: %w", err)
	}

	candidates := candidatePaths(cwd, name)
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf(
		"could not locate artifact %q under %s (tried %d paths); "+
			"pass --target-map=%s=<path> to point the agent explicitly",
		name, cwd, len(candidates), name,
	)
}

// validateArtifactName rejects names that could escape cwd when joined
// to it (path traversal). The agent never trusts the platform's name
// blindly — see resolveTarget. Tested with names from real CLI corpora
// (mcp-server, @scope/pkg, hf:org/model resolved to "model").
func validateArtifactName(name string) error {
	if name == "" {
		return fmt.Errorf("artifact name is empty")
	}
	if strings.HasPrefix(name, ".") {
		return fmt.Errorf("artifact name %q starts with '.'", name)
	}
	if strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("artifact name %q contains path separator", name)
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("artifact name %q contains '..'", name)
	}
	return nil
}

// candidatePaths builds the ordered list of paths the agent probes when
// no explicit --target-map entry exists. Kept exported for tests.
// Caller MUST pass a name validated via validateArtifactName.
func candidatePaths(cwd, name string) []string {
	sep := string(os.PathSeparator)
	out := []string{
		cwd + sep + name,
		cwd + sep + "examples" + sep + name,
		cwd + sep + "vendor" + sep + name,
		cwd + sep + "node_modules" + sep + name,
	}
	// Glob npm scopes (@scope/<name>) — we don't know which scope owns
	// the package without metadata, so probe whatever's there.
	if entries, err := os.ReadDir(cwd + sep + "node_modules"); err == nil {
		for _, e := range entries {
			if !e.IsDir() || !strings.HasPrefix(e.Name(), "@") {
				continue
			}
			out = append(out, cwd+sep+"node_modules"+sep+e.Name()+sep+name)
		}
	}
	return out
}

// fetchArtifactName hits GET /api/v1/artifacts/:id to learn the artifact's
// display name when the long-poll response didn't inline it.
func (a *agentLoop) fetchArtifactName(artifactID string) (string, error) {
	endpoint, err := url.JoinPath(a.apiURL, "/api/v1/artifacts/", artifactID)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+a.apiKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("artifact lookup %d: %s", resp.StatusCode, snippet(body, 256))
	}
	var env struct {
		Data struct {
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return "", err
	}
	if env.Data.Name == "" {
		return "", errors.New("artifact has no name")
	}
	return env.Data.Name, nil
}

// pushScan POSTs the scan and returns the new scan id.
func (a *agentLoop) pushScan(f *lastscan.File) (string, error) {
	body, err := json.Marshal(f)
	if err != nil {
		return "", err
	}
	endpoint, err := url.JoinPath(a.apiURL, "/api/v1/scans")
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.apiKey)
	req.Header.Set("User-Agent", "oxvault-agent/"+version)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("push %d: %s", resp.StatusCode, snippet(respBody, 256))
	}
	var env struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &env); err != nil {
		return "", err
	}
	return env.Data.ID, nil
}

// completeWithRetry wraps `complete()` in 3 attempts with exponential
// backoff (0s, 1s, 2s). Used after pushScan succeeds — losing this call
// orphans a real scan result in the platform's `claimed` state, so we
// burn budget here rather than leak the job. Each retry attempt is
// logged at warn level so operators can see partial-failure trails.
func (a *agentLoop) completeWithRetry(jobID string, scanID *string, errMsg *string, logf *agentLogger) error {
	const attempts = 3
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			delay := time.Duration(1<<uint(i-1)) * time.Second
			logf.Warn("job %s /complete attempt %d/%d failed: %v — retrying in %s",
				jobID, i, attempts, lastErr, delay)
			time.Sleep(delay)
		}
		if err := a.complete(jobID, scanID, errMsg); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}

// complete tells the platform a job is done. scanID is set on success,
// errMsg on failure — exactly one is required.
func (a *agentLoop) complete(jobID string, scanID *string, errMsg *string) error {
	body, err := json.Marshal(map[string]any{"scan_id": scanID, "error": errMsg})
	if err != nil {
		return err
	}
	endpoint, err := url.JoinPath(a.apiURL, "/api/v1/scan-jobs/", jobID, "/complete")
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.apiKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("complete %d: %s", resp.StatusCode, snippet(respBody, 256))
	}
	return nil
}

// envelopeErr matches httputils.ErrorEnvelope on the platform side.
type envelopeErr struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// parseTargetMaps turns ["a=b", "c=d"] into {a: b, c: d}, validating that
// each entry has exactly one '='.
func parseTargetMaps(in []string) (map[string]string, error) {
	out := map[string]string{}
	for _, s := range in {
		eq := strings.IndexByte(s, '=')
		if eq <= 0 || eq == len(s)-1 {
			return nil, fmt.Errorf("invalid --target-map %q (expected name=path)", s)
		}
		out[strings.TrimSpace(s[:eq])] = strings.TrimSpace(s[eq+1:])
	}
	return out, nil
}

func sleepOrStop(d time.Duration, stop <-chan os.Signal) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-stop:
		return false
	}
}

func ptrString(s string) *string { return &s }

// agentLogger is a tiny stderr logger. We don't ship zerolog in the CLI
// because the rest of the scanner uses fatih/color and friends.
type agentLogger struct{}

func newAgentLogger() *agentLogger { return &agentLogger{} }

func (l *agentLogger) Info(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[agent] %s\n", fmt.Sprintf(format, args...))
}
func (l *agentLogger) Warn(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[agent] WARN %s\n", fmt.Sprintf(format, args...))
}
