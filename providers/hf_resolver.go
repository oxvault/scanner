package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Hugging Face resolver.
//
// Resolves `hf:org/model[@revision]` targets by:
//
//  1. Parsing the target into (org, model, revision). Default revision is "main".
//  2. Calling the HF API manifest endpoint to enumerate the repo's siblings.
//  3. Filtering siblings to security-relevant files only (model artifacts,
//     model cards, signatures, common config / manifest files).
//  4. Downloading each filtered file under a per-(org, model, rev) cache
//     directory rooted at `~/.cache/oxvault/hf/`. Idempotent: existing files
//     with matching size are skipped.
//  5. Returning a `ResolvedPackage` with `Kind=KindModelDirectory` so the
//     AIBOM composer can scan the cache directory like any other model dir.
//
// Layer rule: this file lives in providers/ and depends on patterns/ + stdlib
// only. No HF SDK, no third-party HTTP libraries. Pure `net/http`.
//
// HTTP base URL is overridable via `WithHFBaseURL` so tests can swap in an
// `httptest.Server` — the production default is `https://huggingface.co`.

// ── constants ───────────────────────────────────────────────────────────────

const (
	// DefaultHFBaseURL is the production Hugging Face host. Tests override via
	// WithHFBaseURL pointing at an httptest.Server.
	DefaultHFBaseURL = "https://huggingface.co"

	// DefaultHFRevision is the default branch name when the target does not
	// specify one with `@revision`.
	DefaultHFRevision = "main"

	// DefaultHFMaxFileBytes is the default per-file safety cap. Files whose
	// declared size exceeds this are skipped (with a logged warning) — set
	// large because real model checkpoints commonly exceed 1 GiB.
	DefaultHFMaxFileBytes int64 = 4 * 1024 * 1024 * 1024 // 4 GiB

	// DefaultHFMaxCacheBytes is the default total-cache safety cap. The
	// resolver errors out before exceeding this — it does NOT silently
	// truncate, since a partial download would mislead the AIBOM composer.
	DefaultHFMaxCacheBytes int64 = 16 * 1024 * 1024 * 1024 // 16 GiB

	// hfHTTPTimeout is the per-request timeout for HF API + file downloads.
	hfHTTPTimeout = 30 * time.Second

	// hfMaxRetries is the max number of retries on 5xx and timeout errors.
	// 3 retries after the initial = 4 total attempts.
	hfMaxRetries = 3

	// hfRetryBaseDelay is the base delay for exponential backoff. Each retry
	// waits hfRetryBaseDelay * 2^attempt.
	hfRetryBaseDelay = 500 * time.Millisecond

	// hfMaxManifestBytes caps the manifest JSON body. Real HF manifests are a
	// few KiB — anything beyond 8 MiB is either a hostile host or a runaway
	// repo we should not be enumerating client-side.
	hfMaxManifestBytes int64 = 8 * 1024 * 1024
)

// ── filtering ───────────────────────────────────────────────────────────────

// hfRelevantExtensions enumerates file extensions whose contents are scanned
// by the AIBOM module. Anything outside this set is ignored to keep the cache
// small and the download time bounded.
var hfRelevantExtensions = map[string]bool{
	".pkl":         true,
	".pickle":      true,
	".pt":          true,
	".pth":         true,
	".bin":         true,
	".ckpt":        true,
	".onnx":        true,
	".safetensors": true,
	".md":          true,
	".sigstore":    true,
	".sig":         true,
}

// hfRelevantBasenames enumerates exact basenames worth fetching even when the
// extension alone is uninformative (`config.json`, `manifest.json`). Match is
// case-insensitive — the resolver lowercases before lookup.
var hfRelevantBasenames = map[string]bool{
	"model_signing.json": true,
	"manifest.json":      true,
	"config.json":        true,
	"readme.md":          true,
	"model_card.md":      true,
	"model_card.yaml":    true,
	".modelcard.yaml":    true,
}

// isHFRelevantFile returns true when the file is worth downloading for AIBOM
// analysis.
func isHFRelevantFile(rfilename string) bool {
	base := strings.ToLower(filepath.Base(rfilename))
	if hfRelevantBasenames[base] {
		return true
	}
	ext := strings.ToLower(filepath.Ext(rfilename))
	return hfRelevantExtensions[ext]
}

// ── target parsing ──────────────────────────────────────────────────────────

// hfTarget is the parsed shape of an `hf:org/model[@revision]` target.
type hfTarget struct {
	Org      string
	Model    string
	Revision string
}

// String returns the canonical "org/model" form used for ResolvedPackage.Name.
func (t hfTarget) String() string {
	return t.Org + "/" + t.Model
}

// parseHFTarget parses an `hf:org/model[@revision]` string. The leading `hf:`
// prefix is required; the revision is optional and defaults to defaultRevision
// (which is itself defaulted to DefaultHFRevision when empty).
func parseHFTarget(target, defaultRevision string) (hfTarget, error) {
	const prefix = "hf:"
	if !strings.HasPrefix(target, prefix) {
		return hfTarget{}, fmt.Errorf("hf target must start with %q (got %q)", prefix, target)
	}
	body := strings.TrimPrefix(target, prefix)
	if body == "" {
		return hfTarget{}, fmt.Errorf("hf target is empty after %q prefix", prefix)
	}

	revision := defaultRevision
	if revision == "" {
		revision = DefaultHFRevision
	}
	if at := strings.LastIndex(body, "@"); at != -1 {
		revision = body[at+1:]
		body = body[:at]
		if strings.TrimSpace(revision) == "" {
			return hfTarget{}, fmt.Errorf("hf target has empty revision after '@' (target=%q)", target)
		}
		if strings.ContainsAny(revision, "/\\") {
			return hfTarget{}, fmt.Errorf("hf revision must not contain path separators (revision=%q)", revision)
		}
	}

	parts := strings.Split(body, "/")
	if len(parts) != 2 {
		return hfTarget{}, fmt.Errorf("hf target must be of the form 'org/model[@revision]' (got %q)", target)
	}
	org := strings.TrimSpace(parts[0])
	model := strings.TrimSpace(parts[1])
	if org == "" || model == "" {
		return hfTarget{}, fmt.Errorf("hf target has empty org or model (target=%q)", target)
	}
	if strings.ContainsAny(org, "\\") || strings.ContainsAny(model, "\\") {
		return hfTarget{}, fmt.Errorf("hf target must not contain backslashes (target=%q)", target)
	}
	return hfTarget{Org: org, Model: model, Revision: revision}, nil
}

// ── manifest types ──────────────────────────────────────────────────────────

// hfManifest mirrors the subset of the HF API model-info response we need.
type hfManifest struct {
	Siblings []hfSibling `json:"siblings"`
}

// hfSibling is a single file entry from the HF manifest.
type hfSibling struct {
	Rfilename string `json:"rfilename"`
}

// ── HF resolver options ─────────────────────────────────────────────────────

// HFConfig captures the runtime configuration for the Hugging Face resolver.
type HFConfig struct {
	// Token is the HF API token used as a bearer for gated models.
	Token string

	// Revision is the default revision used when the target omits one.
	Revision string

	// CacheDir is the absolute path to the cache root.
	CacheDir string

	// MaxFileBytes caps the size of a single sibling file.
	MaxFileBytes int64

	// MaxCacheBytes caps the total cumulative on-disk size for one resolve.
	MaxCacheBytes int64

	// BaseURL is the HF host. Tests override via WithHFBaseURL.
	BaseURL string

	// HTTPClient is the HTTP client used for all HF requests.
	HTTPClient *http.Client
}

// applyDefaults fills in unset fields with sensible defaults.
func (c *HFConfig) applyDefaults() {
	if c.Revision == "" {
		c.Revision = DefaultHFRevision
	}
	if c.CacheDir == "" {
		c.CacheDir = defaultHFCacheDir()
	}
	if c.MaxFileBytes <= 0 {
		c.MaxFileBytes = DefaultHFMaxFileBytes
	}
	if c.MaxCacheBytes <= 0 {
		c.MaxCacheBytes = DefaultHFMaxCacheBytes
	}
	if c.BaseURL == "" {
		c.BaseURL = DefaultHFBaseURL
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: hfHTTPTimeout}
	}
}

// defaultHFCacheDir returns `~/.cache/oxvault/hf`. Falls back to OS temp dir.
func defaultHFCacheDir() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".cache", "oxvault", "hf")
	}
	return filepath.Join(os.TempDir(), "oxvault-hf-cache")
}

// ── resolver options for HF ─────────────────────────────────────────────────

// resolverOptions is the set of functional options for the resolver.
type resolverOptions struct {
	hf HFConfig
}

// ResolverOption configures the resolver.
type ResolverOption func(*resolverOptions)

// WithHFConfig REPLACES the resolver's HFConfig wholesale.
func WithHFConfig(cfg HFConfig) ResolverOption {
	return func(o *resolverOptions) { o.hf = cfg }
}

// WithHFToken sets the HF API token used as a bearer for gated repos.
func WithHFToken(token string) ResolverOption {
	return func(o *resolverOptions) { o.hf.Token = token }
}

// WithHFRevision sets the default revision used when the target omits one.
func WithHFRevision(rev string) ResolverOption {
	return func(o *resolverOptions) { o.hf.Revision = rev }
}

// WithHFCacheDir sets the cache root used to materialise HF repos to disk.
func WithHFCacheDir(dir string) ResolverOption {
	return func(o *resolverOptions) { o.hf.CacheDir = dir }
}

// WithHFMaxFileBytes sets the per-file safety cap.
func WithHFMaxFileBytes(n int64) ResolverOption {
	return func(o *resolverOptions) { o.hf.MaxFileBytes = n }
}

// WithHFMaxCacheBytes sets the total-cache safety cap.
func WithHFMaxCacheBytes(n int64) ResolverOption {
	return func(o *resolverOptions) { o.hf.MaxCacheBytes = n }
}

// WithHFBaseURL sets the HF host. Tests use this to point at httptest.Server.
func WithHFBaseURL(u string) ResolverOption {
	return func(o *resolverOptions) { o.hf.BaseURL = u }
}

// WithHFHTTPClient sets the HTTP client.
func WithHFHTTPClient(c *http.Client) ResolverOption {
	return func(o *resolverOptions) { o.hf.HTTPClient = c }
}

// NewResolverWithOptions constructs a resolver with HF-specific configuration.
// The plain `NewResolver(logger)` constructor remains the default for call
// sites that don't need HF wiring.
func NewResolverWithOptions(logger *slog.Logger, opts ...ResolverOption) Resolver {
	o := &resolverOptions{}
	for _, opt := range opts {
		opt(o)
	}
	return &resolver{logger: logger, hf: o.hf}
}

// ── resolver implementation ─────────────────────────────────────────────────

// resolveHuggingFaceImpl materialises the target HF repo's relevant files
// under a cache dir and returns a ResolvedPackage pointing at it.
func (r *resolver) resolveHuggingFaceImpl(target string) (*ResolvedPackage, error) {
	hfCfg := r.hf // local copy so applyDefaults doesn't mutate the resolver
	hfCfg.applyDefaults()

	parsed, err := parseHFTarget(target, hfCfg.Revision)
	if err != nil {
		return nil, fmt.Errorf("hf resolve: %w", err)
	}
	r.logger.Info("resolving hf target",
		"org", parsed.Org,
		"model", parsed.Model,
		"revision", parsed.Revision,
	)

	cacheDir := filepath.Join(hfCfg.CacheDir, parsed.Org, parsed.Model, parsed.Revision)
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return nil, fmt.Errorf("hf cache mkdir %s: %w", cacheDir, err)
	}

	ctx := context.Background()

	manifest, err := r.fetchHFManifest(ctx, hfCfg, parsed)
	if err != nil {
		return nil, fmt.Errorf("hf manifest: %w", err)
	}

	// Filter siblings to security-relevant files only.
	var relevant []string
	for _, s := range manifest.Siblings {
		if s.Rfilename == "" {
			continue
		}
		if !isSafeRelPath(s.Rfilename) {
			r.logger.Warn("hf: skipping unsafe sibling path",
				"rfilename", s.Rfilename,
				"target", parsed.String(),
			)
			continue
		}
		if isHFRelevantFile(s.Rfilename) {
			relevant = append(relevant, s.Rfilename)
		}
	}

	if len(relevant) == 0 {
		r.logger.Warn("hf: no security-relevant files in repo",
			"target", parsed.String(),
			"revision", parsed.Revision,
			"siblings_total", len(manifest.Siblings),
		)
	}

	var totalBytes int64
	for _, rel := range relevant {
		dest := filepath.Join(cacheDir, filepath.FromSlash(rel))
		fileSize, err := r.fetchHFFile(ctx, hfCfg, parsed, rel, dest, totalBytes)
		if err != nil {
			return nil, fmt.Errorf("hf download %s: %w", rel, err)
		}
		totalBytes += fileSize
	}

	r.logger.Info("hf resolve complete",
		"target", parsed.String(),
		"revision", parsed.Revision,
		"files", len(relevant),
		"bytes", totalBytes,
		"cache", cacheDir,
	)

	return &ResolvedPackage{
		Path:    cacheDir,
		Kind:    KindModelDirectory,
		Name:    parsed.String(),
		Version: parsed.Revision,
	}, nil
}

// ── HTTP helpers ────────────────────────────────────────────────────────────

// fetchHFManifest calls the HF API model-info endpoint and decodes siblings.
func (r *resolver) fetchHFManifest(ctx context.Context, cfg HFConfig, t hfTarget) (*hfManifest, error) {
	endpoint, err := url.JoinPath(cfg.BaseURL, "api", "models", t.Org, t.Model, "revision", t.Revision)
	if err != nil {
		return nil, fmt.Errorf("build manifest url: %w", err)
	}

	body, err := r.doHFRequest(ctx, cfg, http.MethodGet, endpoint, t)
	if err != nil {
		return nil, err
	}
	defer func() { _ = body.Close() }()

	limited := io.LimitReader(body, hfMaxManifestBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read manifest body: %w", err)
	}
	if int64(len(data)) > hfMaxManifestBytes {
		return nil, fmt.Errorf("hf manifest exceeds %d-byte safety cap", hfMaxManifestBytes)
	}

	var manifest hfManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("decode manifest json: %w", err)
	}
	return &manifest, nil
}

// fetchHFFile downloads a single sibling to dest. Returns bytes written.
// Idempotent: if dest already exists with matching size, the download is
// skipped. totalSoFar is the cumulative bytes downloaded before this file
// — the function errors out if the next download would exceed the cap.
func (r *resolver) fetchHFFile(ctx context.Context, cfg HFConfig, t hfTarget, rel, dest string, totalSoFar int64) (int64, error) {
	endpoint, err := url.JoinPath(cfg.BaseURL, t.Org, t.Model, "resolve", t.Revision, rel)
	if err != nil {
		return 0, fmt.Errorf("build file url: %w", err)
	}

	remoteSize, err := r.headHFFile(ctx, cfg, endpoint, t)
	if err != nil {
		return 0, err
	}

	if cfg.MaxFileBytes > 0 && remoteSize > cfg.MaxFileBytes {
		r.logger.Warn("hf: skipping oversized file",
			"rfilename", rel,
			"size", remoteSize,
			"cap", cfg.MaxFileBytes,
		)
		return 0, nil
	}

	if cfg.MaxCacheBytes > 0 && totalSoFar+remoteSize > cfg.MaxCacheBytes {
		return 0, fmt.Errorf(
			"total cache size would exceed %d-byte cap (next file %q is %d bytes, current total %d)",
			cfg.MaxCacheBytes, rel, remoteSize, totalSoFar,
		)
	}

	if info, err := os.Stat(dest); err == nil && !info.IsDir() && (remoteSize <= 0 || info.Size() == remoteSize) {
		r.logger.Debug("hf: cache hit",
			"rfilename", rel,
			"size", info.Size(),
		)
		return info.Size(), nil
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return 0, fmt.Errorf("mkdir for %s: %w", rel, err)
	}

	body, err := r.doHFRequest(ctx, cfg, http.MethodGet, endpoint, t)
	if err != nil {
		return 0, err
	}
	defer func() { _ = body.Close() }()

	tmp, err := os.CreateTemp(filepath.Dir(dest), ".oxvault-hf-*")
	if err != nil {
		return 0, fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	cap := cfg.MaxFileBytes
	if cap <= 0 {
		cap = DefaultHFMaxFileBytes
	}
	limited := io.LimitReader(body, cap+1)
	written, err := io.Copy(tmp, limited)
	if err != nil {
		cleanup()
		return 0, fmt.Errorf("write %s: %w", rel, err)
	}
	if written > cap {
		cleanup()
		return 0, fmt.Errorf("file %s exceeds per-file safety cap of %d bytes", rel, cap)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return 0, fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, dest); err != nil {
		_ = os.Remove(tmpName)
		return 0, fmt.Errorf("rename to %s: %w", dest, err)
	}
	return written, nil
}

// headHFFile issues a HEAD request and returns the declared Content-Length.
// Returns 0 (not an error) when the server omits Content-Length.
func (r *resolver) headHFFile(ctx context.Context, cfg HFConfig, endpoint string, t hfTarget) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, endpoint, nil)
	if err != nil {
		return 0, fmt.Errorf("build HEAD request: %w", err)
	}
	if cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}
	req.Header.Set("User-Agent", hfUserAgent())

	resp, err := r.doHFRoundTrip(cfg, req, t)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	cl := resp.Header.Get("Content-Length")
	if cl == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(cl, 10, 64)
	if err != nil || n < 0 {
		return 0, nil
	}
	return n, nil
}

// doHFRequest issues a request and returns the response body for streaming.
func (r *resolver) doHFRequest(ctx context.Context, cfg HFConfig, method, endpoint string, t hfTarget) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build %s request: %w", method, err)
	}
	if cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}
	req.Header.Set("User-Agent", hfUserAgent())
	req.Header.Set("Accept", "*/*")

	resp, err := r.doHFRoundTrip(cfg, req, t)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// doHFRoundTrip executes req with retry on 5xx + Retry-After-aware 429.
func (r *resolver) doHFRoundTrip(cfg HFConfig, req *http.Request, t hfTarget) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt <= hfMaxRetries; attempt++ {
		reqClone := req.Clone(req.Context())
		resp, err := cfg.HTTPClient.Do(reqClone)
		if err != nil {
			lastErr = err
			if attempt < hfMaxRetries && !errors.Is(err, context.Canceled) {
				if waitErr := sleepWithContext(req.Context(), backoff(attempt)); waitErr != nil {
					return nil, waitErr
				}
				continue
			}
			return nil, fmt.Errorf("hf %s %s: %w", req.Method, req.URL.String(), err)
		}

		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			return resp, nil
		case resp.StatusCode == http.StatusUnauthorized:
			drainAndClose(resp)
			return nil, fmt.Errorf(
				"hf authentication required for %s/%s (status 401) — set HF_TOKEN or pass --hf-token",
				t.Org, t.Model,
			)
		case resp.StatusCode == http.StatusForbidden:
			drainAndClose(resp)
			return nil, fmt.Errorf(
				"hf access denied for %s/%s (status 403) — gated model? set HF_TOKEN or pass --hf-token, and confirm the account has been granted access",
				t.Org, t.Model,
			)
		case resp.StatusCode == http.StatusNotFound:
			drainAndClose(resp)
			return nil, fmt.Errorf(
				"hf model not found: %s/%s@%s (status 404)",
				t.Org, t.Model, t.Revision,
			)
		case resp.StatusCode == http.StatusTooManyRequests:
			retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
			drainAndClose(resp)
			if attempt >= hfMaxRetries {
				lastErr = fmt.Errorf("hf rate-limited (status 429) after %d attempts", attempt+1)
				return nil, lastErr
			}
			delay := retryAfter
			if delay <= 0 {
				delay = backoff(attempt)
			}
			if waitErr := sleepWithContext(req.Context(), delay); waitErr != nil {
				return nil, waitErr
			}
			continue
		case resp.StatusCode >= 500:
			drainAndClose(resp)
			lastErr = fmt.Errorf("hf server error %d on %s", resp.StatusCode, req.URL.String())
			if attempt >= hfMaxRetries {
				return nil, lastErr
			}
			if waitErr := sleepWithContext(req.Context(), backoff(attempt)); waitErr != nil {
				return nil, waitErr
			}
			continue
		default:
			drainAndClose(resp)
			return nil, fmt.Errorf("hf unexpected status %d on %s", resp.StatusCode, req.URL.String())
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("hf request exhausted retries on %s", req.URL.String())
	}
	return nil, lastErr
}

// drainAndClose drains and closes resp.Body so the underlying connection
// can be reused.
func drainAndClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	_ = resp.Body.Close()
}

// backoff returns the delay before the (attempt+1)th retry. Exponential.
func backoff(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	return hfRetryBaseDelay * (1 << attempt)
}

// parseRetryAfter parses the Retry-After header per RFC 7231 §7.1.3.
// Only the seconds form is supported.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	return 0
}

// sleepWithContext waits `d` while honouring ctx.Done().
func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// hfUserAgent returns the User-Agent used on every HF request.
func hfUserAgent() string {
	return "oxvault-scanner/0.4 (+https://oxvault.dev)"
}

// isSafeRelPath returns true when rel does not escape the cache dir.
func isSafeRelPath(rel string) bool {
	if rel == "" {
		return false
	}
	if strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "\\") {
		return false
	}
	cleaned := filepath.ToSlash(filepath.Clean(rel))
	if cleaned == "." || strings.HasPrefix(cleaned, "../") || cleaned == ".." {
		return false
	}
	for _, seg := range strings.Split(cleaned, "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}
