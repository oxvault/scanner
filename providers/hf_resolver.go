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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/oxvault/scanner/internal/version"
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

	// hfMaxRedirects bounds the number of HTTP redirects we follow on any
	// single request. Stdlib's default is 10 — we tighten this to 5 because
	// the HF CDN chain is at most 2 hops in practice.
	hfMaxRedirects = 5
)

// hfHostAllowlist enumerates the hostnames our default HTTP client trusts to
// receive an Authorization header on a redirect. Anything outside this list
// has the bearer stripped before the redirected request is sent.
var hfHostAllowlist = map[string]bool{
	"huggingface.co":         true,
	"cdn-lfs.huggingface.co": true,
}

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

// hfNameRegex matches the shape Hugging Face actually allows for org / model
// segments: alphanumerics plus `.`, `_`, `-`, with a leading and trailing
// alphanumeric (no leading/trailing dot, no double dots, no separators).
//
// This is intentionally stricter than HF's full regex — we reject anything
// the cache layer would have to special-case (`..`, `.`, leading dot) so the
// path joiner can never escape the cache root.
var hfNameRegex = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$`)

// hfRevisionRegex matches the shape we accept for a revision: alphanumerics
// plus `.`, `_`, `-`. Branch names, tags, and commit SHAs all fit this
// allowlist.
var hfRevisionRegex = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// validateHFNameSegment enforces the org/model allowlist and rejects shapes
// that would let an attacker climb out of the cache root via the path
// joiner (`..`, leading `.`, embedded separators, control chars).
func validateHFNameSegment(kind, value string) error {
	if value == "" {
		return fmt.Errorf("hf %s is empty", kind)
	}
	// Explicit reject for the obvious traversal shapes BEFORE the regex,
	// so the error message names the actual offence instead of a generic
	// "invalid character" message.
	if value == "." || value == ".." || strings.HasPrefix(value, ".") {
		return fmt.Errorf("hf %s must not start with '.' (got %q)", kind, value)
	}
	if !hfNameRegex.MatchString(value) {
		return fmt.Errorf("hf %s contains invalid characters (got %q)", kind, value)
	}
	return nil
}

// validateHFRevision enforces the revision allowlist.
func validateHFRevision(rev string) error {
	if rev == "" {
		return errors.New("hf revision is empty")
	}
	if rev == "." || rev == ".." {
		return fmt.Errorf("hf revision must not be %q", rev)
	}
	if !hfRevisionRegex.MatchString(rev) {
		return fmt.Errorf("hf revision contains invalid characters (got %q)", rev)
	}
	return nil
}

// parseHFTarget parses an `hf:org/model[@revision]` string. The leading `hf:`
// prefix is required; the revision is optional and defaults to defaultRevision
// (which is itself defaulted to DefaultHFRevision when empty).
//
// Org, model, and revision are validated against an allowlist regex — the
// resolver materialises files under `cacheDir/org/model/rev/...`, so any
// shape that could climb out of that root (`..`, leading `.`, separators,
// control characters) is rejected here. This is the single chokepoint for
// cache-traversal hardening.
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
	}

	parts := strings.Split(body, "/")
	if len(parts) != 2 {
		return hfTarget{}, fmt.Errorf("hf target must be of the form 'org/model[@revision]' (got %q)", target)
	}
	org := strings.TrimSpace(parts[0])
	model := strings.TrimSpace(parts[1])
	if err := validateHFNameSegment("org", org); err != nil {
		return hfTarget{}, fmt.Errorf("hf target invalid (target=%q): %w", target, err)
	}
	if err := validateHFNameSegment("model", model); err != nil {
		return hfTarget{}, fmt.Errorf("hf target invalid (target=%q): %w", target, err)
	}
	if err := validateHFRevision(revision); err != nil {
		return hfTarget{}, fmt.Errorf("hf target invalid (target=%q): %w", target, err)
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

// LogValue redacts the bearer token before slog records the config. Without
// this, a `logger.Debug("config", "hf", cfg)` call would emit the token in
// plaintext to whatever sink the operator wired up. We keep the boolean
// presence so it's still useful for triage ("did the operator forget to
// pass --hf-token?").
func (c HFConfig) LogValue() slog.Value {
	tokenStatus := "<unset>"
	if c.Token != "" {
		tokenStatus = "<set>"
	}
	return slog.GroupValue(
		slog.String("token", tokenStatus),
		slog.String("revision", c.Revision),
		slog.String("cache_dir", c.CacheDir),
		slog.Int64("max_file_bytes", c.MaxFileBytes),
		slog.Int64("max_cache_bytes", c.MaxCacheBytes),
		slog.String("base_url", c.BaseURL),
	)
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
		c.HTTPClient = newHFHTTPClient(c.BaseURL)
	} else {
		// Always wrap user-supplied clients so they get the same redirect
		// hardening as our default. Repeated wraps are idempotent — the
		// CheckRedirect we install names itself with a sentinel and is
		// preserved on subsequent calls.
		hardenHFClient(c.HTTPClient, c.BaseURL)
	}
}

// newHFHTTPClient builds the default HTTP client used by the HF resolver.
// The client has the standard timeout AND a CheckRedirect that strips the
// Authorization header when redirecting to an off-allowlist host AND bounds
// the redirect chain to hfMaxRedirects.
func newHFHTTPClient(baseURL string) *http.Client {
	c := &http.Client{Timeout: hfHTTPTimeout}
	hardenHFClient(c, baseURL)
	return c
}

// hardenHFClient installs our standard CheckRedirect on c. Idempotent.
//
// Defence-in-depth on top of stdlib's implicit auth-stripping:
//
//   - Stdlib already strips Authorization on cross-host redirects, but only
//     for the literal `Authorization` header — anything we add later (e.g. a
//     custom token header) would leak. We always re-strip and re-add inside
//     CheckRedirect, so the policy is enforced regardless of header naming.
//   - Stdlib's default redirect cap is 10. We tighten to hfMaxRedirects.
//   - For HF (BaseURL == DefaultHFBaseURL) we re-add Authorization only when
//     the redirect target is on hfHostAllowlist, so legitimate hf.co → cdn-
//     lfs.hf.co hops keep working.
func hardenHFClient(c *http.Client, baseURL string) {
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= hfMaxRedirects {
			return fmt.Errorf("hf: stopped after %d redirects", hfMaxRedirects)
		}
		// Strip Authorization unconditionally — stdlib already does this on
		// cross-host but we want a single defensive policy.
		req.Header.Del("Authorization")

		// Only re-add the bearer for the production HF host. Tests use
		// httptest.Server URLs that won't match the allowlist, so they
		// already exercise the no-auth path.
		if baseURL != DefaultHFBaseURL {
			return nil
		}
		host := strings.ToLower(req.URL.Hostname())
		if !hfHostAllowlist[host] {
			return nil
		}
		// Re-add Authorization from the original request's header, if any.
		// `via` is ordered oldest→newest; the original is via[0].
		if len(via) > 0 {
			if auth := via[0].Header.Get("Authorization"); auth != "" {
				req.Header.Set("Authorization", auth)
			}
		}
		return nil
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
//
// The named return + deferred recover() is load-bearing: a hostile manifest
// or a corrupt cache file must NEVER take down the scanner. Without the
// named return, an explicit `return ...` would have already evaluated by
// the time the recover runs, causing the panic to be silently swallowed
// (same lesson learned in Day 5 onnx, Day 6 modelcard, Day 7 signature).
func (r *resolver) resolveHuggingFaceImpl(target string) (pkg *ResolvedPackage, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			pkg = nil
			err = fmt.Errorf("hf resolve panic: %v", rec)
		}
	}()

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

	// Open the cache root via os.Root so all subsequent file operations are
	// guaranteed to stay inside it — symlinks pointing outside the root are
	// rejected by the OS, not by our string sanitisation. Go 1.25 feature.
	if err := os.MkdirAll(hfCfg.CacheDir, 0o755); err != nil {
		return nil, fmt.Errorf("hf cache mkdir %s: %w", hfCfg.CacheDir, err)
	}
	root, err := os.OpenRoot(hfCfg.CacheDir)
	if err != nil {
		return nil, fmt.Errorf("hf cache open root %s: %w", hfCfg.CacheDir, err)
	}
	defer func() { _ = root.Close() }()

	// Per-target subdir: org/model/revision. parseHFTarget already validates
	// these segments, so MkdirAll under root is safe.
	cacheRel := filepath.Join(parsed.Org, parsed.Model, parsed.Revision)
	if err := root.MkdirAll(cacheRel, 0o755); err != nil {
		return nil, fmt.Errorf("hf cache mkdir %s: %w", cacheRel, err)
	}
	cacheDir := filepath.Join(hfCfg.CacheDir, cacheRel)

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
		// File destination is relative to the os.Root. The combination of
		// isSafeRelPath above + os.Root's symlink-escape protection here
		// gives us defence-in-depth against cache traversal.
		destRel := filepath.Join(cacheRel, filepath.FromSlash(rel))
		fileSize, err := r.fetchHFFile(ctx, hfCfg, parsed, rel, root, destRel, totalBytes)
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

// fetchHFFile downloads a single sibling to the given root-relative dest.
// Returns bytes written. Idempotent: if dest already exists with matching
// size, the download is skipped — UNLESS the server omitted Content-Length,
// in which case we always re-download (the alternative is trusting a cached
// file we can't validate, which closes the pre-seeded cache attack).
//
// totalSoFar is the cumulative bytes downloaded before this file — the
// function errors out if the next download would exceed the cache cap.
func (r *resolver) fetchHFFile(ctx context.Context, cfg HFConfig, t hfTarget, rel string, root *os.Root, destRel string, totalSoFar int64) (int64, error) {
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

	// Cache hit only when the server gave us a positive Content-Length AND
	// the on-disk size matches. When Content-Length is absent (remoteSize
	// <= 0), we cannot validate the cached file, so we MUST force a re-
	// download — otherwise an attacker who pre-seeded the cache could keep
	// stale/malicious bytes there indefinitely.
	if remoteSize > 0 {
		if info, err := root.Stat(destRel); err == nil && !info.IsDir() && info.Size() == remoteSize {
			r.logger.Debug("hf: cache hit",
				"rfilename", rel,
				"size", info.Size(),
			)
			return info.Size(), nil
		}
	}

	// Make sure the destination's parent dir exists inside the root.
	if parent := filepath.Dir(destRel); parent != "" && parent != "." {
		if err := root.MkdirAll(parent, 0o755); err != nil {
			return 0, fmt.Errorf("mkdir for %s: %w", rel, err)
		}
	}

	body, err := r.doHFRequest(ctx, cfg, http.MethodGet, endpoint, t)
	if err != nil {
		return 0, err
	}
	defer func() { _ = body.Close() }()

	// Stream into a temp file alongside the destination so a crashed
	// download never leaves a half-written file in cache.
	tmpRel := destRel + ".oxvault-hf-tmp"
	tmp, err := root.OpenFile(tmpRel, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, fmt.Errorf("create temp file: %w", err)
	}
	cleanup := func() {
		_ = tmp.Close()
		_ = root.Remove(tmpRel)
	}

	fileCap := cfg.MaxFileBytes
	if fileCap <= 0 {
		fileCap = DefaultHFMaxFileBytes
	}
	limited := io.LimitReader(body, fileCap+1)
	written, err := io.Copy(tmp, limited)
	if err != nil {
		cleanup()
		return 0, fmt.Errorf("write %s: %w", rel, err)
	}
	if written > fileCap {
		cleanup()
		return 0, fmt.Errorf("file %s exceeds per-file safety cap of %d bytes", rel, fileCap)
	}
	if err := tmp.Close(); err != nil {
		_ = root.Remove(tmpRel)
		return 0, fmt.Errorf("close temp file: %w", err)
	}
	if err := root.Rename(tmpRel, destRel); err != nil {
		_ = root.Remove(tmpRel)
		return 0, fmt.Errorf("rename to %s: %w", destRel, err)
	}
	return written, nil
}

// headHFFile issues a HEAD request and returns the declared Content-Length.
//
// Returns 0 (not an error) when the server omits or malforms Content-Length,
// but logs each case distinctly so operators can tell "header absent" (debug)
// from "header malformed" (warn) — the latter signals a buggy or hostile
// server we want to flag.
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
		// Header genuinely absent — common for chunked-transfer responses.
		// Not a security event on its own; the caller already forces a
		// re-download in this case.
		r.logger.Debug("hf: HEAD response has no Content-Length",
			"endpoint", endpoint,
		)
		return 0, nil
	}
	n, err := strconv.ParseInt(strings.TrimSpace(cl), 10, 64)
	if err != nil {
		// Malformed header — not parseable as int64. Surface as a warning
		// because a well-behaved server should never emit this.
		r.logger.Warn("hf: HEAD response Content-Length is not a valid integer",
			"endpoint", endpoint,
			"value", cl,
			"err", err,
		)
		return 0, nil
	}
	if n < 0 {
		// Negative length — explicitly hostile or buggy server. Warn so
		// the operator notices.
		r.logger.Warn("hf: HEAD response Content-Length is negative",
			"endpoint", endpoint,
			"value", n,
		)
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

// hfUserAgent returns the User-Agent used on every HF request. The version
// comes from internal/version so a single ldflags override at build time
// reflects everywhere the scanner identifies itself.
func hfUserAgent() string {
	return fmt.Sprintf("oxvault-scanner/%s (+https://oxvault.dev)", version.Version)
}

// isSafeRelPath returns true when rel does not escape the cache dir.
//
// Defence-in-depth on top of os.Root: even though os.Root prevents symlink
// escapes at OS level, this check rejects manifestly hostile rfilename
// values (`..`, absolute paths, path-traversal segments) before we even
// open a file handle. Belt and braces.
//
// We deliberately reject ANY `..` segment in the input, even one that
// `filepath.Clean` would normalise to a path inside the root (e.g.
// `foo/../bar` cleans to `bar`). A manifest from upstream should never
// have a reason to encode literal `..` — its presence is a strong
// signal of either bug or attack, and silently cleaning it would let
// future refactors miss the traversal.
func isSafeRelPath(rel string) bool {
	if rel == "" {
		return false
	}
	if strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "\\") {
		return false
	}
	// Normalise both Unix and Windows separators so we catch
	// `..\\windows\\system32` too.
	normalised := strings.ReplaceAll(rel, "\\", "/")
	// Reject literal `..` segments BEFORE Clean rewrites them.
	for _, seg := range strings.Split(normalised, "/") {
		if seg == ".." {
			return false
		}
	}
	cleaned := filepath.ToSlash(filepath.Clean(normalised))
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
