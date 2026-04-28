package providers

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── parseHFTarget ──────────────────────────────────────────────────────────

func TestParseHFTarget(t *testing.T) {
	tests := []struct {
		name      string
		target    string
		defRev    string
		wantErr   bool
		wantOrg   string
		wantModel string
		wantRev   string
	}{
		{name: "simple", target: "hf:meta-llama/Llama-3-8B", defRev: "main", wantOrg: "meta-llama", wantModel: "Llama-3-8B", wantRev: "main"},
		{name: "with revision", target: "hf:org/model@v1.0", defRev: "main", wantOrg: "org", wantModel: "model", wantRev: "v1.0"},
		{name: "default rev empty -> main", target: "hf:a/b", defRev: "", wantOrg: "a", wantModel: "b", wantRev: "main"},
		{name: "missing prefix", target: "org/model", wantErr: true},
		{name: "no slash", target: "hf:nothing", wantErr: true},
		{name: "empty org", target: "hf:/model", wantErr: true},
		{name: "empty model", target: "hf:org/", wantErr: true},
		{name: "path traversal in revision", target: "hf:org/model@../../etc", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseHFTarget(tt.target, tt.defRev)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Org != tt.wantOrg || got.Model != tt.wantModel || got.Revision != tt.wantRev {
				t.Errorf("got (%q, %q, %q), want (%q, %q, %q)",
					got.Org, got.Model, got.Revision, tt.wantOrg, tt.wantModel, tt.wantRev)
			}
		})
	}
}

// ── httptest harness ───────────────────────────────────────────────────────

type hfFixture struct {
	rfilename string
	body      []byte
}

func newHFTestServer(t *testing.T, fixtures []hfFixture, opts ...func(*hfServerOpts)) *httptest.Server {
	t.Helper()
	cfg := hfServerOpts{}
	for _, o := range opts {
		o(&cfg)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// API manifest path: /api/models/{org}/{model}/revision/{rev}
		if strings.HasPrefix(r.URL.Path, "/api/models/") {
			if cfg.manifestStatus != 0 && cfg.manifestStatus != 200 {
				if cfg.retryAfter != "" {
					w.Header().Set("Retry-After", cfg.retryAfter)
				}
				w.WriteHeader(cfg.manifestStatus)
				return
			}
			siblings := make([]map[string]string, 0, len(fixtures))
			for _, f := range fixtures {
				siblings = append(siblings, map[string]string{"rfilename": f.rfilename})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"siblings": siblings})
			return
		}
		// File resolve path: /{org}/{model}/resolve/{rev}/{filename...}
		for _, f := range fixtures {
			if strings.HasSuffix(r.URL.Path, "/"+f.rfilename) {
				if r.Method == http.MethodHead {
					w.Header().Set("Content-Length", fmt.Sprintf("%d", len(f.body)))
					w.WriteHeader(http.StatusOK)
					return
				}
				w.Header().Set("Content-Length", fmt.Sprintf("%d", len(f.body)))
				_, _ = w.Write(f.body)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	})

	return httptest.NewServer(mux)
}

type hfServerOpts struct {
	manifestStatus int
	retryAfter     string
}

func withManifestStatus(code int) func(*hfServerOpts) {
	return func(o *hfServerOpts) { o.manifestStatus = code }
}

// ── happy path ─────────────────────────────────────────────────────────────

func TestHFResolver_Success(t *testing.T) {
	fixtures := []hfFixture{
		{rfilename: "config.json", body: []byte(`{"a":1}`)},
		{rfilename: "model.safetensors", body: []byte("safetensors-bytes")},
		{rfilename: "README.md", body: []byte("# model card")},
		{rfilename: "junk.bin.txt", body: []byte("ignored")},
	}
	srv := newHFTestServer(t, fixtures)
	defer srv.Close()

	cacheDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := NewResolverWithOptions(logger,
		WithHFBaseURL(srv.URL),
		WithHFCacheDir(cacheDir),
	)

	pkg, err := r.Resolve("hf:org/model")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if pkg.Kind != KindModelDirectory {
		t.Errorf("Kind = %q, want KindModelDirectory", pkg.Kind)
	}
	if pkg.Name != "org/model" {
		t.Errorf("Name = %q", pkg.Name)
	}
	// security-relevant files downloaded
	for _, want := range []string{"config.json", "model.safetensors", "README.md"} {
		if _, err := os.Stat(filepath.Join(pkg.Path, want)); err != nil {
			t.Errorf("expected %q in cache: %v", want, err)
		}
	}
	// junk.bin.txt is NOT a security-relevant file (.txt extension)
	if _, err := os.Stat(filepath.Join(pkg.Path, "junk.bin.txt")); err == nil {
		t.Error("junk.bin.txt should NOT have been downloaded (not a security artifact)")
	}
}

func TestHFResolver_CacheHit(t *testing.T) {
	fixtures := []hfFixture{
		{rfilename: "config.json", body: []byte(`{"x":1}`)},
	}
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/models/") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"siblings": []map[string]string{{"rfilename": "config.json"}},
			})
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(fixtures[0].body)))
			return
		}
		hits++
		_, _ = w.Write(fixtures[0].body)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := NewResolverWithOptions(logger, WithHFBaseURL(srv.URL), WithHFCacheDir(cacheDir))

	if _, err := r.Resolve("hf:org/model"); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if hits != 1 {
		t.Fatalf("expected 1 GET, got %d", hits)
	}
	// second resolve should hit cache (no GET)
	if _, err := r.Resolve("hf:org/model"); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if hits != 1 {
		t.Errorf("cache miss: expected 1 GET total, got %d", hits)
	}
}

// ── error paths ────────────────────────────────────────────────────────────

func TestHFResolver_Unauthorized(t *testing.T) {
	srv := newHFTestServer(t, nil, withManifestStatus(http.StatusUnauthorized))
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := NewResolverWithOptions(logger, WithHFBaseURL(srv.URL), WithHFCacheDir(t.TempDir()))
	_, err := r.Resolve("hf:org/model")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "HF_TOKEN") {
		t.Errorf("expected HF_TOKEN hint, got: %v", err)
	}
}

func TestHFResolver_NotFound(t *testing.T) {
	srv := newHFTestServer(t, nil, withManifestStatus(http.StatusNotFound))
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := NewResolverWithOptions(logger, WithHFBaseURL(srv.URL), WithHFCacheDir(t.TempDir()))
	_, err := r.Resolve("hf:org/model")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

func TestHFResolver_RetryOn5xx(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/models/") {
			calls++
			if calls < 2 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"siblings": []map[string]string{{"rfilename": "config.json"}},
			})
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", "1")
			return
		}
		_, _ = w.Write([]byte("x"))
	}))
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	client := &http.Client{Timeout: 10 * time.Second}
	r := NewResolverWithOptions(logger,
		WithHFBaseURL(srv.URL),
		WithHFCacheDir(t.TempDir()),
		WithHFHTTPClient(client),
	)
	if _, err := r.Resolve("hf:org/model"); err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if calls < 2 {
		t.Errorf("expected at least 2 manifest calls, got %d", calls)
	}
}
