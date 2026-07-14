package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oxvault/scanner/internal/userconfig"
)

// meServer spins up an httptest server standing in for the platform's
// GET /api/v1/auth/me. It records the Bearer token it last received and
// responds with status/body driven by the caller.
type meServer struct {
	*httptest.Server
	gotAuth string
}

func newMeServer(t *testing.T, status int) *meServer {
	t.Helper()
	ms := &meServer{}
	ms.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/me" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		ms.gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(status)
		if status == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user":      map[string]any{"email": "dev@oxvault.dev"},
				"workspace": map[string]any{"name": "Acme", "slug": "acme"},
			})
		}
	}))
	t.Cleanup(ms.Close)
	return ms
}

// isolateConfig points userconfig at a throwaway path and clears every env
// var the login flow reads, so tests never touch the real ~/.oxvault or leak
// the developer's shell environment into resolution.
func isolateConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	t.Setenv("OXVAULT_CONFIG", path)
	t.Setenv("OXVAULT_API_KEY", "")
	t.Setenv("OXVAULT_API_URL", "")
	t.Setenv("OXVAULT_CONSOLE_URL", "")
	return path
}

// failPrompt is the injected prompt for cases where it must NOT be called.
func failPrompt(t *testing.T) func() (string, error) {
	t.Helper()
	return func() (string, error) {
		t.Fatal("prompt should not have been called")
		return "", nil
	}
}

func TestRunLoginFlow_KeyResolutionPrecedence(t *testing.T) {
	tests := []struct {
		name       string
		flagKey    string
		envKey     string
		prompt     func() (string, error)
		wantBearer string
	}{
		{
			name:       "flag wins over env and prompt",
			flagKey:    "ox_flagkey1234",
			envKey:     "ox_envkey1234",
			prompt:     func() (string, error) { return "ox_promptkey1234", nil },
			wantBearer: "Bearer ox_flagkey1234",
		},
		{
			name:       "env wins over prompt when no flag",
			flagKey:    "",
			envKey:     "ox_envkey1234",
			prompt:     func() (string, error) { return "ox_promptkey1234", nil },
			wantBearer: "Bearer ox_envkey1234",
		},
		{
			name:       "prompt used when flag and env empty",
			flagKey:    "",
			envKey:     "",
			prompt:     func() (string, error) { return "ox_promptkey1234", nil },
			wantBearer: "Bearer ox_promptkey1234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolateConfig(t)
			if tt.envKey != "" {
				t.Setenv("OXVAULT_API_KEY", tt.envKey)
			}
			srv := newMeServer(t, http.StatusOK)

			err := runLoginFlow(tt.flagKey, srv.URL, "", tt.prompt)
			if err != nil {
				t.Fatalf("runLoginFlow: unexpected error: %v", err)
			}
			if srv.gotAuth != tt.wantBearer {
				t.Errorf("bearer sent = %q, want %q", srv.gotAuth, tt.wantBearer)
			}
		})
	}
}

func TestRunLoginFlow_RejectsBadPrefix(t *testing.T) {
	path := isolateConfig(t)
	// No server should be hit; a call would fail the URL join / request but
	// the prefix guard must fire first. Use a bogus URL to be sure.
	err := runLoginFlow("badkey123", "http://127.0.0.1:0", "", failPrompt(t))
	if err == nil {
		t.Fatal("expected error for non-ox_ key")
	}
	if !strings.Contains(err.Error(), "ox_") {
		t.Errorf("error = %q, want it to mention the ox_ prefix", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("config must not be written on prefix rejection (stat err = %v)", statErr)
	}
}

func TestRunLoginFlow_ValidWritesConfig(t *testing.T) {
	path := isolateConfig(t)
	srv := newMeServer(t, http.StatusOK)

	err := runLoginFlow("ox_validkey1234", srv.URL, "", failPrompt(t))
	if err != nil {
		t.Fatalf("runLoginFlow: unexpected error: %v", err)
	}

	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("expected config written at %s: %v", path, statErr)
	}
	uc, err := userconfig.Load()
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if uc.Push.APIKey != "ox_validkey1234" {
		t.Errorf("api_key = %q, want ox_validkey1234", uc.Push.APIKey)
	}
	if uc.Push.APIURL != srv.URL {
		t.Errorf("api_url = %q, want %q", uc.Push.APIURL, srv.URL)
	}
	if uc.Push.ConsoleURL == "" {
		t.Error("console_url must be populated")
	}
}

func TestRunLoginFlow_InvalidKeyDoesNotWrite(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			path := isolateConfig(t)
			srv := newMeServer(t, status)

			err := runLoginFlow("ox_invalidkey1234", srv.URL, "", failPrompt(t))
			if err == nil {
				t.Fatal("expected error for rejected key")
			}
			if !strings.Contains(err.Error(), "invalid API key") {
				t.Errorf("error = %q, want it to mention invalid API key", err)
			}
			if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
				t.Errorf("config must not be written on auth failure (stat err = %v)", statErr)
			}
		})
	}
}

func TestRunLoginFlow_PreservesExistingSettings(t *testing.T) {
	path := isolateConfig(t)
	// Pre-seed a config with auto=true; login must keep it.
	seed := &userconfig.Config{}
	seed.Push.Auto = true
	seed.Push.APIKey = "ox_oldkey1234"
	if err := userconfig.Save(seed); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	srv := newMeServer(t, http.StatusOK)
	if err := runLoginFlow("ox_newkey5678", srv.URL, "", failPrompt(t)); err != nil {
		t.Fatalf("runLoginFlow: %v", err)
	}

	uc, err := userconfig.Load()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !uc.Push.Auto {
		t.Error("existing [push].auto=true was clobbered")
	}
	if uc.Push.APIKey != "ox_newkey5678" {
		t.Errorf("api_key = %q, want ox_newkey5678", uc.Push.APIKey)
	}
	_ = path
}

func TestRedactKey(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"ox_abcdef1234", "ox_…1234"},
		{"ox_short", "ox_…"},
		{"", "ox_…"},
	}
	for _, tt := range tests {
		if got := redactKey(tt.in); got != tt.want {
			t.Errorf("redactKey(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if tt.in != "" && len(tt.in) > 8 && strings.Contains(redactKey(tt.in), tt.in) {
			t.Errorf("redactKey leaked the full key for %q", tt.in)
		}
	}
}
