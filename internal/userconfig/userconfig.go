// Package userconfig loads ~/.oxvault/config.toml — the persistent
// per-user preferences for the Oxvault CLI.
//
// Schema:
//
//	[push]
//	auto        = true                          # auto-upload after every scan
//	api_key     = "ox_…"                        # alternative to OXVAULT_API_KEY
//	api_url     = "https://platform.oxvault.dev"
//	console_url = "https://console.oxvault.dev"
//	quiet       = false
//
// The file is optional. If missing or unreadable, Load() returns a zero
// Config and no error — defaults take over.
package userconfig

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

// Config mirrors the on-disk TOML. Only [push] is defined today; other
// sections will land as the CLI grows.
type Config struct {
	Push PushSection `toml:"push"`
}

// PushSection captures the preferences that drive `oxvault scan --push`
// and the standalone `oxvault push` subcommand.
type PushSection struct {
	Auto       bool   `toml:"auto"`
	APIKey     string `toml:"api_key"`
	APIURL     string `toml:"api_url"`
	ConsoleURL string `toml:"console_url"`
	Quiet      bool   `toml:"quiet"`
}

// Path returns the canonical config path: $XDG_CONFIG_HOME/oxvault/config.toml
// when set, otherwise ~/.oxvault/config.toml. Errors only when neither HOME
// nor XDG_CONFIG_HOME can be resolved.
func Path() (string, error) {
	if x := os.Getenv("OXVAULT_CONFIG"); x != "" {
		return x, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("userconfig: cannot resolve home dir: %w", err)
	}
	return filepath.Join(home, ".oxvault", "config.toml"), nil
}

// Load reads the config from disk. A missing file is not an error — it
// returns a zero Config so callers can apply their own defaults.
func Load() (*Config, error) {
	p, err := Path()
	if err != nil {
		return &Config{}, nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("userconfig: read %s: %w", p, err)
	}
	cfg := &Config{}
	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("userconfig: parse %s: %w", p, err)
	}
	return cfg, nil
}
