// Package config loads and validates Zeerak's YAML config.
//
// Per VISION.md §11 Q3 (UI vs file ownership):
//
//   - /etc/zeerak/zeerak.yaml is the *hand-edited* file. Loaded on startup
//     and on SIGHUP / `zeerak reload`. Never rewritten by the UI.
//   - /var/lib/zeerak/autosave.yaml is the *UI/API-managed* file. Persisted
//     after every successful commit. Loaded last, overlays the hand-edited
//     file, and is the source of truth for what's currently running.
//
// `zeerak config export` dumps the current running (merged) config as clean
// YAML for git.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/zeerak/zeerak/internal/policy"
)

// DefaultPath is the canonical hand-edited config location.
const DefaultPath = "/etc/zeerak/zeerak.yaml"

// DefaultAutosavePath is where UI/API edits are persisted.
const DefaultAutosavePath = "/var/lib/zeerak/autosave.yaml"

// Config is the on-disk shape of zeerak.yaml.
//
// The schema is intentionally tiny in v0.1: just enough to hold a list of
// nft tables/chains/rules and a few server knobs. Higher-level "policy"
// shapes (zones, services, presets) land in v0.1 once the renderer round-trip
// is green.
type Config struct {
	Version int    `yaml:"version"` // schema version; only 1 is valid in v0.1
	Server  Server `yaml:"server,omitempty"`
	// Higher-level presets (caddy_box, ssh, default_deny_inbound) compile to
	// the table `inet zeerak-presets` via internal/policy. See VISION.md §11 Q1.
	Presets policy.Presets `yaml:"presets,omitempty"`
	// Raw nftables-mirror objects. Layered on top of the compiled presets.
	Tables []TableSpec `yaml:"tables,omitempty"`
}

// Server holds daemon-level knobs.
type Server struct {
	Listen          string `yaml:"listen,omitempty"`           // default 127.0.0.1:7878
	Socket          string `yaml:"socket,omitempty"`           // default /run/zeerak/zeerak.sock
	RollbackSeconds int    `yaml:"rollback_seconds,omitempty"` // default 60
}

// TableSpec is the YAML projection of model.Table.
// Kept small for v0.1; will grow as the model does.
type TableSpec struct {
	Family string       `yaml:"family"`
	Name   string       `yaml:"name"`
	Chains []ChainSpec  `yaml:"chains,omitempty"`
}

// ChainSpec is the YAML projection of model.Chain.
type ChainSpec struct {
	Name     string     `yaml:"name"`
	Type     string     `yaml:"type,omitempty"`
	Hook     string     `yaml:"hook,omitempty"`
	Priority int        `yaml:"priority,omitempty"`
	Policy   string     `yaml:"policy,omitempty"`
	Rules    []RuleSpec `yaml:"rules,omitempty"`
}

// RuleSpec is the YAML projection of model.Rule.
type RuleSpec struct {
	Expr    string `yaml:"expr"`
	Comment string `yaml:"comment,omitempty"`
}

// Load reads and validates the config at path. Missing file is an error;
// callers (e.g. `zeerak-server`) decide whether to seed a default.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("validate %s: %w", path, err)
	}
	return &c, nil
}

// Validate performs cheap, deterministic checks. The full nftables-semantic
// validation lives in internal/render (the renderer is the validator).
func (c *Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("unsupported config version %d (expected 1)", c.Version)
	}
	if err := c.Presets.Validate(); err != nil {
		return err
	}
	for i, t := range c.Tables {
		if t.Family == "" || t.Name == "" {
			return fmt.Errorf("tables[%d]: family and name are required", i)
		}
	}
	return nil
}
