package policy

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// DaemonConfig defines daemon-level operational settings.
type DaemonConfig struct {
	MetricsInterval time.Duration `yaml:"metrics_interval"`
	PendingTTL      time.Duration `yaml:"pending_ttl"`
	RingbufSizeKB   int           `yaml:"ringbuf_size_kb"`
	LogLevel        string        `yaml:"log_level"`
}

// MitigationConfig defines active response parameters.
type MitigationConfig struct {
	Enabled       bool          `yaml:"enabled"`
	Mode          string        `yaml:"mode"`           // "audit" or "enforce"
	DefaultAction string        `yaml:"default_action"` // "alert", "kill", "freeze", "quarantine"
	Cooldown      time.Duration `yaml:"cooldown"`
}

// JSONLExportConfig defines paths for JSON lines storage.
type JSONLExportConfig struct {
	EventsLog      string `yaml:"events_log"`
	AlertsLog      string `yaml:"alerts_log"`
	MitigationsLog string `yaml:"mitigations_log"`
}

// PrometheusConfig defines Prometheus metrics server configuration.
type PrometheusConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	Path       string `yaml:"path"`
}

// WebhookConfig defines remote alert forwarder settings.
type WebhookConfig struct {
	Enabled bool          `yaml:"enabled"`
	URL     string        `yaml:"url"`
	Timeout time.Duration `yaml:"timeout"`
}

// SQLiteExportConfig defines SQLite database storage configuration.
type SQLiteExportConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

// ExportConfig bundles all export sinks.
type ExportConfig struct {
	JSONL      JSONLExportConfig  `yaml:"jsonl"`
	SQLite     SQLiteExportConfig `yaml:"sqlite"`
	Prometheus PrometheusConfig   `yaml:"prometheus"`
	Webhook    WebhookConfig      `yaml:"webhook"`
}

// RuleConditions represents matching criteria for a detection rule.
type RuleConditions struct {
	MatchBinaries        []string `yaml:"match_binaries"`
	PathPrefixes         []string `yaml:"path_prefixes"`
	ContainerOnly        bool     `yaml:"container_only"`
	RequireSetuidFlag    bool     `yaml:"require_setuid_flag"`
	RequireEmptyPathFlag bool     `yaml:"require_empty_path_flag"`
}

// RuleDefinition represents a declarative rule specification.
type RuleDefinition struct {
	ID               string         `yaml:"id"`
	Name             string         `yaml:"name"`
	Description      string         `yaml:"description"`
	Severity         string         `yaml:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Enabled          bool           `yaml:"enabled"`
	MitigationAction string         `yaml:"mitigation_action"` // alert, kill, freeze, quarantine
	MitreAttack      []string       `yaml:"mitre_attack"`
	Conditions       RuleConditions `yaml:"conditions"`
}

// Config represents the top-level ContainerGuard policy configuration.
type Config struct {
	Version    string           `yaml:"version"`
	Daemon     DaemonConfig     `yaml:"daemon"`
	Mitigation MitigationConfig `yaml:"mitigation"`
	Export     ExportConfig     `yaml:"export"`
	Rules      []RuleDefinition `yaml:"rules"`
}

// DefaultConfig provides conservative defaults.
func DefaultConfig() *Config {
	return &Config{
		Version: "v2",
		Daemon: DaemonConfig{
			MetricsInterval: 5 * time.Second,
			PendingTTL:      2 * time.Second,
			RingbufSizeKB:   16384,
			LogLevel:        "info",
		},
		Mitigation: MitigationConfig{
			Enabled:       true,
			Mode:          "audit",
			DefaultAction: "alert",
			Cooldown:      5 * time.Second,
		},
		Export: ExportConfig{
			JSONL: JSONLExportConfig{
				EventsLog:      "exec_paths_events.jsonl",
				AlertsLog:      "exec_paths_alerts.jsonl",
				MitigationsLog: "exec_paths_mitigations.jsonl",
			},
			SQLite: SQLiteExportConfig{
				Enabled: true,
				Path:    "docs/evidence/containerguard_evidence.db",
			},
			Prometheus: PrometheusConfig{
				Enabled:    true,
				ListenAddr: ":9115",
				Path:       "/metrics",
			},
			Webhook: WebhookConfig{
				Enabled: false,
				URL:     "",
				Timeout: 3 * time.Second,
			},
		},
		Rules: nil,
	}
}

// Manager manages active policy configuration and thread-safe dynamic reloads.
type Manager struct {
	mu         sync.RWMutex
	cfgPath    string
	current    *Config
	onReload   []func(oldCfg, newCfg *Config)
	stopReload chan struct{}
}

// NewManager creates a policy manager from the given file path.
func NewManager(cfgPath string) (*Manager, error) {
	m := &Manager{
		cfgPath:    cfgPath,
		current:    DefaultConfig(),
		stopReload: make(chan struct{}),
	}

	if cfgPath != "" {
		cfg, err := LoadFile(cfgPath)
		if err != nil {
			return nil, fmt.Errorf("loading initial policy config: %w", err)
		}
		m.current = cfg
	}

	return m, nil
}

// LoadFile parses and validates a policy YAML file.
func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file %s: %w", path, err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing YAML %s: %w", path, err)
	}

	if err := Validate(cfg); err != nil {
		return nil, fmt.Errorf("validating configuration: %w", err)
	}

	return cfg, nil
}

// Validate checks for structural and semantic validity.
func Validate(cfg *Config) error {
	if cfg.Daemon.RingbufSizeKB <= 0 {
		return fmt.Errorf("daemon.ringbuf_size_kb must be positive")
	}
	if cfg.Daemon.PendingTTL <= 0 {
		return fmt.Errorf("daemon.pending_ttl must be positive")
	}
	for i, r := range cfg.Rules {
		if r.ID == "" {
			return fmt.Errorf("rule[%d] missing ID", i)
		}
		if r.Severity == "" {
			return fmt.Errorf("rule[%s] missing severity", r.ID)
		}
	}
	return nil
}

// Get returns a thread-safe snapshot of the current configuration.
func (m *Manager) Get() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

// OnReload registers a callback invoked whenever configuration is reloaded.
func (m *Manager) OnReload(cb func(oldCfg, newCfg *Config)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onReload = append(m.onReload, cb)
}

// Reload re-reads configuration from disk and notifies subscribers.
func (m *Manager) Reload() error {
	if m.cfgPath == "" {
		return fmt.Errorf("no config path defined")
	}

	newCfg, err := LoadFile(m.cfgPath)
	if err != nil {
		return fmt.Errorf("reloading policy: %w", err)
	}

	m.mu.Lock()
	oldCfg := m.current
	m.current = newCfg
	callbacks := append([]func(oldCfg, newCfg *Config){}, m.onReload...)
	m.mu.Unlock()

	for _, cb := range callbacks {
		cb(oldCfg, newCfg)
	}

	return nil
}

// StartSignalReloader starts listening for SIGHUP to trigger dynamic hot-reloads.
func (m *Manager) StartSignalReloader() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)

	go func() {
		for {
			select {
			case <-sigChan:
				if err := m.Reload(); err != nil {
					fmt.Fprintf(os.Stderr, "[policy] Error reloading configuration: %v\n", err)
				} else {
					fmt.Fprintf(os.Stdout, "[policy] Configuration hot-reloaded successfully.\n")
				}
			case <-m.stopReload:
				signal.Stop(sigChan)
				return
			}
		}
	}()
}

// Close terminates reload listeners.
func (m *Manager) Close() {
	close(m.stopReload)
}
