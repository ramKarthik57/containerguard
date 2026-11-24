package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPolicyLoadAndValidate(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
version: "v2"
daemon:
  metrics_interval: 10s
  pending_ttl: 3s
  ringbuf_size_kb: 8192
  log_level: "debug"
mitigation:
  enabled: true
  mode: "enforce"
  default_action: "kill"
  cooldown: 2s
export:
  jsonl:
    events_log: "test_events.jsonl"
    alerts_log: "test_alerts.jsonl"
    mitigations_log: "test_mitigations.jsonl"
  prometheus:
    enabled: true
    listen_addr: ":9999"
    path: "/metrics"
rules:
  - id: "CG-RULE-001"
    name: "Privileged Breakout"
    severity: "CRITICAL"
    enabled: true
    mitigation_action: "kill"
    conditions:
      match_binaries: ["nsenter", "unshare"]
      container_only: true
`
	if err := os.WriteFile(cfgFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	mgr, err := NewManager(cfgFile)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer mgr.Close()

	cfg := mgr.Get()
	if cfg.Daemon.RingbufSizeKB != 8192 {
		t.Errorf("Expected RingbufSizeKB 8192, got %d", cfg.Daemon.RingbufSizeKB)
	}
	if cfg.Daemon.PendingTTL != 3*time.Second {
		t.Errorf("Expected PendingTTL 3s, got %v", cfg.Daemon.PendingTTL)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(cfg.Rules))
	}
	if cfg.Rules[0].ID != "CG-RULE-001" {
		t.Errorf("Expected rule ID CG-RULE-001, got %s", cfg.Rules[0].ID)
	}
}

func TestPolicyDynamicReload(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "config.yaml")

	yaml1 := `
version: "v2"
daemon:
  ringbuf_size_kb: 4096
  pending_ttl: 1s
rules:
  - id: "CG-RULE-001"
    severity: "CRITICAL"
`
	if err := os.WriteFile(cfgFile, []byte(yaml1), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	mgr, err := NewManager(cfgFile)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer mgr.Close()

	reloaded := false
	mgr.OnReload(func(oldCfg, newCfg *Config) {
		reloaded = true
		if newCfg.Daemon.RingbufSizeKB != 16384 {
			t.Errorf("Expected reloaded RingbufSizeKB 16384, got %d", newCfg.Daemon.RingbufSizeKB)
		}
	})

	yaml2 := `
version: "v2"
daemon:
  ringbuf_size_kb: 16384
  pending_ttl: 1s
rules:
  - id: "CG-RULE-001"
    severity: "CRITICAL"
  - id: "CG-RULE-002"
    severity: "HIGH"
`
	if err := os.WriteFile(cfgFile, []byte(yaml2), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if err := mgr.Reload(); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	if !reloaded {
		t.Errorf("Expected onReload callback to fire")
	}

	cfg := mgr.Get()
	if len(cfg.Rules) != 2 {
		t.Errorf("Expected 2 rules after reload, got %d", len(cfg.Rules))
	}
}
