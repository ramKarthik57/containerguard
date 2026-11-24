package export

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cg-smoke-test/internal/detection"
	"cg-smoke-test/internal/mitigation"
	"cg-smoke-test/internal/policy"
	"cg-smoke-test/internal/telemetry"
)

type mockProv struct {
	snap telemetry.MetricsSnapshot
}

func (m *mockProv) Snapshot() telemetry.MetricsSnapshot {
	return m.snap
}

func TestMultiSinkExporter(t *testing.T) {
	tmpDir := t.TempDir()
	evLog := filepath.Join(tmpDir, "events.jsonl")
	alLog := filepath.Join(tmpDir, "alerts.jsonl")
	mtLog := filepath.Join(tmpDir, "mitigations.jsonl")

	prov := &mockProv{
		snap: telemetry.MetricsSnapshot{
			KernelHookInvocations:  100,
			KernelRingBufferSubmit: 90,
			KernelRingBufferDrops:  10,
			EventsProcessed:        90,
		},
	}

	cfg := policy.ExportConfig{
		JSONL: policy.JSONLExportConfig{
			EventsLog:      evLog,
			AlertsLog:      alLog,
			MitigationsLog: mtLog,
		},
		Prometheus: policy.PrometheusConfig{
			Enabled:    true,
			ListenAddr: ":19115",
			Path:       "/metrics",
		},
	}

	exporter, err := NewMultiSinkExporter(cfg, prov)
	if err != nil {
		t.Fatalf("NewMultiSinkExporter failed: %v", err)
	}
	defer exporter.Close()

	// 1. Export Event
	ev := &telemetry.SecurityEvent{
		SeqNum:        1,
		Filename:      "/bin/ls",
		ContainerID:   "cont-1",
		ContainerName: "test-cont",
	}
	if err := exporter.ExportEvent(ev); err != nil {
		t.Errorf("ExportEvent failed: %v", err)
	}

	// 2. Export Alert
	al := &detection.Alert{
		ID:       "ALERT-1",
		RuleID:   "CG-RULE-001",
		Severity: detection.SeverityCritical,
		Title:    "Test Alert",
	}
	if err := exporter.ExportAlert(al); err != nil {
		t.Errorf("ExportAlert failed: %v", err)
	}

	// 3. Export Mitigation
	rec := &mitigation.Record{
		ID:          "MIT-1",
		ActionTaken: mitigation.ActionKill,
		Success:     true,
	}
	if err := exporter.ExportMitigation(rec); err != nil {
		t.Errorf("ExportMitigation failed: %v", err)
	}

	// 4. Verify Prometheus Handler
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	exporter.handlePrometheusMetrics(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	respStr := string(body)

	if !strings.Contains(respStr, "containerguard_hook_calls_total 100") {
		t.Errorf("Missing hook calls metric in prometheus output")
	}
	if !strings.Contains(respStr, "containerguard_loss_invariant_satisfied 1") {
		t.Errorf("Expected loss invariant satisfied 1, got:\n%s", respStr)
	}
	if !strings.Contains(respStr, `containerguard_alerts_total{rule_id="CG-RULE-001",severity="CRITICAL"} 1`) {
		t.Errorf("Missing alert counter in prometheus output:\n%s", respStr)
	}
	if !strings.Contains(respStr, `containerguard_mitigations_total{action="kill",success="true"} 1`) {
		t.Errorf("Missing mitigation counter in prometheus output:\n%s", respStr)
	}

	// 5. Verify JSONL files created and non-empty
	if evData, err := os.ReadFile(evLog); err != nil || len(evData) == 0 {
		t.Errorf("Events log not written properly")
	}
	if alData, err := os.ReadFile(alLog); err != nil || len(alData) == 0 {
		t.Errorf("Alerts log not written properly")
	}
	if mtData, err := os.ReadFile(mtLog); err != nil || len(mtData) == 0 {
		t.Errorf("Mitigations log not written properly")
	}
}

func TestWebhookDispatch(t *testing.T) {
	received := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := policy.ExportConfig{
		Webhook: policy.WebhookConfig{
			Enabled: true,
			URL:     server.URL,
			Timeout: 1 * time.Second,
		},
	}

	exporter, err := NewMultiSinkExporter(cfg, nil)
	if err != nil {
		t.Fatalf("NewMultiSinkExporter failed: %v", err)
	}
	defer exporter.Close()

	al := &detection.Alert{
		ID:       "ALERT-WEBHOOK",
		RuleID:   "CG-RULE-002",
		Severity: detection.SeverityHigh,
	}
	_ = exporter.ExportAlert(al)

	// Wait up to 500ms for async webhook
	time.Sleep(100 * time.Millisecond)
	if !received {
		t.Errorf("Webhook was not received by test server")
	}
}
