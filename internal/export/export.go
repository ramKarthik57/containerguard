package export

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"cg-smoke-test/internal/detection"
	"cg-smoke-test/internal/mitigation"
	"cg-smoke-test/internal/policy"
	"cg-smoke-test/internal/storage"
	"cg-smoke-test/internal/telemetry"
)

// MetricsProvider interfaces the telemetry accounting snapshot.
type MetricsProvider interface {
	Snapshot() telemetry.MetricsSnapshot
}

// MultiSinkExporter coordinates writing to JSONL files, Prometheus metrics, and webhooks.
type MultiSinkExporter struct {
	mu           sync.Mutex
	cfg          policy.ExportConfig
	metricsProv  MetricsProvider
	eventsFile   *os.File
	alertsFile   *os.File
	mitigFile    *os.File
	sqliteStore  *storage.SQLiteStorage
	promServer   *http.Server
	httpClient   *http.Client
	alertCounts  map[string]*atomic.Uint64 // "rule_id:severity" -> count
	mitigCounts  map[string]*atomic.Uint64 // "action:success" -> count
	activeClosed bool
}

// NewMultiSinkExporter initializes all export channels.
func NewMultiSinkExporter(cfg policy.ExportConfig, prov MetricsProvider) (*MultiSinkExporter, error) {
	e := &MultiSinkExporter{
		cfg:         cfg,
		metricsProv: prov,
		httpClient: &http.Client{
			Timeout: cfg.Webhook.Timeout,
		},
		alertCounts: make(map[string]*atomic.Uint64),
		mitigCounts: make(map[string]*atomic.Uint64),
	}

	// 1. Initialize JSONL files if paths configured
	if cfg.JSONL.EventsLog != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.JSONL.EventsLog), 0755); err == nil || filepath.Dir(cfg.JSONL.EventsLog) == "." {
			f, err := os.OpenFile(cfg.JSONL.EventsLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				return nil, fmt.Errorf("opening events log: %w", err)
			}
			e.eventsFile = f
		}
	}

	if cfg.JSONL.AlertsLog != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.JSONL.AlertsLog), 0755); err == nil || filepath.Dir(cfg.JSONL.AlertsLog) == "." {
			f, err := os.OpenFile(cfg.JSONL.AlertsLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				return nil, fmt.Errorf("opening alerts log: %w", err)
			}
			e.alertsFile = f
		}
	}

	if cfg.JSONL.MitigationsLog != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.JSONL.MitigationsLog), 0755); err == nil || filepath.Dir(cfg.JSONL.MitigationsLog) == "." {
			f, err := os.OpenFile(cfg.JSONL.MitigationsLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				return nil, fmt.Errorf("opening mitigations log: %w", err)
			}
			e.mitigFile = f
		}
	}

	// 2. Initialize SQLite database if configured
	if cfg.SQLite.Enabled && cfg.SQLite.Path != "" {
		sqlStore, err := storage.NewSQLiteStorage(cfg.SQLite.Path)
		if err != nil {
			return nil, fmt.Errorf("initializing sqlite exporter: %w", err)
		}
		e.sqliteStore = sqlStore
	}

	return e, nil
}

// StartPrometheusServer starts the Prometheus HTTP metrics exporter.
func (e *MultiSinkExporter) StartPrometheusServer(ctx context.Context) error {
	if !e.cfg.Prometheus.Enabled || e.cfg.Prometheus.ListenAddr == "" {
		return nil
	}

	mux := http.NewServeMux()
	path := e.cfg.Prometheus.Path
	if path == "" {
		path = "/metrics"
	}

	mux.HandleFunc(path, e.handlePrometheusMetrics)

	server := &http.Server{
		Addr:    e.cfg.Prometheus.ListenAddr,
		Handler: mux,
	}
	e.promServer = server

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "[export] Prometheus server error: %v\n", err)
		}
	}()

	return nil
}

// ExportEvent writes an enriched security event to JSONL and SQLite.
func (e *MultiSinkExporter) ExportEvent(ev *telemetry.SecurityEvent) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if ev == nil {
		return nil
	}

	if e.sqliteStore != nil {
		_ = e.sqliteStore.WriteEvent(ev)
	}

	if e.eventsFile == nil {
		return nil
	}

	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = e.eventsFile.Write(data)
	return err
}

// ExportAlert writes an alert to JSONL, SQLite, updates Prometheus counters, and posts to Webhook.
func (e *MultiSinkExporter) ExportAlert(alert *detection.Alert) error {
	e.mu.Lock()
	key := fmt.Sprintf("%s:%s", alert.RuleID, alert.Severity)
	ctr, ok := e.alertCounts[key]
	if !ok {
		ctr = &atomic.Uint64{}
		e.alertCounts[key] = ctr
	}
	ctr.Add(1)

	if e.sqliteStore != nil && alert != nil {
		_ = e.sqliteStore.WriteAlert(alert)
	}

	var writeErr error
	if e.alertsFile != nil && alert != nil {
		data, err := json.Marshal(alert)
		if err == nil {
			data = append(data, '\n')
			_, writeErr = e.alertsFile.Write(data)
		}
	}
	e.mu.Unlock()

	// Webhook dispatch (asynchronous)
	if e.cfg.Webhook.Enabled && e.cfg.Webhook.URL != "" {
		go e.sendWebhook(alert)
	}

	return writeErr
}

// ExportMitigation writes a mitigation record to JSONL, SQLite, and updates counters.
func (e *MultiSinkExporter) ExportMitigation(rec *mitigation.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if rec == nil {
		return nil
	}

	successStr := "true"
	if !rec.Success {
		successStr = "false"
	}
	key := fmt.Sprintf("%s:%s", rec.ActionTaken, successStr)
	ctr, ok := e.mitigCounts[key]
	if !ok {
		ctr = &atomic.Uint64{}
		e.mitigCounts[key] = ctr
	}
	ctr.Add(1)

	if e.sqliteStore != nil {
		_ = e.sqliteStore.WriteMitigation(rec)
	}

	if e.mitigFile != nil {
		data, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		data = append(data, '\n')
		_, err = e.mitigFile.Write(data)
		return err
	}
	return nil
}

func (e *MultiSinkExporter) sendWebhook(alert *detection.Alert) {
	data, err := json.Marshal(alert)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", e.cfg.Webhook.URL, bytes.NewBuffer(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ContainerGuard-Exporter/v2")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

func (e *MultiSinkExporter) handlePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	var snap telemetry.MetricsSnapshot
	if e.metricsProv != nil {
		snap = e.metricsProv.Snapshot()
	}

	// 1. Core Kernel Telemetry Counters
	fmt.Fprintf(w, "# HELP containerguard_hook_calls_total Total eBPF tracepoint hook invocations in kernel\n")
	fmt.Fprintf(w, "# TYPE containerguard_hook_calls_total counter\n")
	fmt.Fprintf(w, "containerguard_hook_calls_total %d\n\n", snap.KernelHookInvocations)

	fmt.Fprintf(w, "# HELP containerguard_ringbuf_submitted_total Total events submitted to BPF ring buffer\n")
	fmt.Fprintf(w, "# TYPE containerguard_ringbuf_submitted_total counter\n")
	fmt.Fprintf(w, "containerguard_ringbuf_submitted_total %d\n\n", snap.KernelRingBufferSubmit)

	fmt.Fprintf(w, "# HELP containerguard_ringbuf_reserve_drops_total Total events dropped in kernel due to ring buffer saturation\n")
	fmt.Fprintf(w, "# TYPE containerguard_ringbuf_reserve_drops_total counter\n")
	fmt.Fprintf(w, "containerguard_ringbuf_reserve_drops_total %d\n\n", snap.KernelRingBufferDrops)

	fmt.Fprintf(w, "# HELP containerguard_events_processed_total Total events processed through userspace pipeline\n")
	fmt.Fprintf(w, "# TYPE containerguard_events_processed_total counter\n")
	fmt.Fprintf(w, "containerguard_events_processed_total %d\n\n", snap.EventsProcessed)

	fmt.Fprintf(w, "# HELP containerguard_sequence_gaps_total Sequence number anomalies detected by ingester\n")
	fmt.Fprintf(w, "# TYPE containerguard_sequence_gaps_total counter\n")
	fmt.Fprintf(w, "containerguard_sequence_gaps_total %d\n\n", snap.SequenceGapsDetected)

	// 2. Exact Loss Invariant Conservation Gauge
	invariantVal := 0
	if snap.KernelHookInvocations == snap.KernelRingBufferSubmit+snap.KernelRingBufferDrops {
		invariantVal = 1
	}
	fmt.Fprintf(w, "# HELP containerguard_loss_invariant_satisfied 1 if Hooks == Submissions + Drops, 0 if violated\n")
	fmt.Fprintf(w, "# TYPE containerguard_loss_invariant_satisfied gauge\n")
	fmt.Fprintf(w, "containerguard_loss_invariant_satisfied %d\n\n", invariantVal)

	// 3. Detection Alerts by Rule & Severity
	e.mu.Lock()
	fmt.Fprintf(w, "# HELP containerguard_alerts_total Total intrusion alerts triggered\n")
	fmt.Fprintf(w, "# TYPE containerguard_alerts_total counter\n")
	for key, ctr := range e.alertCounts {
		parts := bytes.Split([]byte(key), []byte(":"))
		if len(parts) == 2 {
			fmt.Fprintf(w, "containerguard_alerts_total{rule_id=\"%s\",severity=\"%s\"} %d\n", parts[0], parts[1], ctr.Load())
		}
	}
	fmt.Fprintf(w, "\n")

	// 4. Mitigations by Action & Outcome
	fmt.Fprintf(w, "# HELP containerguard_mitigations_total Total runtime containment actions executed\n")
	fmt.Fprintf(w, "# TYPE containerguard_mitigations_total counter\n")
	for key, ctr := range e.mitigCounts {
		parts := bytes.Split([]byte(key), []byte(":"))
		if len(parts) == 2 {
			fmt.Fprintf(w, "containerguard_mitigations_total{action=\"%s\",success=\"%s\"} %d\n", parts[0], parts[1], ctr.Load())
		}
	}
	e.mu.Unlock()
}

// Close flushes and closes active export files.
func (e *MultiSinkExporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.activeClosed {
		return nil
	}
	e.activeClosed = true

	var firstErr error
	if e.sqliteStore != nil {
		if err := e.sqliteStore.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if e.eventsFile != nil {
		if err := e.eventsFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if e.alertsFile != nil {
		if err := e.alertsFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if e.mitigFile != nil {
		if err := e.mitigFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}
