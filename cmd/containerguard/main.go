package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	mobyclient "github.com/moby/moby/client"

	"cg-smoke-test/internal/collector"
	"cg-smoke-test/internal/container"
	"cg-smoke-test/internal/detection"
	"cg-smoke-test/internal/export"
	"cg-smoke-test/internal/lineage"
	"cg-smoke-test/internal/mitigation"
	"cg-smoke-test/internal/network"
	"cg-smoke-test/internal/pipeline"
	"cg-smoke-test/internal/policy"
	"cg-smoke-test/internal/session"
	"cg-smoke-test/internal/storage"
	"cg-smoke-test/internal/telemetry"
	"cg-smoke-test/internal/tui"
)

func main() {
	bpfPath := flag.String("bpf", "bpf/execve_events.o", "Path to compiled eBPF ELF object")
	configPath := flag.String("config", "configs/containerguard.yaml", "Path to YAML policy configuration")
	metricsInterval := flag.Duration("metrics-interval", 5*time.Second, "Telemetry metrics reporting interval")
	eventsLog := flag.String("events-log", "", "Path to write JSON lines event stream (optional)")
	alertsLog := flag.String("alerts-log", "", "Path to write JSON lines alert stream (optional)")
	mitigationsLog := flag.String("mitigations-log", "", "Path to write JSON lines mitigation stream (optional)")
	pendingTTL := flag.Duration("pending-ttl", 2*time.Second, "Attribution buffer pending event TTL")
	ringbufSizeKB := flag.Int("ringbuf-size-kb", 16384, "eBPF Ring Buffer capacity in KiB (power of two * 4KB)")
	backpressurePauseSec := flag.Int("backpressure-pause-sec", 0, "Benchmark backpressure: pause reader startup for N seconds")
	backpressureDelayMS := flag.Int("backpressure-delay-ms", 0, "Benchmark backpressure: delay each sample read by N ms")
	enableTUI := flag.Bool("tui", false, "Enable live interactive terminal dashboard")
	mitigationMode := flag.String("mode", "", "Override mitigation mode ('audit' or 'enforce')")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Println("=================================================================")
	log.Println(" ContainerGuard v2.0: Resilient eBPF Runtime Detection & Mitigation")
	log.Println("=================================================================")

	// 1. Initialize Policy Manager
	var policyMgr *policy.Manager
	var activePolicy *policy.Config
	if _, err := os.Stat(*configPath); err == nil {
		mgr, err := policy.NewManager(*configPath)
		if err != nil {
			log.Printf("[policy] warning: loading policy file %s: %v (falling back to defaults)", *configPath, err)
			activePolicy = policy.DefaultConfig()
		} else {
			policyMgr = mgr
			activePolicy = mgr.Get()
			log.Printf("[policy] Loaded configuration from %s (%d rules active)", *configPath, len(activePolicy.Rules))
			policyMgr.StartSignalReloader()
			defer policyMgr.Close()
		}
	} else {
		activePolicy = policy.DefaultConfig()
	}

	// Apply CLI overrides to policy if provided
	if *mitigationMode != "" {
		activePolicy.Mitigation.Mode = *mitigationMode
	}
	if *eventsLog != "" {
		activePolicy.Export.JSONL.EventsLog = *eventsLog
	}
	if *alertsLog != "" {
		activePolicy.Export.JSONL.AlertsLog = *alertsLog
	}
	if *mitigationsLog != "" {
		activePolicy.Export.JSONL.MitigationsLog = *mitigationsLog
	}
	if *ringbufSizeKB != 16384 {
		activePolicy.Daemon.RingbufSizeKB = *ringbufSizeKB
	}
	if *pendingTTL != 2*time.Second {
		activePolicy.Daemon.PendingTTL = *pendingTTL
	}

	// 2. Initialize Telemetry Accounting
	accounting := &telemetry.TelemetryAccounting{}

	// 3. Initialize Multi-Sink Exporter (JSONL, Prometheus metrics, Webhook)
	exporter, err := export.NewMultiSinkExporter(activePolicy.Export, accounting)
	if err != nil {
		log.Printf("[export] warning: initializing multi-sink exporter: %v", err)
	} else {
		defer exporter.Close()
		if err := exporter.StartPrometheusServer(ctx); err != nil {
			log.Printf("[export] warning: starting Prometheus exporter: %v", err)
		} else if activePolicy.Export.Prometheus.Enabled {
			log.Printf("[export] Prometheus metrics listening on %s%s",
				activePolicy.Export.Prometheus.ListenAddr, activePolicy.Export.Prometheus.Path)
		}
	}

	// Legacy Storage fallback (for backward compatibility)
	store, _ := storage.NewStorage(*eventsLog, *alertsLog)
	if store != nil {
		defer store.Close()
	}

	// 4. Initialize Mitigation Engine
	mitigEngine := mitigation.NewEngine(activePolicy.Mitigation)
	log.Printf("[mitigation] Runtime containment engine active (mode: %s, default_action: %s)",
		strings.ToUpper(activePolicy.Mitigation.Mode), activePolicy.Mitigation.DefaultAction)

	// 5. Initialize Network Correlator & Session Inspector
	networkCorrelator := network.NewCorrelator()
	sessionInspector := session.NewInspector()

	// 6. Connect to Docker Engine
	dockerClient, err := mobyclient.New(mobyclient.FromEnv)
	if err != nil {
		log.Printf("[container] warning: connecting to Docker Engine: %v (operating in standalone cgroup mode)", err)
	} else {
		defer dockerClient.Close()
	}

	// 7. Initialize Container Resolver
	resolver := container.NewContainerResolver(dockerClient)
	resolver.Start(ctx)

	// 8. Initialize Attribution Pipeline
	pipelineCfg := pipeline.DefaultConfig()
	pipelineCfg.PendingTTL = activePolicy.Daemon.PendingTTL
	buffer := pipeline.NewAttributionBuffer(pipelineCfg, resolver, accounting)
	ingester := pipeline.NewIngester(buffer, accounting)
	go buffer.Run(ctx)

	// 9. Initialize Lineage Tracker and Detection Engine
	lineageTracker := lineage.NewLineageTracker(20000, 15*time.Minute)
	detectionEngine := detection.NewEngine(lineageTracker)
	detectionEngine.ConfigureFromPolicy(activePolicy)

	// Hook policy reloads dynamically to update rules & mitigation settings
	if policyMgr != nil {
		policyMgr.OnReload(func(oldCfg, newCfg *policy.Config) {
			log.Printf("[policy] Hot-reloading active rules and containment parameters...")
			detectionEngine.ConfigureFromPolicy(newCfg)
			mitigEngine.SetConfig(newCfg.Mitigation)
		})
	}

	// 10. Initialize TUI Monitor
	var liveMon *tui.LiveMonitor
	if *enableTUI {
		liveMon = tui.NewLiveMonitor(os.Stdout)
	}

	// 11. Initialize and start eBPF Collector
	collectorCfg := collector.CollectorConfig{
		RingBufSizeKB:     activePolicy.Daemon.RingbufSizeKB,
		SimulatedPauseSec: *backpressurePauseSec,
		SimulatedDelayMS:  *backpressureDelayMS,
	}
	bpfCollector := collector.NewBPFCollectorWithConfig(*bpfPath, collectorCfg, ingester, accounting)
	if err := bpfCollector.Start(ctx); err != nil {
		log.Fatalf("Failed to start eBPF collector: %v", err)
	}
	defer bpfCollector.Close()

	// 12. Periodic Reporting Ticker
	go func() {
		ticker := time.NewTicker(*metricsInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				snap := accounting.Snapshot()
				if liveMon != nil {
					liveMon.Render(snap, activePolicy.Mitigation.Mode)
				} else {
					metricsJSON, _ := json.Marshal(snap)
					log.Printf("[METRICS] %s", string(metricsJSON))
				}
			}
		}
	}()

	// 13. Dispatch and processing loop
	log.Println("[containerguard] Telemetry pipeline active. Awaiting container events...")

	outChan := buffer.Output()
	for {
		select {
		case <-ctx.Done():
			log.Println("[containerguard] Shutdown signal received, terminating collector...")
			// 1. Stop ring buffer reader to unblock readLoop while keeping BPF maps accessible
			bpfCollector.StopReader()

			// 2. Flush ingester sequence gap tracker
			ingester.Flush()

			// 3. Force-expire any lingering pending events to UNRESOLVED to cleanly drain queue to 0
			buffer.Flush()

			// 4. Drain remaining events in outChan up to 3 seconds deadline
			drainTimeout := time.After(3 * time.Second)
		drainLoop:
			for {
				select {
				case event, ok := <-outChan:
					if !ok {
						break drainLoop
					}
					lineageTracker.RecordExec(event)
					alerts := detectionEngine.Evaluate(event)
					for _, alert := range alerts {
						if store != nil {
							_ = store.WriteAlert(alert)
						}
						if exporter != nil {
							_ = exporter.ExportAlert(alert)
						}
					}
					if store != nil {
						_ = store.WriteEvent(event)
					}
					if exporter != nil {
						_ = exporter.ExportEvent(event)
					}
					accounting.EventsProcessed.Add(1)
				case <-drainTimeout:
					log.Println("[containerguard] Drain deadline elapsed during shutdown.")
					break drainLoop
				default:
					break drainLoop
				}
			}

			// 5. Synchronously poll final kernel metrics from BPF maps *now* that all events have drained
			if err := bpfCollector.PollKernelMetrics(); err != nil {
				log.Printf("[collector] warning: final kernel metrics poll: %v", err)
			}

			finalSnapshot := accounting.Snapshot()
			finalJSON, _ := json.MarshalIndent(finalSnapshot, "", "  ")
			fmt.Printf("\n=== FINAL TELEMETRY INTEGRITY ACCOUNTING REPORT ===\n%s\n", string(finalJSON))
			return

		case event, ok := <-outChan:
			if !ok {
				return
			}

			// Record event in lineage tracker
			lineageTracker.RecordExec(event)

			// Phase II Context Enrichments: Session/TTY and Network Correlation
			sessInfo := sessionInspector.Inspect(event)
			if sessInfo.IsInteractive {
				event.CommTruncated = false // ensure flags carry through
			}
			netCorr := networkCorrelator.Correlate(event)

			// Record in live TUI if enabled
			if liveMon != nil {
				liveMon.RecordEvent(event)
			}

			// Evaluate deterministic detection rules
			alerts := detectionEngine.Evaluate(event)
			for _, alert := range alerts {
				// Enrich alert with network correlation if reverse shell or external socket detected
				if netCorr.PotentialReverseShell {
					alert.Description += fmt.Sprintf(" | Network Indicator: %s", netCorr.ReverseShellDetails)
					alert.MitreTechniques = append(alert.MitreTechniques, "T1059", "T1071")
				}

				if liveMon != nil {
					liveMon.RecordAlert(alert)
				} else {
					log.Printf("[ALERT] [%s] %s: %s (Container: %s, Exec: %s, Action: %s)",
						alert.Severity, alert.RuleID, alert.Title, event.ContainerName, event.Filename, alert.MitigationAction)
				}

				// Execute Active Runtime Containment
				mitigRec := mitigEngine.Execute(alert)
				if mitigRec != nil {
					if liveMon != nil {
						liveMon.RecordMitigation(mitigRec)
					}
					if exporter != nil {
						_ = exporter.ExportMitigation(mitigRec)
					}
				}

				if store != nil {
					_ = store.WriteAlert(alert)
				}
				if exporter != nil {
					_ = exporter.ExportAlert(alert)
				}
			}

			// Format and emit telemetry record
			if liveMon == nil {
				fmt.Println(event.String())
			}
			if store != nil {
				_ = store.WriteEvent(event)
			}
			if exporter != nil {
				_ = exporter.ExportEvent(event)
			}

			accounting.EventsProcessed.Add(1)
		}
	}
}
