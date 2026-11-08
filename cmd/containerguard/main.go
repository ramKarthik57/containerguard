package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	mobyclient "github.com/moby/moby/client"

	"cg-smoke-test/internal/collector"
	"cg-smoke-test/internal/container"
	"cg-smoke-test/internal/detection"
	"cg-smoke-test/internal/lineage"
	"cg-smoke-test/internal/pipeline"
	"cg-smoke-test/internal/storage"
	"cg-smoke-test/internal/telemetry"
)

func main() {
	bpfPath := flag.String("bpf", "bpf/execve_events.o", "Path to compiled eBPF ELF object")
	metricsInterval := flag.Duration("metrics-interval", 5*time.Second, "Telemetry metrics reporting interval")
	eventsLog := flag.String("events-log", "", "Path to write JSON lines event stream (optional)")
	alertsLog := flag.String("alerts-log", "", "Path to write JSON lines alert stream (optional)")
	pendingTTL := flag.Duration("pending-ttl", 2*time.Second, "Attribution buffer pending event TTL")
	ringbufSizeKB := flag.Int("ringbuf-size-kb", 16384, "eBPF Ring Buffer capacity in KiB (power of two * 4KB)")
	backpressurePauseSec := flag.Int("backpressure-pause-sec", 0, "Benchmark backpressure: pause reader startup for N seconds")
	backpressureDelayMS := flag.Int("backpressure-delay-ms", 0, "Benchmark backpressure: delay each sample read by N ms")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Println("=================================================================")
	log.Println(" ContainerGuard: Resilient eBPF Runtime Intrusion Detection")
	log.Println("=================================================================")

	// 1. Initialize Storage
	store, err := storage.NewStorage(*eventsLog, *alertsLog)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()

	// 2. Initialize Telemetry Accounting
	accounting := &telemetry.TelemetryAccounting{}

	// 3. Connect to Docker Engine
	dockerClient, err := mobyclient.New(mobyclient.FromEnv)
	if err != nil {
		log.Fatalf("Connecting to Docker Engine: %v", err)
	}
	defer dockerClient.Close()

	// 4. Initialize Container Resolver
	resolver := container.NewContainerResolver(dockerClient)
	resolver.Start(ctx)

	// 5. Initialize Attribution Pipeline
	pipelineCfg := pipeline.DefaultConfig()
	pipelineCfg.PendingTTL = *pendingTTL
	buffer := pipeline.NewAttributionBuffer(pipelineCfg, resolver, accounting)
	ingester := pipeline.NewIngester(buffer, accounting)
	go buffer.Run(ctx)

	// 6. Initialize Lineage and Detection
	lineageTracker := lineage.NewLineageTracker(20000, 15*time.Minute)
	detectionEngine := detection.NewEngine(lineageTracker)

	// 7. Initialize and start eBPF Collector with configurable capacity & backpressure
	collectorCfg := collector.CollectorConfig{
		RingBufSizeKB:     *ringbufSizeKB,
		SimulatedPauseSec: *backpressurePauseSec,
		SimulatedDelayMS:  *backpressureDelayMS,
	}
	bpfCollector := collector.NewBPFCollectorWithConfig(*bpfPath, collectorCfg, ingester, accounting)
	if err := bpfCollector.Start(ctx); err != nil {
		log.Fatalf("Failed to start eBPF collector: %v", err)
	}
	defer bpfCollector.Close()

	// 8. Start metrics reporting ticker
	go func() {
		ticker := time.NewTicker(*metricsInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				snap := accounting.Snapshot()
				metricsJSON, _ := json.Marshal(snap)
				log.Printf("[METRICS] %s", string(metricsJSON))
			}
		}
	}()

	// 9. Dispatch and processing loop
	log.Println("[containerguard] Telemetry pipeline active. Awaiting container events...")

	outChan := buffer.Output()
	for {
		select {
		case <-ctx.Done():
			log.Println("[containerguard] Shutdown signal received, terminating collector...")
			ingester.Flush()
			// Drain remaining events in outChan up to 3 seconds deadline
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
						_ = store.WriteAlert(alert)
					}
					_ = store.WriteEvent(event)
					accounting.EventsProcessed.Add(1)
				case <-drainTimeout:
					log.Println("[containerguard] Drain deadline elapsed during shutdown.")
					break drainLoop
				default:
					break drainLoop
				}
			}

			finalSnapshot := accounting.Snapshot()
			finalJSON, _ := json.MarshalIndent(finalSnapshot, "", "  ")
			fmt.Printf("\n=== FINAL TELEMETRY INTEGRITY ACCOUNTING REPORT ===\n%s\n", string(finalJSON))
			return

		case event, ok := <-outChan:
			if !ok {
				return
			}

			// Update lineage
			lineageTracker.RecordExec(event)

			// Evaluate deterministic detection rules
			alerts := detectionEngine.Evaluate(event)
			for _, alert := range alerts {
				log.Printf("[ALERT] [%s] %s: %s (Container: %s, Exec: %s)",
					alert.Severity, alert.RuleID, alert.Title, event.ContainerName, event.Filename)
				_ = store.WriteAlert(alert)
			}

			// Print formatted telemetry record
			fmt.Println(event.String())
			_ = store.WriteEvent(event)

			accounting.EventsProcessed.Add(1)
		}
	}
}
