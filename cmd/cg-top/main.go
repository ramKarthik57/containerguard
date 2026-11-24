package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"cg-smoke-test/internal/telemetry"
	"cg-smoke-test/internal/tui"
)

func main() {
	metricsURL := flag.String("metrics-url", "http://localhost:9115/metrics", "Prometheus metrics endpoint to query")
	refreshRate := flag.Duration("refresh", 1*time.Second, "Dashboard refresh rate")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	mon := tui.NewLiveMonitor(os.Stdout)
	client := &http.Client{Timeout: 2 * time.Second}
	ticker := time.NewTicker(*refreshRate)
	defer ticker.Stop()

	fmt.Println("Connecting to ContainerGuard telemetry endpoint:", *metricsURL)

	for {
		select {
		case <-ctx.Done():
			fmt.Println("\n[cg-top] Exited.")
			return
		case <-ticker.C:
			snap := fetchPrometheusSnapshot(client, *metricsURL)
			mon.Render(snap, "connected")
		}
	}
}

func fetchPrometheusSnapshot(client *http.Client, url string) telemetry.MetricsSnapshot {
	snap := telemetry.MetricsSnapshot{}
	resp, err := client.Get(url)
	if err != nil {
		return snap
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return snap
	}

	lines := strings.Split(string(data), "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "#") || l == "" {
			continue
		}
		parts := strings.Fields(l)
		if len(parts) < 2 {
			continue
		}
		val, _ := strconv.ParseUint(parts[1], 10, 64)
		if strings.HasPrefix(parts[0], "containerguard_hook_calls_total") {
			snap.KernelHookInvocations = val
		} else if strings.HasPrefix(parts[0], "containerguard_ringbuf_submitted_total") {
			snap.KernelRingBufferSubmit = val
		} else if strings.HasPrefix(parts[0], "containerguard_ringbuf_reserve_drops_total") {
			snap.KernelRingBufferDrops = val
		} else if strings.HasPrefix(parts[0], "containerguard_events_processed_total") {
			snap.EventsProcessed = val
		} else if strings.HasPrefix(parts[0], "containerguard_sequence_gaps_total") {
			snap.SequenceGapsDetected = val
		}
	}

	if snap.KernelHookInvocations > 0 {
		snap.KernelDropRatePercent = float64(snap.KernelRingBufferDrops) / float64(snap.KernelHookInvocations) * 100.0
	}
	return snap
}
