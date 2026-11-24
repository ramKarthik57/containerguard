package tui

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"cg-smoke-test/internal/detection"
	"cg-smoke-test/internal/mitigation"
	"cg-smoke-test/internal/telemetry"
)

// ANSI color codes
const (
	ColorReset   = "\033[0m"
	ColorBold    = "\033[1m"
	ColorDim     = "\033[2m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorWhite   = "\033[37m"
	ClearScreen  = "\033[H\033[2J"
)

// LiveMonitor renders a high-fidelity terminal dashboard.
type LiveMonitor struct {
	mu           sync.Mutex
	out          io.Writer
	recentAlerts []*detection.Alert
	recentMitigs []*mitigation.Record
	containers   map[string]int // ContainerName -> exec count
	maxAlerts    int
	maxMitigs    int
	lastTime     time.Time
}

// NewLiveMonitor creates an interactive terminal dashboard monitor.
func NewLiveMonitor(out io.Writer) *LiveMonitor {
	return &LiveMonitor{
		out:        out,
		containers: make(map[string]int),
		maxAlerts:  8,
		maxMitigs:  5,
		lastTime:   time.Now(),
	}
}

// RecordAlert adds an alert to the live dashboard.
func (m *LiveMonitor) RecordAlert(alert *detection.Alert) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recentAlerts = append([]*detection.Alert{alert}, m.recentAlerts...)
	if len(m.recentAlerts) > m.maxAlerts {
		m.recentAlerts = m.recentAlerts[:m.maxAlerts]
	}
}

// RecordMitigation adds a containment record to the dashboard.
func (m *LiveMonitor) RecordMitigation(rec *mitigation.Record) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recentMitigs = append([]*mitigation.Record{rec}, m.recentMitigs...)
	if len(m.recentMitigs) > m.maxMitigs {
		m.recentMitigs = m.recentMitigs[:m.maxMitigs]
	}
}

// RecordEvent records container execution for the dashboard inventory.
func (m *LiveMonitor) RecordEvent(ev *telemetry.SecurityEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ev.ContainerName != "" {
		m.containers[ev.ContainerName]++
	}
}

// Render writes a formatted dashboard frame to the output writer.
func (m *LiveMonitor) Render(snap telemetry.MetricsSnapshot, mode string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var b strings.Builder
	b.WriteString(ClearScreen)

	// Header Banner
	b.WriteString(fmt.Sprintf("%s%s========================================================================================%s\n", ColorCyan, ColorBold, ColorReset))
	b.WriteString(fmt.Sprintf("%s%s   ContainerGuard Enterprise v2.0 | eBPF Runtime Intrusion Detection & Containment      %s\n", ColorWhite, ColorBold, ColorReset))
	b.WriteString(fmt.Sprintf("%s%s   100%% Production Milestone | Mode: %s%s%s | Time: %s%s\n",
		ColorDim, ColorWhite, ColorGreen, strings.ToUpper(mode), ColorReset, time.Now().Format("2006-01-02 15:04:05"), ColorReset))
	b.WriteString(fmt.Sprintf("%s%s========================================================================================%s\n\n", ColorCyan, ColorBold, ColorReset))

	// Invariant Check
	invariantSatisfied := snap.KernelHookInvocations == snap.KernelRingBufferSubmit+snap.KernelRingBufferDrops
	invColor := ColorGreen
	invStatus := "SATISFIED (Hooks = Submissions + Drops)"
	if !invariantSatisfied && snap.KernelHookInvocations > 0 {
		invColor = ColorRed
		invStatus = "VIOLATION DETECTED"
	}

	// 1. Kernel Telemetry & Loss Accounting Panel
	b.WriteString(fmt.Sprintf("%s%s[+] Kernel eBPF Telemetry Accounting:%s\n", ColorBold, ColorYellow, ColorReset))
	b.WriteString(fmt.Sprintf("  Tracepoint Hooks:  %-12d   RingBuffer Submissions: %-12d\n", snap.KernelHookInvocations, snap.KernelRingBufferSubmit))
	b.WriteString(fmt.Sprintf("  RingBuffer Drops:  %-12d   Drop Rate:              %.2f%%\n", snap.KernelRingBufferDrops, snap.KernelDropRatePercent))
	b.WriteString(fmt.Sprintf("  Processed Events:  %-12d   Sequence Anomaly Gaps:  %-12d\n", snap.EventsProcessed, snap.SequenceGapsDetected))
	b.WriteString(fmt.Sprintf("  Loss Invariant:    %s%s%s%s\n\n", invColor, ColorBold, invStatus, ColorReset))

	// 2. Container Workload Inventory Panel
	b.WriteString(fmt.Sprintf("%s%s[+] Monitored Container Workloads (%d active):%s\n", ColorBold, ColorYellow, len(m.containers), ColorReset))
	if len(m.containers) == 0 {
		b.WriteString(fmt.Sprintf("  %sNo container executions observed yet (awaiting workload)...%s\n\n", ColorDim, ColorReset))
	} else {
		for name, count := range m.containers {
			b.WriteString(fmt.Sprintf("  Container: %-24s Executions Captured: %-8d Status: %sACTIVE%s\n", name, count, ColorGreen, ColorReset))
		}
		b.WriteString("\n")
	}

	// 3. Security Detection Alerts Panel
	b.WriteString(fmt.Sprintf("%s%s[+] Recent Intrusion Alerts (%d):%s\n", ColorBold, ColorRed, len(m.recentAlerts), ColorReset))
	if len(m.recentAlerts) == 0 {
		b.WriteString(fmt.Sprintf("  %sZero security anomalies detected. System operating under baseline conditions.%s\n\n", ColorGreen, ColorReset))
	} else {
		for _, al := range m.recentAlerts {
			sevColor := ColorYellow
			if al.Severity == detection.SeverityCritical {
				sevColor = ColorRed
			}
			mitreStr := ""
			if len(al.MitreTechniques) > 0 {
				mitreStr = fmt.Sprintf("[%s]", strings.Join(al.MitreTechniques, ","))
			}
			b.WriteString(fmt.Sprintf("  %s%-8s%s %-12s %s %s (Action: %s) [%s]\n",
				sevColor, al.Severity, ColorReset, al.RuleID, al.Title, mitreStr, al.MitigationAction, al.Timestamp.Format("15:04:05")))
		}
		b.WriteString("\n")
	}

	// 4. Runtime Containment Actions Panel
	b.WriteString(fmt.Sprintf("%s%s[+] Active Mitigation Actions (%d):%s\n", ColorBold, ColorMagenta, len(m.recentMitigs), ColorReset))
	if len(m.recentMitigs) == 0 {
		b.WriteString(fmt.Sprintf("  %sNo containment actions required.%s\n\n", ColorDim, ColorReset))
	} else {
		for _, rec := range m.recentMitigs {
			resColor := ColorGreen
			if !rec.Success {
				resColor = ColorYellow
			}
			b.WriteString(fmt.Sprintf("  Action: %-10s TGID: %-6d Container: %-16s Status: %s%s%s (%s)\n",
				rec.ActionTaken, rec.TGID, rec.ContainerName, resColor, rec.Message, ColorReset, rec.Timestamp.Format("15:04:05")))
		}
		b.WriteString("\n")
	}

	b.WriteString(fmt.Sprintf("%s[Press Ctrl+C to stop daemon and export final integrity reports]%s\n", ColorDim, ColorReset))

	_, _ = io.WriteString(m.out, b.String())
}
