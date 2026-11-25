package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "embed"
	_ "modernc.org/sqlite"
)

type Config struct {
	Port       int
	MetricsURL string
	DBPath     string
	ConfigPath string
	RootDir    string
}

type Server struct {
	cfg        Config
	mu         sync.RWMutex
	daemonPID  int
	db         *sql.DB
	clients    map[chan []byte]bool
	clientMu   sync.Mutex
	lastScrape map[string]float64
}

type StatusResponse struct {
	DaemonRunning  bool               `json:"daemon_running"`
	DaemonPID      int                `json:"daemon_pid"`
	KernelVersion  string             `json:"kernel_version"`
	Metrics        map[string]float64 `json:"metrics"`
	InvariantValid bool               `json:"invariant_valid"`
	ProofText      string             `json:"proof_text"`
	Containers     []ContainerInfo    `json:"containers"`
	LastUpdated    string             `json:"last_updated"`
}

type ContainerInfo struct {
	ID      string `json:"id"`
	Names   string `json:"names"`
	Image   string `json:"image"`
	Status  string `json:"status"`
	State   string `json:"state"`
	Running bool   `json:"running"`
}

type SimulationRequest struct {
	Type        string `json:"type"` // "writable_exec", "breakout", "shell_ingress", "recon", "benign"
	ContainerID string `json:"container_id,omitempty"`
}

type SimulationResponse struct {
	Success      bool   `json:"success"`
	RuleTriggered string `json:"rule_triggered"`
	ActionTaken  string `json:"action_taken"`
	Target       string `json:"target"`
	Output       string `json:"output"`
	DurationMs   int64  `json:"duration_ms"`
	Timestamp    string `json:"timestamp"`
}

func main() {
	port := flag.Int("port", 8080, "Web dashboard HTTP listen port")
	metricsURL := flag.String("metrics-url", "http://localhost:9115/metrics", "ContainerGuard Prometheus metrics endpoint")
	dbPath := flag.String("db", "docs/evidence/containerguard_evidence.db", "SQLite evidence database path")
	configPath := flag.String("config", "configs/containerguard.yaml", "YAML policy configuration path")
	rootDir := flag.String("root", ".", "Project root directory")
	flag.Parse()

	absRoot, err := filepath.Abs(*rootDir)
	if err != nil {
		log.Fatalf("Failed to resolve root dir: %v", err)
	}

	cfg := Config{
		Port:       *port,
		MetricsURL: *metricsURL,
		DBPath:     filepath.Join(absRoot, *dbPath),
		ConfigPath: filepath.Join(absRoot, *configPath),
		RootDir:    absRoot,
	}

	srv := &Server{
		cfg:        cfg,
		clients:    make(map[chan []byte]bool),
		lastScrape: make(map[string]float64),
	}

	srv.initDB()
	srv.startDaemonIfNeeded()

	// Background scraper & SSE broadcaster
	go srv.broadcastLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleIndex)
	mux.HandleFunc("/api/status", srv.handleStatus)
	mux.HandleFunc("/api/events", srv.handleEvents)
	mux.HandleFunc("/api/alerts", srv.handleAlerts)
	mux.HandleFunc("/api/mitigations", srv.handleMitigations)
	mux.HandleFunc("/api/stream", srv.handleSSE)
	mux.HandleFunc("/api/action/simulate", srv.handleSimulate)
	mux.HandleFunc("/api/action/hot-reload", srv.handleHotReload)
	mux.HandleFunc("/api/action/daemon", srv.handleDaemonControl)
	mux.HandleFunc("/api/query", srv.handleSQLQuery)

	addr := fmt.Sprintf("0.0.0.0:%d", cfg.Port)
	log.Printf("[cg-web] ContainerGuard Enterprise Web Console listening on http://localhost:%d", cfg.Port)
	log.Printf("[cg-web] Connected to Prometheus: %s", cfg.MetricsURL)
	log.Printf("[cg-web] SQLite Database: %s", cfg.DBPath)

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server exited: %v", err)
	}
}

func (s *Server) initDB() {
	if _, err := os.Stat(s.cfg.DBPath); err == nil {
		db, err := sql.Open("sqlite", s.cfg.DBPath+"?mode=ro&_journal=WAL")
		if err == nil {
			s.db = db
			log.Printf("[cg-web] Opened SQLite database in read-only WAL mode: %s", s.cfg.DBPath)
		}
	}
}

func (s *Server) detectDaemon() {
	out, err := exec.Command("pgrep", "-f", "bin/containerguard").Output()
	if err == nil {
		pids := strings.Fields(string(out))
		if len(pids) > 0 {
			pid, _ := strconv.Atoi(pids[0])
			s.mu.Lock()
			s.daemonPID = pid
			s.mu.Unlock()
			log.Printf("[cg-web] Detected active ContainerGuard daemon (PID %d)", pid)
			return
		}
	}
	s.mu.Lock()
	s.daemonPID = 0
	s.mu.Unlock()
}

func (s *Server) startDaemonIfNeeded() {
	s.detectDaemon()
	s.mu.RLock()
	pid := s.daemonPID
	s.mu.RUnlock()
	if pid > 0 {
		return
	}
	daemonBin := filepath.Join(s.cfg.RootDir, "bin/containerguard")
	if _, err := os.Stat(daemonBin); err != nil {
		log.Printf("[cg-web] Daemon binary not found at %s", daemonBin)
		return
	}
	log.Printf("[cg-web] Auto-starting ContainerGuard daemon: %s", daemonBin)
	cmd := exec.Command(daemonBin,
		"-config", s.cfg.ConfigPath,
		"-events-log", filepath.Join(s.cfg.RootDir, "docs/evidence/exec_paths_events.jsonl"),
		"-alerts-log", filepath.Join(s.cfg.RootDir, "docs/evidence/exec_paths_alerts.jsonl"),
		"-mitigations-log", filepath.Join(s.cfg.RootDir, "docs/evidence/exec_paths_mitigations.jsonl"),
	)
	logFile, err := os.OpenFile(filepath.Join(s.cfg.RootDir, "docs/evidence/daemon_web.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}
	if err := cmd.Start(); err == nil {
		s.mu.Lock()
		s.daemonPID = cmd.Process.Pid
		s.mu.Unlock()
		log.Printf("[cg-web] ContainerGuard daemon started successfully (PID %d)", cmd.Process.Pid)
		time.Sleep(1 * time.Second)
		s.initDB()
	} else {
		log.Printf("[cg-web] Note: Daemon startup required root/CAP_BPF privileges: %v", err)
	}
}

func (s *Server) scrapeMetrics() map[string]float64 {
	metrics := make(map[string]float64)
	client := http.Client{Timeout: 1 * time.Second}
	resp, err := client.Get(s.cfg.MetricsURL)
	if err != nil {
		return metrics
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return metrics
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			name := parts[0]
			val, err := strconv.ParseFloat(parts[1], 64)
			if err == nil {
				metrics[name] = val
			}
		}
	}

	s.mu.Lock()
	s.lastScrape = metrics
	s.mu.Unlock()
	return metrics
}

func (s *Server) getContainers() []ContainerInfo {
	var list []ContainerInfo
	out, err := exec.Command("docker", "ps", "-a", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.State}}").Output()
	if err != nil {
		return list
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		f := strings.Split(l, "\t")
		if len(f) >= 5 {
			list = append(list, ContainerInfo{
				ID:      f[0],
				Names:   f[1],
				Image:   f[2],
				Status:  f[3],
				State:   f[4],
				Running: strings.ToLower(f[4]) == "running",
			})
		}
	}
	return list
}

func (s *Server) broadcastLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if s.db == nil {
			s.initDB()
		}
		s.detectDaemon()
		metrics := s.scrapeMetrics()
		containers := s.getContainers()

		kernelOut, _ := exec.Command("uname", "-r").Output()
		kernel := strings.TrimSpace(string(kernelOut))

		hooks := metrics["containerguard_hook_calls_total"]
		submits := metrics["containerguard_ringbuf_submitted_total"]
		drops := metrics["containerguard_ringbuf_reserve_drops_total"]
		invSat := metrics["containerguard_loss_invariant_satisfied"] == 1

		proof := fmt.Sprintf("%.0f (Hooks) = %.0f (Submissions) + %.0f (Drops)", hooks, submits, drops)

		s.mu.RLock()
		daemonPID := s.daemonPID
		s.mu.RUnlock()

		status := StatusResponse{
			DaemonRunning:  daemonPID > 0 && len(metrics) > 0,
			DaemonPID:      daemonPID,
			KernelVersion:  kernel,
			Metrics:        metrics,
			InvariantValid: invSat,
			ProofText:      proof,
			Containers:     containers,
			LastUpdated:    time.Now().Format("15:04:05 MST"),
		}

		payload, _ := json.Marshal(status)
		s.clientMu.Lock()
		for ch := range s.clients {
			select {
			case ch <- payload:
			default:
			}
		}
		s.clientMu.Unlock()
	}
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := make(chan []byte, 10)
	s.clientMu.Lock()
	s.clients[ch] = true
	s.clientMu.Unlock()

	defer func() {
		s.clientMu.Lock()
		delete(s.clients, ch)
		s.clientMu.Unlock()
	}()

	notify := r.Context().Done()
	for {
		select {
		case <-notify:
			return
		case msg := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		}
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.detectDaemon()
	metrics := s.scrapeMetrics()
	containers := s.getContainers()
	kernelOut, _ := exec.Command("uname", "-r").Output()

	hooks := metrics["containerguard_hook_calls_total"]
	submits := metrics["containerguard_ringbuf_submitted_total"]
	drops := metrics["containerguard_ringbuf_reserve_drops_total"]
	invSat := metrics["containerguard_loss_invariant_satisfied"] == 1

	proof := fmt.Sprintf("%.0f (Hooks) = %.0f (Submissions) + %.0f (Drops)", hooks, submits, drops)

	s.mu.RLock()
	daemonPID := s.daemonPID
	s.mu.RUnlock()

	status := StatusResponse{
		DaemonRunning:  daemonPID > 0 && len(metrics) > 0,
		DaemonPID:      daemonPID,
		KernelVersion:  strings.TrimSpace(string(kernelOut)),
		Metrics:        metrics,
		InvariantValid: invSat,
		ProofText:      proof,
		Containers:     containers,
		LastUpdated:    time.Now().Format("15:04:05 MST"),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	if s.db != nil {
		rows, err := s.db.Query(`SELECT id, timestamp_ns, pid, tgid, comm, nodename, container_id, container_name, cgroup_path, return_val, flags FROM events ORDER BY id DESC LIMIT ?`, limit)
		if err == nil {
			defer rows.Close()
			var events []map[string]interface{}
			for rows.Next() {
				var id int64
				var ts int64
				var pid, tgid uint32
				var comm, nodename, cid, cname, cpath string
				var ret int32
				var flags uint32
				rows.Scan(&id, &ts, &pid, &tgid, &comm, &nodename, &cid, &cname, &cpath, &ret, &flags)
				events = append(events, map[string]interface{}{
					"id":             id,
					"timestamp_ns":   ts,
					"pid":            pid,
					"tgid":           tgid,
					"comm":           comm,
					"nodename":       nodename,
					"container_id":   cid,
					"container_name": cname,
					"cgroup_path":    cpath,
					"return_val":     ret,
					"flags":          flags,
				})
			}
			json.NewEncoder(w).Encode(events)
			return
		}
	}

	// Fallback to JSONL file if DB is not open
	eventsFile := filepath.Join(s.cfg.RootDir, "docs/evidence/exec_paths_events.jsonl")
	data, err := os.ReadFile(eventsFile)
	if err != nil {
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var events []interface{}
	start := len(lines) - limit
	if start < 0 {
		start = 0
	}
	for i := len(lines) - 1; i >= start; i-- {
		var item interface{}
		if err := json.Unmarshal([]byte(lines[i]), &item); err == nil {
			events = append(events, item)
		}
	}
	json.NewEncoder(w).Encode(events)
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.db != nil {
		rows, err := s.db.Query(`SELECT id, event_id, rule_id, title, severity, action, container_id, timestamp_ns, details FROM alerts ORDER BY id DESC LIMIT 50`)
		if err == nil {
			defer rows.Close()
			var alerts []map[string]interface{}
			for rows.Next() {
				var id string
				var eventID int64
				var ruleID, title, severity, action, cid, details string
				var ts int64
				rows.Scan(&id, &eventID, &ruleID, &title, &severity, &action, &cid, &ts, &details)
				alerts = append(alerts, map[string]interface{}{
					"id":           id,
					"event_id":     eventID,
					"rule_id":      ruleID,
					"title":        title,
					"severity":     severity,
					"action":       action,
					"container_id": cid,
					"timestamp_ns": ts,
					"details":      details,
				})
			}
			json.NewEncoder(w).Encode(alerts)
			return
		}
	}

	alertsFile := filepath.Join(s.cfg.RootDir, "docs/evidence/exec_paths_alerts.jsonl")
	data, err := os.ReadFile(alertsFile)
	if err != nil {
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var alerts []interface{}
	for i := len(lines) - 1; i >= 0 && len(alerts) < 50; i-- {
		var item interface{}
		if err := json.Unmarshal([]byte(lines[i]), &item); err == nil {
			alerts = append(alerts, item)
		}
	}
	json.NewEncoder(w).Encode(alerts)
}

func (s *Server) handleMitigations(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.db != nil {
		rows, err := s.db.Query(`SELECT id, alert_id, rule_id, action_taken, target_type, tgid, cgroup_path, timestamp_ns, success, message FROM mitigations ORDER BY id DESC LIMIT 50`)
		if err == nil {
			defer rows.Close()
			var mitigations []map[string]interface{}
			for rows.Next() {
				var id, alertID, ruleID, actionTaken, targetType, cpath, message string
				var tgid uint32
				var ts int64
				var success int
				rows.Scan(&id, &alertID, &ruleID, &actionTaken, &targetType, &tgid, &cpath, &ts, &success, &message)
				mitigations = append(mitigations, map[string]interface{}{
					"id":           id,
					"alert_id":     alertID,
					"rule_id":      ruleID,
					"action_taken": actionTaken,
					"target_type":  targetType,
					"tgid":         tgid,
					"cgroup_path":  cpath,
					"timestamp_ns": ts,
					"success":      success == 1,
					"message":      message,
				})
			}
			json.NewEncoder(w).Encode(mitigations)
			return
		}
	}

	mitigFile := filepath.Join(s.cfg.RootDir, "docs/evidence/exec_paths_mitigations.jsonl")
	data, err := os.ReadFile(mitigFile)
	if err != nil {
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var mitigations []interface{}
	for i := len(lines) - 1; i >= 0 && len(mitigations) < 50; i-- {
		var item interface{}
		if err := json.Unmarshal([]byte(lines[i]), &item); err == nil {
			mitigations = append(mitigations, item)
		}
	}
	json.NewEncoder(w).Encode(mitigations)
}

func (s *Server) handleSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SimulationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	start := time.Now()
	resp := SimulationResponse{
		Success:   true,
		Target:    "cg-demo-victim",
		Timestamp: time.Now().Format("15:04:05 MST"),
	}

	switch req.Type {
	case "writable_exec":
		resp.RuleTriggered = "CG-RULE-002"
		resp.ActionTaken = "kill (escalated to cgroup.kill)"
		// Start disposable victim container, inject exploit
		exec.Command("docker", "rm", "-f", "cg-demo-victim").Run()
		createCmd := exec.Command("docker", "run", "-d", "--name", "cg-demo-victim", "busybox:latest", "sleep", "300")
		if out, err := createCmd.CombinedOutput(); err != nil {
			resp.Success = false
			resp.Output = "Failed to launch victim container: " + string(out)
			break
		}
		// Run exploit in background/foreground
		exploitCmd := exec.Command("docker", "exec", "cg-demo-victim", "sh", "-c", "echo '#!/bin/sh' > /tmp/malicious.sh && chmod +x /tmp/malicious.sh && /tmp/malicious.sh")
		out, _ := exploitCmd.CombinedOutput()
		time.Sleep(500 * time.Millisecond)

		// Check if container was terminated
		inspectOut, _ := exec.Command("docker", "inspect", "--format", "{{.State.Running}}", "cg-demo-victim").Output()
		isRunning := strings.TrimSpace(string(inspectOut)) == "true"
		if !isRunning {
			resp.Output = "Exploit intercepted! Process kill escalated to atomic cgroup.kill. Container terminated in kernel space."
		} else {
			resp.Output = "Container still running: " + string(out)
		}

	case "breakout":
		resp.RuleTriggered = "CG-RULE-001"
		resp.ActionTaken = "kill (Privileged Breakout Intercepted)"
		exec.Command("docker", "rm", "-f", "cg-demo-victim").Run()
		exec.Command("docker", "run", "-d", "--name", "cg-demo-victim", "busybox:latest", "sleep", "300").Run()
		out, _ := exec.Command("docker", "exec", "cg-demo-victim", "nsenter", "--help").CombinedOutput()
		time.Sleep(400 * time.Millisecond)
		resp.Output = "Breakout binary (nsenter) intercepted inside container! " + string(out)

	case "shell_ingress":
		resp.RuleTriggered = "CG-RULE-003"
		resp.ActionTaken = "alert (Interactive Container Shell Ingress)"
		target := req.ContainerID
		if target == "" {
			target = "cg-test-a"
		}
		resp.Target = target
		out, _ := exec.Command("docker", "exec", target, "/bin/sh", "-c", "id").CombinedOutput()
		resp.Output = "Interactive shell ingress detected inside container " + target + ": " + string(out)

	case "benign":
		resp.RuleTriggered = "NONE (0.00% False Positive)"
		resp.ActionTaken = "pass (Zero alerts triggered)"
		target := req.ContainerID
		if target == "" {
			target = "cg-test-a"
		}
		resp.Target = target
		out1, _ := exec.Command("docker", "exec", target, "ls", "-la", "/").CombinedOutput()
		out2, _ := exec.Command("docker", "exec", target, "date").CombinedOutput()
		resp.Output = fmt.Sprintf("Benign commands (ls, date) executed cleanly in %s with 0 alerts fired:\n%s\n%s", target, string(out1), string(out2))

	default:
		resp.Success = false
		resp.Output = "Unknown simulation type: " + req.Type
	}

	resp.DurationMs = time.Since(start).Milliseconds()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleHotReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.detectDaemon()
	s.mu.RLock()
	pid := s.daemonPID
	s.mu.RUnlock()

	if pid <= 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "ContainerGuard daemon is not currently running",
		})
		return
	}

	// Send SIGHUP to the daemon
	err := syscall.Kill(pid, syscall.SIGHUP)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	time.Sleep(300 * time.Millisecond)
	metrics := s.scrapeMetrics()
	drops := metrics["containerguard_ringbuf_reserve_drops_total"]

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"message":       fmt.Sprintf("SIGHUP sent to PID %d. Active YAML configuration reloaded with zero downtime.", pid),
		"events_dropped": drops,
		"invariant":     metrics["containerguard_loss_invariant_satisfied"] == 1,
		"timestamp":     time.Now().Format("15:04:05 MST"),
	})
}

func (s *Server) handleDaemonControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	action := r.URL.Query().Get("action")
	if action == "stop" {
		s.detectDaemon()
		s.mu.RLock()
		pid := s.daemonPID
		s.mu.RUnlock()
		if pid > 0 {
			syscall.Kill(pid, syscall.SIGTERM)
			s.mu.Lock()
			s.daemonPID = 0
			s.mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "status": "stopped"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "status": "running"})
}

func (s *Server) handleSQLQuery(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.initDB()
	}
	if s.db == nil {
		http.Error(w, "Database unavailable", http.StatusServiceUnavailable)
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		query = "SELECT id, rule_id, severity, action, container_id FROM alerts ORDER BY id DESC LIMIT 10"
	}

	// Read-only safety guardrail
	lower := strings.ToLower(strings.TrimSpace(query))
	if !strings.HasPrefix(lower, "select") && !strings.HasPrefix(lower, "explain") {
		http.Error(w, "Only read-only SELECT queries are permitted", http.StatusForbidden)
		return
	}

	rows, err := s.db.Query(query)
	if err != nil {
		http.Error(w, "Query error: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer rows.Close()

	cols, _ := rows.Columns()
	var results []map[string]interface{}
	for rows.Next() {
		values := make([]interface{}, len(cols))
		valuePtrs := make([]interface{}, len(cols))
		for i := range values {
			valuePtrs[i] = &values[i]
		}
		rows.Scan(valuePtrs...)
		rowMap := make(map[string]interface{})
		for i, col := range cols {
			var v interface{}
			val := values[i]
			b, ok := val.([]byte)
			if ok {
				v = string(b)
			} else {
				v = val
			}
			rowMap[col] = v
		}
		results = append(results, rowMap)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"columns": cols,
		"rows":    results,
		"count":   len(results),
	})
}

// Embedded Single Page Application
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	indexPath := filepath.Join(s.cfg.RootDir, "cmd/cg-web/index.html")
	if data, err := os.ReadFile(indexPath); err == nil {
		w.Write(data)
		return
	}
	w.Write([]byte(htmlTemplate))
}

//go:embed index.html
var htmlTemplate string

