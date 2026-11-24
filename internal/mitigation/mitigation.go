package mitigation

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"cg-smoke-test/internal/detection"
	"cg-smoke-test/internal/policy"
	"cg-smoke-test/internal/telemetry"
)

// Action defines the mitigation action type.
type Action string

const (
	ActionAlert      Action = "alert"
	ActionKill       Action = "kill"
	ActionFreeze     Action = "freeze"
	ActionQuarantine Action = "quarantine"
)

// Record captures audit information for a mitigation response.
type Record struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	AlertID       string    `json:"alert_id"`
	RuleID        string    `json:"rule_id"`
	ActionTaken   Action    `json:"action_taken"`
	Mode          string    `json:"mode"` // "audit" or "enforce"
	ContainerID   string    `json:"container_id"`
	ContainerName string    `json:"container_name"`
	CgroupID      uint64    `json:"cgroup_id"`
	TGID          uint32    `json:"tgid"`
	LocalPID      int       `json:"local_pid,omitempty"`
	Comm          string    `json:"comm"`
	Filename      string    `json:"filename"`
	Success       bool      `json:"success"`
	Message       string    `json:"message"`
}

// Engine executes runtime containment actions against detected intrusions.
type Engine struct {
	mu           sync.Mutex
	cfg          policy.MitigationConfig
	cgroupV2Root string
	procRoot     string
	cooldowns    map[string]time.Time
	killFunc     func(pid int, sig syscall.Signal) error
	freezeFunc   func(cgroupPath string) error
	cgroupKillFn func(cgroupPath string) error
	onMitigation []func(record *Record)
}

// NewEngine initializes the mitigation engine.
func NewEngine(cfg policy.MitigationConfig) *Engine {
	e := &Engine{
		cfg:          cfg,
		cgroupV2Root: "/sys/fs/cgroup",
		procRoot:     "/proc",
		cooldowns:    make(map[string]time.Time),
	}
	e.killFunc = syscall.Kill
	e.freezeFunc = e.defaultFreeze
	e.cgroupKillFn = e.defaultCgroupKill
	return e
}

// SetConfig updates mitigation settings dynamically.
func (e *Engine) SetConfig(cfg policy.MitigationConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = cfg
}

// SetProcRoot allows overriding /proc for testing.
func (e *Engine) SetProcRoot(root string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.procRoot = root
}

// OnMitigation registers an audit callback.
func (e *Engine) OnMitigation(cb func(record *Record)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onMitigation = append(e.onMitigation, cb)
}

// SetKillFunc allows overriding syscall.Kill for unit testing.
func (e *Engine) SetKillFunc(fn func(pid int, sig syscall.Signal) error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.killFunc = fn
}

// SetFreezeFunc allows overriding cgroup freeze for unit testing.
func (e *Engine) SetFreezeFunc(fn func(cgroupPath string) error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.freezeFunc = fn
}

// SetCgroupKillFunc allows overriding cgroup kill for unit testing.
func (e *Engine) SetCgroupKillFunc(fn func(cgroupPath string) error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cgroupKillFn = fn
}

// TranslateRootTGID scans procRoot for any process whose root NStgid matches rootTGID.
func (e *Engine) TranslateRootTGID(rootTGID uint32, expectedComm string) int {
	entries, err := os.ReadDir(e.procRoot)
	if err != nil {
		return int(rootTGID)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		localPID, err := strconv.Atoi(entry.Name())
		if err != nil || localPID <= 0 {
			continue
		}

		statusPath := filepath.Join(e.procRoot, entry.Name(), "status")
		f, err := os.Open(statusPath)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		matched := false
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "NStgid:") {
				fields := strings.Fields(line[7:])
				if len(fields) > 0 {
					if rTGID, err := strconv.ParseUint(fields[0], 10, 32); err == nil {
						if uint32(rTGID) == rootTGID {
							matched = true
							break
						}
					}
				}
			}
		}
		_ = f.Close()

		if matched {
			return localPID
		}
	}

	return int(rootTGID)
}

// Execute evaluates the alert's requested mitigation action and executes containment.
func (e *Engine) Execute(alert *detection.Alert) *Record {
	if alert == nil || alert.Event == nil {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	ev := alert.Event
	action := Action(alert.MitigationAction)
	if action == "" {
		action = Action(e.cfg.DefaultAction)
	}
	if action == "" {
		action = ActionAlert
	}

	record := &Record{
		ID:            fmt.Sprintf("MIT-%d-%s", ev.SeqNum, alert.RuleID),
		Timestamp:     time.Now(),
		AlertID:       alert.ID,
		RuleID:        alert.RuleID,
		ActionTaken:   action,
		Mode:          e.cfg.Mode,
		ContainerID:   ev.ContainerID,
		ContainerName: ev.ContainerName,
		CgroupID:      ev.CgroupID,
		TGID:          ev.TGID,
		Comm:          ev.Comm,
		Filename:      ev.Filename,
		Success:       true,
		Message:       "Audit alert recorded",
	}

	// Guardrail: Never mitigate host processes
	if ev.State == telemetry.AttributionHostConfirmed || ev.ContainerID == "host" || ev.CgroupID <= 1 {
		record.Success = false
		record.Message = "Mitigation skipped: host-confirmed process is protected by safety guardrail"
		e.dispatch(record)
		return record
	}

	// Check cooldown per container+rule to avoid flapping
	cooldownKey := fmt.Sprintf("%s:%s:%d", ev.ContainerID, alert.RuleID, ev.TGID)
	if last, exists := e.cooldowns[cooldownKey]; exists {
		if time.Since(last) < e.cfg.Cooldown {
			record.Success = false
			record.Message = fmt.Sprintf("Mitigation skipped: in cooldown period (elapsed %v < %v)", time.Since(last), e.cfg.Cooldown)
			e.dispatch(record)
			return record
		}
	}
	e.cooldowns[cooldownKey] = time.Now()

	// If in audit mode or action is alert, do not apply active kill/freeze
	if e.cfg.Mode == "audit" || action == ActionAlert || !e.cfg.Enabled {
		record.Message = fmt.Sprintf("Audit logged (action: %s, mode: %s)", action, e.cfg.Mode)
		e.dispatch(record)
		return record
	}

	// Enforce containment
	switch action {
	case ActionKill:
		// Attempt direct signal first
		err := e.killFunc(int(ev.TGID), syscall.SIGKILL)
		if err == syscall.ESRCH {
			// PID namespace mismatch: Translate root TGID via /proc NStgid scanning
			localPID := e.TranslateRootTGID(ev.TGID, ev.Comm)
			record.LocalPID = localPID
			if localPID != int(ev.TGID) {
				err = e.killFunc(localPID, syscall.SIGKILL)
			}
		}

		if err != nil {
			// Fallback: If individual signal fails, attempt atomic cgroup.kill
			cgPath := e.resolveCgroupPath(ev.CgroupID, ev.ContainerID)
			cgErr := e.cgroupKillFn(cgPath)
			if cgErr == nil {
				record.Success = true
				record.Message = fmt.Sprintf("Process kill escalated to atomic cgroup.kill for container %s (%s)", ev.ContainerName, cgPath)
			} else {
				record.Success = false
				record.Message = fmt.Sprintf("Failed to kill TGID %d: %v (cgroup fallback error: %v)", ev.TGID, err, cgErr)
			}
		} else {
			record.Message = fmt.Sprintf("Successfully killed malicious process TGID %d with SIGKILL", ev.TGID)
		}

	case ActionFreeze, ActionQuarantine:
		cgPath := e.resolveCgroupPath(ev.CgroupID, ev.ContainerID)
		err := e.freezeFunc(cgPath)
		if err != nil {
			record.Success = false
			record.Message = fmt.Sprintf("Failed to freeze container cgroup %s: %v", cgPath, err)
		} else {
			record.Message = fmt.Sprintf("Successfully frozen container %s cgroup via cgroup.freeze", ev.ContainerName)
		}

	default:
		record.Message = fmt.Sprintf("Unknown mitigation action: %s", action)
	}

	e.dispatch(record)
	return record
}

func (e *Engine) dispatch(rec *Record) {
	for _, cb := range e.onMitigation {
		cb(rec)
	}
}

func (e *Engine) defaultFreeze(cgroupPath string) error {
	freezeFile := filepath.Join(cgroupPath, "cgroup.freeze")
	return os.WriteFile(freezeFile, []byte("1\n"), 0644)
}

func (e *Engine) defaultCgroupKill(cgroupPath string) error {
	killFile := filepath.Join(cgroupPath, "cgroup.kill")
	return os.WriteFile(killFile, []byte("1\n"), 0644)
}

func (e *Engine) resolveCgroupPath(cgroupID uint64, containerID string) string {
	candidates := []string{
		filepath.Join(e.cgroupV2Root, "system.slice", fmt.Sprintf("docker-%s.scope", containerID)),
		filepath.Join(e.cgroupV2Root, "docker", containerID),
		filepath.Join(e.cgroupV2Root, containerID),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return filepath.Join(e.cgroupV2Root, fmt.Sprintf("cgroup-%d", cgroupID))
}
