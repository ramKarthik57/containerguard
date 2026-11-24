package session

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"cg-smoke-test/internal/telemetry"
)

// SessionInfo encapsulates interactive terminal and session attributes.
type SessionInfo struct {
	SessionID     uint32 `json:"session_id"`
	ProcessGroup  uint32 `json:"process_group"`
	IsInteractive bool   `json:"is_interactive"`
	HasTTY        bool   `json:"has_tty"`
	TTYDevice     string `json:"tty_device,omitempty"`
	ControllingFD int    `json:"controlling_fd,omitempty"`
}

// Inspector evaluates process terminal and session interactivity.
type Inspector struct {
	mu       sync.RWMutex
	procRoot string
	cache    map[uint32]SessionInfo
	cacheTTL map[uint32]time.Time
}

// NewInspector creates a new terminal session inspector.
func NewInspector() *Inspector {
	return &Inspector{
		procRoot: "/proc",
		cache:    make(map[uint32]SessionInfo),
		cacheTTL: make(map[uint32]time.Time),
	}
}

// SetProcRoot allows overriding the /proc path for testing.
func (i *Inspector) SetProcRoot(root string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.procRoot = root
}

// Inspect examines the session and TTY properties of a process.
func (i *Inspector) Inspect(event *telemetry.SecurityEvent) SessionInfo {
	if event == nil || event.TGID == 0 {
		return SessionInfo{}
	}

	tgid := event.TGID

	i.mu.RLock()
	cached, ok := i.cache[tgid]
	last := i.cacheTTL[tgid]
	i.mu.RUnlock()

	if ok && time.Since(last) < 1*time.Second {
		return cached
	}

	info := SessionInfo{}

	// 1. Parse /proc/<tgid>/stat for SessionID and ProcessGroupID
	statPath := filepath.Join(i.procRoot, strconv.Itoa(int(tgid)), "stat")
	if data, err := os.ReadFile(statPath); err == nil {
		fields := strings.Fields(string(data))
		// In /proc/<pid>/stat:
		// Field 0: pid
		// Field 1: comm (in parentheses)
		// Field 2: state
		// Field 3: ppid
		// Field 4: pgrp
		// Field 5: session
		// Field 6: tty_nr
		if len(fields) >= 7 {
			// Handle comm with spaces by locating the last closing parenthesis
			lastParen := strings.LastIndex(string(data), ")")
			if lastParen != -1 && lastParen+2 < len(data) {
				postComm := strings.Fields(string(data[lastParen+2:]))
				if len(postComm) >= 5 {
					// postComm[0] is state, [1] is ppid, [2] is pgrp, [3] is session, [4] is tty_nr
					if pgrp, err := strconv.ParseUint(postComm[2], 10, 32); err == nil {
						info.ProcessGroup = uint32(pgrp)
					}
					if sid, err := strconv.ParseUint(postComm[3], 10, 32); err == nil {
						info.SessionID = uint32(sid)
					}
					if ttyNr, err := strconv.ParseInt(postComm[4], 10, 32); err == nil && ttyNr != 0 {
						info.HasTTY = true
					}
				}
			}
		}
	}

	// 2. Inspect standard descriptors: /proc/<tgid>/fd/0, 1, 2
	fdDir := filepath.Join(i.procRoot, strconv.Itoa(int(tgid)), "fd")
	for fd := 0; fd <= 2; fd++ {
		linkPath := filepath.Join(fdDir, strconv.Itoa(fd))
		target, err := os.Readlink(linkPath)
		if err != nil {
			continue
		}

		if isTerminalDevice(target) {
			info.HasTTY = true
			info.TTYDevice = target
			info.ControllingFD = fd
			info.IsInteractive = true
			break
		}
	}

	// 3. Fallback check: if event Comm or Filename is a shell and ttyNr was set
	if !info.IsInteractive && info.HasTTY {
		info.IsInteractive = true
		if info.TTYDevice == "" {
			info.TTYDevice = fmt.Sprintf("tty:%d", info.SessionID)
		}
	}

	i.mu.Lock()
	i.cache[tgid] = info
	i.cacheTTL[tgid] = time.Now()
	i.mu.Unlock()

	return info
}

func isTerminalDevice(path string) bool {
	if strings.HasPrefix(path, "/dev/pts/") ||
		strings.HasPrefix(path, "/dev/tty") ||
		path == "/dev/console" {
		return true
	}
	return false
}
