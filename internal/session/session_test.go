package session

import (
	"os"
	"path/filepath"
	"testing"

	"cg-smoke-test/internal/telemetry"
)

func TestSessionInspectorMock(t *testing.T) {
	tmpDir := t.TempDir()
	tgid := uint32(23456)
	procPidDir := filepath.Join(tmpDir, "23456")
	fdDir := filepath.Join(procPidDir, "fd")

	if err := os.MkdirAll(fdDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	// Create mock /proc/<tgid>/stat
	// pid (comm) state ppid pgrp session tty_nr ...
	statContent := "23456 (bash) S 1000 23456 23456 34816 23456 4194304 123 0 0 0 0 0 0 0 20 0 1 0 1234567 0 0"
	if err := os.WriteFile(filepath.Join(procPidDir, "stat"), []byte(statContent), 0644); err != nil {
		t.Fatalf("WriteFile stat failed: %v", err)
	}

	// Create mock stdin symlink pointing to pseudo-terminal /dev/pts/2
	if err := os.Symlink("/dev/pts/2", filepath.Join(fdDir, "0")); err != nil {
		t.Fatalf("Symlink failed: %v", err)
	}

	inspector := NewInspector()
	inspector.SetProcRoot(tmpDir)

	ev := &telemetry.SecurityEvent{
		TGID:          tgid,
		Filename:      "/bin/bash",
		Comm:          "bash",
		ContainerID:   "cont-interactive",
		ContainerName: "interactive-container",
	}

	info := inspector.Inspect(ev)
	if !info.IsInteractive {
		t.Errorf("Expected IsInteractive true for PTY attached bash")
	}
	if !info.HasTTY {
		t.Errorf("Expected HasTTY true")
	}
	if info.TTYDevice != "/dev/pts/2" {
		t.Errorf("Expected TTYDevice /dev/pts/2, got %s", info.TTYDevice)
	}
	if info.SessionID != 23456 {
		t.Errorf("Expected SessionID 23456, got %d", info.SessionID)
	}
	if info.ProcessGroup != 23456 {
		t.Errorf("Expected ProcessGroup 23456, got %d", info.ProcessGroup)
	}
}

func TestSessionInspectorNonInteractive(t *testing.T) {
	tmpDir := t.TempDir()
	tgid := uint32(34567)
	procPidDir := filepath.Join(tmpDir, "34567")
	fdDir := filepath.Join(procPidDir, "fd")

	if err := os.MkdirAll(fdDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	// Non-interactive stat with tty_nr = 0
	statContent := "34567 (cron) S 1 34567 34567 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0"
	if err := os.WriteFile(filepath.Join(procPidDir, "stat"), []byte(statContent), 0644); err != nil {
		t.Fatalf("WriteFile stat failed: %v", err)
	}

	// Fds pointing to regular files/pipes
	if err := os.Symlink("/dev/null", filepath.Join(fdDir, "0")); err != nil {
		t.Fatalf("Symlink failed: %v", err)
	}
	if err := os.Symlink("pipe:[12345]", filepath.Join(fdDir, "1")); err != nil {
		t.Fatalf("Symlink failed: %v", err)
	}

	inspector := NewInspector()
	inspector.SetProcRoot(tmpDir)

	ev := &telemetry.SecurityEvent{
		TGID:          tgid,
		Filename:      "/usr/sbin/cron",
		Comm:          "cron",
		ContainerID:   "cont-bg",
		ContainerName: "bg-container",
	}

	info := inspector.Inspect(ev)
	if info.IsInteractive {
		t.Errorf("Expected IsInteractive false for background cron")
	}
	if info.HasTTY {
		t.Errorf("Expected HasTTY false for /dev/null and pipe")
	}
}

func TestShortLivedProcessRaceFallback(t *testing.T) {
	tmpDir := t.TempDir()
	parentTGID := uint32(50000)
	parentDir := filepath.Join(tmpDir, "50000")
	pFdDir := filepath.Join(parentDir, "fd")

	if err := os.MkdirAll(pFdDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	// Parent shell stat
	pStat := "50000 (bash) S 1000 50000 50000 34816 50000 4194304 123 0 0 0 0 0 0 0 20 0 1 0 1234567 0 0"
	if err := os.WriteFile(filepath.Join(parentDir, "stat"), []byte(pStat), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if err := os.Symlink("/dev/pts/5", filepath.Join(pFdDir, "0")); err != nil {
		t.Fatalf("Symlink failed: %v", err)
	}

	inspector := NewInspector()
	inspector.SetProcRoot(tmpDir)

	// Pre-inspect parent so it is cached
	parentEv := &telemetry.SecurityEvent{
		TGID:        parentTGID,
		Filename:    "/bin/bash",
		Comm:        "bash",
		ContainerID: "cont-race",
	}
	pInfo := inspector.Inspect(parentEv)
	if !pInfo.HasTTY {
		t.Fatalf("Parent should have TTY")
	}

	// Short-lived child process (e.g. whoami) whose /proc/<tgid> does NOT exist
	childTGID := uint32(50001)
	childEv := &telemetry.SecurityEvent{
		TGID:        childTGID,
		ParentTGID:  parentTGID,
		Filename:    "/usr/bin/whoami",
		Comm:        "whoami",
		ContainerID: "cont-race",
	}

	childInfo := inspector.Inspect(childEv)
	if !childInfo.HasTTY {
		t.Errorf("Expected child to inherit HasTTY true from parent during race condition")
	}
	if childInfo.TTYDevice != "/dev/pts/5" {
		t.Errorf("Expected child TTYDevice /dev/pts/5, got %s", childInfo.TTYDevice)
	}
	if !childInfo.IsInteractive {
		t.Errorf("Expected child to inherit IsInteractive true from parent shell")
	}
}
