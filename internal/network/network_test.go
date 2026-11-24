package network

import (
	"os"
	"path/filepath"
	"testing"

	"cg-smoke-test/internal/telemetry"
)

func TestHexEndpointParsing(t *testing.T) {
	// 0100007F:0050 -> 127.0.0.1:80 (hex 0050 = 80, 0100007F = 127.0.0.1 in little endian)
	ip, port := parseHexEndpoint("0100007F:0050", false)
	if ip != "127.0.0.1" {
		t.Errorf("Expected 127.0.0.1, got %s", ip)
	}
	if port != 80 {
		t.Errorf("Expected port 80, got %d", port)
	}

	// Remote: 046433C6:115C -> 198.51.100.4:4444 (hex 115C = 4444, C6=198, 33=51, 64=100, 04=4)
	ip, port = parseHexEndpoint("046433C6:115C", false)
	if ip != "198.51.100.4" {
		t.Errorf("Expected 198.51.100.4, got %s", ip)
	}
	if port != 4444 {
		t.Errorf("Expected port 4444, got %d", port)
	}
}

func TestNetworkCorrelatorMock(t *testing.T) {
	tmpDir := t.TempDir()
	tgid := uint32(12345)
	procPidDir := filepath.Join(tmpDir, "12345")
	fdDir := filepath.Join(procPidDir, "fd")
	netDir := filepath.Join(procPidDir, "net")

	if err := os.MkdirAll(fdDir, 0755); err != nil {
		t.Fatalf("MkdirAll fd failed: %v", err)
	}
	if err := os.MkdirAll(netDir, 0755); err != nil {
		t.Fatalf("MkdirAll net failed: %v", err)
	}

	// Create symlink for fd/3 -> socket:[99999]
	if err := os.Symlink("socket:[99999]", filepath.Join(fdDir, "3")); err != nil {
		t.Fatalf("Symlink failed: %v", err)
	}

	// Create /proc/<tgid>/net/tcp with matching inode 99999
	// Remote is 198.51.100.4:4444 in state ESTABLISHED (01)
	tcpContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 020011AC:AC20 046433C6:115C 01 00000000:00000000 00:00000000 00000000     0        0 99999 1 0000000000000000 100 0 0 10 0
`
	if err := os.WriteFile(filepath.Join(netDir, "tcp"), []byte(tcpContent), 0644); err != nil {
		t.Fatalf("WriteFile tcp failed: %v", err)
	}

	correlator := NewCorrelator()
	correlator.SetProcRoot(tmpDir)

	ev := &telemetry.SecurityEvent{
		TGID:          tgid,
		Filename:      "/bin/bash",
		Comm:          "bash",
		ContainerID:   "cont-shell",
		ContainerName: "shell-container",
	}

	res := correlator.Correlate(ev)
	if !res.HasNetworkSockets {
		t.Fatalf("Expected HasNetworkSockets true")
	}
	if len(res.ActiveSockets) != 1 {
		t.Fatalf("Expected 1 active socket, got %d", len(res.ActiveSockets))
	}
	s := res.ActiveSockets[0]
	if s.RemoteAddress != "198.51.100.4" || s.RemotePort != 4444 {
		t.Errorf("Unexpected socket endpoint: %s:%d", s.RemoteAddress, s.RemotePort)
	}
	if s.State != StateEstablished {
		t.Errorf("Expected StateEstablished, got %s", s.State)
	}
	if !res.PotentialReverseShell {
		t.Errorf("Expected PotentialReverseShell to be TRUE for shell connecting to external IP")
	}
	if len(res.ExternalEndpoints) != 1 || res.ExternalEndpoints[0] != "198.51.100.4:4444" {
		t.Errorf("Unexpected external endpoints: %v", res.ExternalEndpoints)
	}
}

func TestShortLivedProcessNetworkRaceFallback(t *testing.T) {
	tmpDir := t.TempDir()
	parentTGID := uint32(60000)
	parentDir := filepath.Join(tmpDir, "60000")
	pFdDir := filepath.Join(parentDir, "fd")
	pNetDir := filepath.Join(parentDir, "net")

	if err := os.MkdirAll(pFdDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.MkdirAll(pNetDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	if err := os.Symlink("socket:[77777]", filepath.Join(pFdDir, "3")); err != nil {
		t.Fatalf("Symlink failed: %v", err)
	}

	tcpContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 020011AC:AC20 046433C6:115C 01 00000000:00000000 00:00000000 00000000     0        0 77777 1 0000000000000000 100 0 0 10 0
`
	if err := os.WriteFile(filepath.Join(pNetDir, "tcp"), []byte(tcpContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	correlator := NewCorrelator()
	correlator.SetProcRoot(tmpDir)

	// Short-lived child process (TGID 60001) whose /proc entry has already vanished
	childEv := &telemetry.SecurityEvent{
		TGID:          60001,
		ParentTGID:    parentTGID,
		Filename:      "/bin/sh",
		Comm:          "sh",
		ContainerID:   "cont-shell-race",
		ContainerName: "race-container",
	}

	res := correlator.Correlate(childEv)
	if !res.HasNetworkSockets {
		t.Errorf("Expected child to inherit socket correlation from parent during short-lived race")
	}
	if !res.PotentialReverseShell {
		t.Errorf("Expected PotentialReverseShell to be detected via inherited parent socket")
	}
	if len(res.ExternalEndpoints) == 0 || res.ExternalEndpoints[0] != "198.51.100.4:4444" {
		t.Errorf("Expected endpoint 198.51.100.4:4444, got %v", res.ExternalEndpoints)
	}
}
