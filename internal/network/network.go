package network

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"cg-smoke-test/internal/telemetry"
)

// SocketState represents the TCP connection state.
type SocketState string

const (
	StateEstablished SocketState = "ESTABLISHED"
	StateSynSent     SocketState = "SYN_SENT"
	StateSynRecv     SocketState = "SYN_RECV"
	StateFinWait1    SocketState = "FIN_WAIT1"
	StateFinWait2    SocketState = "FIN_WAIT2"
	StateTimeWait    SocketState = "TIME_WAIT"
	StateClose       SocketState = "CLOSE"
	StateCloseWait   SocketState = "CLOSE_WAIT"
	StateLastAck     SocketState = "LAST_ACK"
	StateListen      SocketState = "LISTEN"
	StateClosing     SocketState = "CLOSING"
	StateUnknown     SocketState = "UNKNOWN"
)

// SocketInfo represents network endpoint information for a process socket.
type SocketInfo struct {
	Inode         uint64      `json:"inode"`
	Protocol      string      `json:"protocol"` // "TCP", "TCP6", "UDP"
	LocalAddress  string      `json:"local_address"`
	LocalPort     int         `json:"local_port"`
	RemoteAddress string      `json:"remote_address"`
	RemotePort    int         `json:"remote_port"`
	State         SocketState `json:"state"`
	FD            int         `json:"fd,omitempty"`
}

// CorrelationResult contains network context correlated with an execution event.
type CorrelationResult struct {
	HasNetworkSockets     bool         `json:"has_network_sockets"`
	ActiveSockets         []SocketInfo `json:"active_sockets,omitempty"`
	PotentialReverseShell bool         `json:"potential_reverse_shell"`
	ReverseShellDetails   string       `json:"reverse_shell_details,omitempty"`
	ExternalEndpoints     []string     `json:"external_endpoints,omitempty"`
}

// Correlator correlates process execution with live network connections.
type Correlator struct {
	mu          sync.RWMutex
	procRoot    string
	socketCache map[uint32][]SocketInfo // TGID -> Sockets
	lastScan    map[uint32]time.Time
}

// NewCorrelator initializes a network socket correlator.
func NewCorrelator() *Correlator {
	return &Correlator{
		procRoot:    "/proc",
		socketCache: make(map[uint32][]SocketInfo),
		lastScan:    make(map[uint32]time.Time),
	}
}

// SetProcRoot allows overriding /proc path for testing.
func (c *Correlator) SetProcRoot(root string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.procRoot = root
}

// Correlate inspects sockets for the given process and enriches with threat indicators.
func (c *Correlator) Correlate(event *telemetry.SecurityEvent) *CorrelationResult {
	if event == nil || event.TGID == 0 {
		return &CorrelationResult{}
	}

	sockets := c.GetProcessSockets(event.TGID)
	res := &CorrelationResult{
		HasNetworkSockets: len(sockets) > 0,
		ActiveSockets:     sockets,
	}

	var extEndpoints []string
	isShell := isShellBinary(event.Filename, event.Comm)

	for _, s := range sockets {
		if s.RemoteAddress != "" && s.RemoteAddress != "0.0.0.0" && s.RemoteAddress != "::" {
			if !isLoopback(s.RemoteAddress) {
				endpoint := fmt.Sprintf("%s:%d", s.RemoteAddress, s.RemotePort)
				extEndpoints = append(extEndpoints, endpoint)

				// Reverse Shell Heuristic: Shell executing with established external network socket
				if isShell && (s.State == StateEstablished || s.State == StateSynSent) {
					res.PotentialReverseShell = true
					res.ReverseShellDetails = fmt.Sprintf("Shell binary '%s' (TGID %d) has active external connection to %s",
						event.Filename, event.TGID, endpoint)
				}
			}
		}
	}

	res.ExternalEndpoints = extEndpoints
	return res
}

// GetProcessSockets discovers active sockets associated with a TGID.
func (c *Correlator) GetProcessSockets(tgid uint32) []SocketInfo {
	c.mu.RLock()
	cached, ok := c.socketCache[tgid]
	last := c.lastScan[tgid]
	c.mu.RUnlock()

	if ok && time.Since(last) < 500*time.Millisecond {
		return cached
	}

	// 1. Find socket inodes open in /proc/<tgid>/fd
	fdDir := filepath.Join(c.procRoot, strconv.Itoa(int(tgid)), "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil
	}

	fdSocketMap := make(map[uint64]int) // Inode -> FD
	for _, entry := range entries {
		linkPath := filepath.Join(fdDir, entry.Name())
		target, err := os.Readlink(linkPath)
		if err != nil {
			continue
		}
		if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			inodeStr := target[8 : len(target)-1]
			if inode, err := strconv.ParseUint(inodeStr, 10, 64); err == nil {
				fdNum, _ := strconv.Atoi(entry.Name())
				fdSocketMap[inode] = fdNum
			}
		}
	}

	if len(fdSocketMap) == 0 {
		return nil
	}

	// 2. Parse /proc/<tgid>/net/tcp and tcp6 for matching inodes
	var matchedSockets []SocketInfo
	tcpFiles := []struct {
		proto string
		path  string
	}{
		{"TCP", filepath.Join(c.procRoot, strconv.Itoa(int(tgid)), "net", "tcp")},
		{"TCP6", filepath.Join(c.procRoot, strconv.Itoa(int(tgid)), "net", "tcp6")},
	}

	for _, tf := range tcpFiles {
		sockets := parseProcNetTCP(tf.path, tf.proto)
		for _, s := range sockets {
			if fd, found := fdSocketMap[s.Inode]; found {
				s.FD = fd
				matchedSockets = append(matchedSockets, s)
			}
		}
	}

	c.mu.Lock()
	c.socketCache[tgid] = matchedSockets
	c.lastScan[tgid] = time.Now()
	c.mu.Unlock()

	return matchedSockets
}

func parseProcNetTCP(path string, proto string) []SocketInfo {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var sockets []SocketInfo
	scanner := bufio.NewScanner(file)
	firstLine := true

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if firstLine {
			firstLine = false
			continue // skip header
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// Field 1: local_address:port (hex)
		// Field 2: rem_address:port (hex)
		// Field 3: st (hex)
		// Field 9: inode
		localIP, localPort := parseHexEndpoint(fields[1], proto == "TCP6")
		remIP, remPort := parseHexEndpoint(fields[2], proto == "TCP6")
		state := parseTCPState(fields[3])
		inode, _ := strconv.ParseUint(fields[9], 10, 64)

		sockets = append(sockets, SocketInfo{
			Inode:         inode,
			Protocol:      proto,
			LocalAddress:  localIP,
			LocalPort:     localPort,
			RemoteAddress: remIP,
			RemotePort:    remPort,
			State:         state,
		})
	}

	return sockets
}

func parseHexEndpoint(hexStr string, isV6 bool) (string, int) {
	parts := strings.Split(hexStr, ":")
	if len(parts) != 2 {
		return "", 0
	}

	port64, _ := strconv.ParseInt(parts[1], 16, 32)
	port := int(port64)

	ipBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", port
	}

	if !isV6 && len(ipBytes) == 4 {
		// Little endian IPv4
		ip := net.IPv4(ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0])
		return ip.String(), port
	} else if isV6 && len(ipBytes) == 16 {
		// IPv6 32-bit words are in little-endian order
		var v6 [16]byte
		for i := 0; i < 16; i += 4 {
			v6[i] = ipBytes[i+3]
			v6[i+1] = ipBytes[i+2]
			v6[i+2] = ipBytes[i+1]
			v6[i+3] = ipBytes[i]
		}
		ip := net.IP(v6[:])
		return ip.String(), port
	}

	return "", port
}

func parseTCPState(hexState string) SocketState {
	st, err := strconv.ParseInt(hexState, 16, 32)
	if err != nil {
		return StateUnknown
	}
	switch st {
	case 1:
		return StateEstablished
	case 2:
		return StateSynSent
	case 3:
		return StateSynRecv
	case 4:
		return StateFinWait1
	case 5:
		return StateFinWait2
	case 6:
		return StateTimeWait
	case 7:
		return StateClose
	case 8:
		return StateCloseWait
	case 9:
		return StateLastAck
	case 10:
		return StateListen
	case 11:
		return StateClosing
	default:
		return StateUnknown
	}
}

func isLoopback(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

func isShellBinary(filename string, comm string) bool {
	shells := []string{"sh", "bash", "dash", "ash", "zsh", "nc", "ncat", "netcat"}
	for _, s := range shells {
		if comm == s || filename == s || strings.HasSuffix(filename, "/"+s) {
			return true
		}
	}
	return false
}
