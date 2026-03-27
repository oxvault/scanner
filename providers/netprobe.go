package providers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oxvault/scanner/internal/version"
	"github.com/oxvault/scanner/patterns"
)

// netActivityType constants for NetActivity.Type.
const (
	NetActivityDNS = "dns"
	NetActivityTCP = "tcp"
	NetActivityUDP = "udp"
)

// straceAvailable reports whether strace is on PATH.
func straceAvailable() bool {
	_, err := exec.LookPath("strace")
	return err == nil
}

// netProbe is the concrete implementation of NetProbe.
type netProbe struct {
	logger *slog.Logger
}

// NewNetProbe returns a new NetProbe. The probe uses strace when available and
// falls back to /proc/<PID>/net/tcp parsing when strace is absent.
func NewNetProbe(logger *slog.Logger) NetProbe {
	return &netProbe{logger: logger}
}

var _ NetProbe = (*netProbe)(nil)

// Probe spawns cmd with args, performs a minimal MCP session (initialize →
// tools/list → call each tool with safe dummy arguments), and records all
// outbound network activity observed during the session.
//
// Network monitoring strategy:
//  1. strace present  → attach strace -f -e trace=connect,sendto to the child
//     process and parse its stderr in real time.
//  2. strace absent   → snapshot /proc/<PID>/net/tcp{,6} before and after, then
//     diff to find new connections (coarse but zero-dependency).
//
// Callers should treat the result as best-effort: some servers may not respond
// to tool calls with dummy arguments, and connections made in background
// goroutines may be missed by the snapshot approach.
func (n *netProbe) Probe(cmd string, args []string, timeout time.Duration) ([]NetActivity, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	if straceAvailable() {
		n.logger.Info("strace available — using syscall tracing")
		return n.probeWithStrace(cmd, args, timeout)
	}

	n.logger.Warn("strace not found — falling back to /proc/<PID>/net/tcp snapshot; " +
		"results may be incomplete. Install strace for full network visibility.")
	return n.probeWithProcNet(cmd, args, timeout)
}

// ---------------------------------------------------------------------------
// strace-based probe
// ---------------------------------------------------------------------------

// straceConnectRE matches:
//   connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16)
//   connect(3, {sa_family=AF_INET6, sin6_port=htons(443), sin6_addr=inet_pton(AF_INET6, "2606:2800::1")}, 28)
//
// Note: inet_addr( and inet_pton(AF_INET6, must both include the opening
// parenthesis so the alternation is unambiguous.
var straceConnectRE = regexp.MustCompile(
	`connect\(\d+,\s*\{sa_family=(AF_INET6?),` +
		`\s*sin6?_port=htons\((\d+)\),` +
		`\s*sin6?_addr=(?:inet_addr\(|inet_pton\(AF_INET6?,\s*)"([^"]+)"`,
)

// straceSendtoRE matches UDP sendto with a destination address:
//
//	sendto(3, ..., {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16)
var straceSendtoRE = regexp.MustCompile(
	`sendto\(\d+,.*\{sa_family=(AF_INET6?),` +
		`\s*sin6?_port=htons\((\d+)\),` +
		`\s*sin6?_addr=(?:inet_addr\(|inet_pton\(AF_INET6?,\s*)"([^"]+)"`,
)

func (n *netProbe) probeWithStrace(cmd string, args []string, timeout time.Duration) ([]NetActivity, error) {
	// We launch the target under strace. strace itself starts the target as a
	// child so we need -f (follow forks) for multi-process servers.
	straceArgs := []string{
		"-f",
		"-e", "trace=connect,sendto",
		"--",
		cmd,
	}
	straceArgs = append(straceArgs, args...)

	proc := exec.Command("strace", straceArgs...)

	// strace writes its trace to stderr; the target's stdout is our MCP channel.
	stdinPipe, err := proc.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdoutPipe, err := proc.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderrPipe, err := proc.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}

	if err := proc.Start(); err != nil {
		return nil, fmt.Errorf("start strace: %w", err)
	}

	var (
		mu         sync.Mutex
		activities []NetActivity
	)

	// Consume strace output in background and parse network syscalls.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		parseStraceOutput(stderrPipe, &mu, &activities)
	}()

	// Run the MCP session (initialize → tools/list → call each tool).
	tools, sessionErr := runMCPSession(stdinPipe, stdoutPipe, timeout)
	_ = tools // tool names collected but correlation is best-effort

	// Give strace a moment to flush remaining output, then kill.
	time.Sleep(200 * time.Millisecond)
	_ = proc.Process.Kill()
	_ = proc.Wait()
	wg.Wait()

	if sessionErr != nil {
		n.logger.Warn("MCP session error during probe", "error", sessionErr)
	}

	return activities, nil
}

// parseStraceOutput reads strace lines from r and appends NetActivity records.
func parseStraceOutput(r io.Reader, mu *sync.Mutex, out *[]NetActivity) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		if act, ok := parseStraceLine(line); ok {
			mu.Lock()
			*out = append(*out, act)
			mu.Unlock()
		}
	}
}

// parseStraceLine parses a single strace line and returns a NetActivity.
// Exported so the test can call it directly without strace installed.
func parseStraceLine(line string) (NetActivity, bool) {
	now := time.Now()

	// connect() → TCP (or UDP on AF_INET sockets, but we can't tell at this
	// layer — classify as TCP for non-port-53 and DNS for port 53).
	if m := straceConnectRE.FindStringSubmatch(line); m != nil {
		family, portStr, addr := m[1], m[2], m[3]
		port, _ := strconv.Atoi(portStr)
		dest := net.JoinHostPort(addr, portStr)

		actType := NetActivityTCP
		if port == 53 {
			actType = NetActivityDNS
		}
		_ = family // already encoded in addr (IPv4 vs IPv6)

		return NetActivity{
			Type:        actType,
			Destination: dest,
			Timestamp:   now,
		}, true
	}

	// sendto() with destination address → UDP (commonly DNS on port 53).
	if m := straceSendtoRE.FindStringSubmatch(line); m != nil {
		portStr, addr := m[2], m[3]
		port, _ := strconv.Atoi(portStr)
		dest := net.JoinHostPort(addr, portStr)

		actType := NetActivityUDP
		if port == 53 {
			actType = NetActivityDNS
		}

		return NetActivity{
			Type:        actType,
			Destination: dest,
			Timestamp:   now,
		}, true
	}

	return NetActivity{}, false
}

// ---------------------------------------------------------------------------
// /proc/<PID>/net/tcp fallback probe
// ---------------------------------------------------------------------------

func (n *netProbe) probeWithProcNet(cmd string, args []string, timeout time.Duration) ([]NetActivity, error) {
	proc := exec.Command(cmd, args...)
	stdinPipe, err := proc.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdoutPipe, err := proc.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	// Discard stderr from the target server.
	proc.Stderr = io.Discard

	if err := proc.Start(); err != nil {
		return nil, fmt.Errorf("start process: %w", err)
	}

	pid := proc.Process.Pid

	// Snapshot connections before we start talking to the server.
	before := snapshotProcNetTCP(pid)

	_, sessionErr := runMCPSession(stdinPipe, stdoutPipe, timeout)

	// Snapshot after the session completes.
	after := snapshotProcNetTCP(pid)

	_ = proc.Process.Kill()
	_ = proc.Wait()

	if sessionErr != nil {
		n.logger.Warn("MCP session error during probe (proc/net fallback)", "error", sessionErr)
	}

	// Diff: any address in after that wasn't in before is a new connection.
	var activities []NetActivity
	now := time.Now()
	for addr := range after {
		if !before[addr] {
			activities = append(activities, NetActivity{
				Type:        NetActivityTCP,
				Destination: addr,
				Timestamp:   now,
			})
		}
	}

	return activities, nil
}

// snapshotProcNetTCP reads /proc/<pid>/net/tcp and /proc/<pid>/net/tcp6
// and returns a set of remote addresses (ip:port) in ESTABLISHED state.
// If the files are not readable (non-Linux, permission denied, etc.) it
// returns an empty set — the caller handles that gracefully.
func snapshotProcNetTCP(pid int) map[string]bool {
	result := make(map[string]bool)
	for _, path := range []string{
		fmt.Sprintf("/proc/%d/net/tcp", pid),
		fmt.Sprintf("/proc/%d/net/tcp6", pid),
	} {
		parseProcNetFile(path, result)
	}
	return result
}

// parseProcNetFile reads a /proc/<PID>/net/tcp{,6} file and adds remote
// addresses in ESTABLISHED (state=01) lines to dst.
func parseProcNetFile(path string, dst map[string]bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	// Skip header line.
	scanner.Scan()
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// Format: sl local_address rem_address st tx_queue rx_queue ...
		// We need fields[2] (rem_address) and fields[3] (st).
		if len(fields) < 4 {
			continue
		}
		state := fields[3]
		if state != "01" { // 01 = ESTABLISHED
			continue
		}
		remHex := fields[2]
		if addr, ok := parseProcNetAddr(remHex); ok {
			dst[addr] = true
		}
	}
}

// parseProcNetAddr decodes the hex address:port from /proc/net/tcp{,6}.
// IPv4:  "0101007F:0035" → "127.1.1.0:53"  (little-endian 32-bit)
// IPv6: 32-char hex      → decoded big-endian 128-bit
func parseProcNetAddr(hexAddr string) (string, bool) {
	parts := strings.SplitN(hexAddr, ":", 2)
	if len(parts) != 2 {
		return "", false
	}
	addrHex, portHex := parts[0], parts[1]

	port64, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", false
	}
	port := int(port64)

	switch len(addrHex) {
	case 8: // IPv4 little-endian
		v, err := strconv.ParseUint(addrHex, 16, 32)
		if err != nil {
			return "", false
		}
		ip := net.IP{
			byte(v),
			byte(v >> 8),
			byte(v >> 16),
			byte(v >> 24),
		}
		return net.JoinHostPort(ip.String(), strconv.Itoa(port)), true

	case 32: // IPv6 big-endian groups
		// Groups of 8 hex chars, each in little-endian 32-bit word order.
		b := make([]byte, 16)
		for i := 0; i < 4; i++ {
			word, err := strconv.ParseUint(addrHex[i*8:(i+1)*8], 16, 32)
			if err != nil {
				return "", false
			}
			b[i*4] = byte(word)
			b[i*4+1] = byte(word >> 8)
			b[i*4+2] = byte(word >> 16)
			b[i*4+3] = byte(word >> 24)
		}
		ip := net.IP(b)
		return net.JoinHostPort(ip.String(), strconv.Itoa(port)), true

	default:
		return "", false
	}
}

// ---------------------------------------------------------------------------
// Minimal MCP session runner
// ---------------------------------------------------------------------------

// runMCPSession performs: initialize → initialized notification → tools/list →
// tools/call for each tool with safe dummy arguments.
// It writes to w (the server's stdin) and reads from r (the server's stdout).
// Returns the list of tools discovered (used for correlation).
func runMCPSession(w io.Writer, r io.Reader, timeout time.Duration) ([]MCPTool, error) {
	enc := json.NewEncoder(w)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	type rpcReq struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id,omitempty"`
		Method  string `json:"method"`
		Params  any    `json:"params,omitempty"`
	}
	type rpcResp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      any             `json:"id,omitempty"`
		Result  json.RawMessage `json:"result,omitempty"`
		Error   *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}

	send := func(req rpcReq) error { return enc.Encode(req) }
	recv := func() (rpcResp, error) {
		done := make(chan struct{})
		var resp rpcResp
		var scanErr error
		go func() {
			defer close(done)
			if scanner.Scan() {
				scanErr = json.Unmarshal(scanner.Bytes(), &resp)
			} else {
				scanErr = fmt.Errorf("no response from server")
			}
		}()
		select {
		case <-done:
			return resp, scanErr
		case <-time.After(timeout):
			return rpcResp{}, fmt.Errorf("timeout waiting for server response")
		}
	}

	// initialize
	if err := send(rpcReq{
		JSONRPC: "2.0", ID: 1, Method: "initialize",
		Params: map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "oxvault-probe", "version": version.Version},
		},
	}); err != nil {
		return nil, fmt.Errorf("send initialize: %w", err)
	}

	initResp, err := recv()
	if err != nil {
		return nil, fmt.Errorf("read initialize: %w", err)
	}
	if initResp.Error != nil {
		return nil, fmt.Errorf("initialize error: %s", initResp.Error.Message)
	}

	// initialized notification (no response expected)
	if err := send(rpcReq{JSONRPC: "2.0", Method: "notifications/initialized"}); err != nil {
		return nil, fmt.Errorf("send initialized: %w", err)
	}

	// tools/list
	if err := send(rpcReq{JSONRPC: "2.0", ID: 2, Method: "tools/list", Params: map[string]any{}}); err != nil {
		return nil, fmt.Errorf("send tools/list: %w", err)
	}

	listResp, err := recv()
	if err != nil {
		return nil, fmt.Errorf("read tools/list: %w", err)
	}
	if listResp.Error != nil {
		return nil, fmt.Errorf("tools/list error: %s", listResp.Error.Message)
	}

	var listResult struct {
		Tools []MCPTool `json:"tools"`
	}
	if err := json.Unmarshal(listResp.Result, &listResult); err != nil {
		return nil, fmt.Errorf("parse tools/list: %w", err)
	}

	// Call each tool with safe dummy arguments.
	for i, tool := range listResult.Tools {
		dummyArgs := buildDummyArgs(tool.InputSchema)
		reqID := 100 + i
		callReq := rpcReq{
			JSONRPC: "2.0",
			ID:      reqID,
			Method:  "tools/call",
			Params: map[string]any{
				"name":      tool.Name,
				"arguments": dummyArgs,
			},
		}
		if err := send(callReq); err != nil {
			// Non-fatal: server may have died or not support this tool.
			continue
		}
		// Best-effort read; ignore errors and timeouts per-tool.
		_, _ = recv()
	}

	return listResult.Tools, nil
}

// buildDummyArgs generates a map of safe placeholder arguments for a tool call
// based on the tool's JSON Schema input schema.
//
// Supported JSON Schema types:
//
//	string  → "test"
//	number  → 0
//	integer → 0
//	boolean → false
//	object  → {}
//	array   → []
//	null    → nil
func buildDummyArgs(schema map[string]any) map[string]any {
	result := make(map[string]any)
	if schema == nil {
		return result
	}

	props, ok := schema["properties"].(map[string]any)
	if !ok {
		return result
	}

	for name, raw := range props {
		prop, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		result[name] = dummyValueForType(prop)
	}

	return result
}

// dummyValueForType returns a safe sentinel value for the given JSON Schema
// property descriptor. It handles the "type" keyword and falls back to the
// first entry in "anyOf"/"oneOf" when "type" is absent.
func dummyValueForType(prop map[string]any) any {
	typVal, hasType := prop["type"].(string)
	if !hasType {
		// Try anyOf / oneOf — use first entry.
		for _, key := range []string{"anyOf", "oneOf"} {
			if arr, ok := prop[key].([]any); ok && len(arr) > 0 {
				if sub, ok := arr[0].(map[string]any); ok {
					return dummyValueForType(sub)
				}
			}
		}
		return nil
	}

	switch typVal {
	case "string":
		return "test"
	case "number", "integer":
		return 0
	case "boolean":
		return false
	case "object":
		return map[string]any{}
	case "array":
		return []any{}
	case "null":
		return nil
	default:
		return nil
	}
}

// ---------------------------------------------------------------------------
// Finding helpers — classify NetActivity into Finding severity
// ---------------------------------------------------------------------------

// rfc1918Nets are the private address ranges from RFC 1918.
var rfc1918Nets = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, cidr := range patterns.RFC1918CIDRs {
		_, n, _ := net.ParseCIDR(cidr)
		nets = append(nets, n)
	}
	return nets
}()

// isRFC1918 reports whether ip is a private (RFC 1918) address.
func isRFC1918(ip net.IP) bool {
	for _, n := range rfc1918Nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// isMetadataService reports whether ip is a cloud metadata service address.
// Currently covers AWS/Azure/GCP (169.254.169.254) and GCP alternative
// (metadata.google.internal resolves to 169.254.169.254).
func isMetadataService(ip net.IP) bool {
	return ip.Equal(net.ParseIP("169.254.169.254"))
}

// NetActivityToFindings converts a slice of NetActivity records into
// Finding entries that can be appended to a ScanReport.
//
// Severity mapping:
//
//	DNS query                        → WARNING
//	TCP/UDP to cloud metadata IP     → CRITICAL
//	TCP/UDP to RFC 1918 address      → HIGH  (possible SSRF)
//	TCP/UDP to any other public IP   → HIGH
func NetActivityToFindings(activities []NetActivity) []Finding {
	var findings []Finding

	for _, act := range activities {
		host, portStr, err := net.SplitHostPort(act.Destination)
		if err != nil {
			host = act.Destination
		}
		_ = portStr

		ip := net.ParseIP(host)

		switch act.Type {
		case NetActivityDNS:
			findings = append(findings, Finding{
				Rule:     "net-probe-dns-query",
				Severity: SeverityWarning,
				Message:  fmt.Sprintf("Tool made DNS query to %s", act.Destination),
				Tool:     act.ToolName,
				Fix:      "Review why the server resolves external hostnames during tool execution.",
			})

		case NetActivityTCP, NetActivityUDP:
			if ip == nil {
				// Could not parse — treat as public.
				findings = append(findings, Finding{
					Rule:     "net-probe-outbound-connection",
					Severity: SeverityHigh,
					Message:  fmt.Sprintf("Tool made outbound %s connection to %s", strings.ToUpper(act.Type), act.Destination),
					Tool:     act.ToolName,
					Fix:      "Audit outbound connections; ensure no data exfiltration is occurring.",
				})
				continue
			}

			switch {
			case isMetadataService(ip):
				findings = append(findings, Finding{
					Rule:     "net-probe-metadata-service",
					Severity: SeverityCritical,
					Message:  fmt.Sprintf("Tool connected to cloud metadata service at %s", act.Destination),
					Tool:     act.ToolName,
					Fix:      "This is a strong SSRF indicator. Block access to 169.254.169.254.",
				})

			case isRFC1918(ip):
				findings = append(findings, Finding{
					Rule:     "net-probe-private-ip",
					Severity: SeverityHigh,
					Message:  fmt.Sprintf("Tool connected to private/RFC1918 address %s (possible SSRF)", act.Destination),
					Tool:     act.ToolName,
					Fix:      "Verify this internal connection is intentional and not SSRF.",
				})

			default:
				findings = append(findings, Finding{
					Rule:     "net-probe-outbound-connection",
					Severity: SeverityHigh,
					Message:  fmt.Sprintf("Tool made outbound %s connection to public IP %s", strings.ToUpper(act.Type), act.Destination),
					Tool:     act.ToolName,
					Fix:      "Audit outbound connections; ensure no data exfiltration is occurring.",
				})
			}
		}
	}

	return findings
}
