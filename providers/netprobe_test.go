package providers

import (
	"net"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// parseStraceLine tests
// ---------------------------------------------------------------------------

func TestParseStraceLine_TCPConnect_IPv4(t *testing.T) {
	line := `connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0`
	act, ok := parseStraceLine(line)
	if !ok {
		t.Fatal("expected parseStraceLine to return true for IPv4 TCP connect")
	}
	if act.Type != NetActivityTCP {
		t.Errorf("expected type %q, got %q", NetActivityTCP, act.Type)
	}
	if !strings.Contains(act.Destination, "93.184.216.34") {
		t.Errorf("expected destination to contain IP, got %q", act.Destination)
	}
	if !strings.Contains(act.Destination, "443") {
		t.Errorf("expected destination to contain port, got %q", act.Destination)
	}
}

func TestParseStraceLine_DNSConnect_Port53(t *testing.T) {
	line := `connect(5, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = 0`
	act, ok := parseStraceLine(line)
	if !ok {
		t.Fatal("expected parseStraceLine to return true for DNS connect")
	}
	if act.Type != NetActivityDNS {
		t.Errorf("expected type %q, got %q", NetActivityDNS, act.Type)
	}
	if !strings.Contains(act.Destination, "8.8.8.8") {
		t.Errorf("expected destination to contain DNS server IP, got %q", act.Destination)
	}
}

func TestParseStraceLine_IPv6_Connect(t *testing.T) {
	line := `connect(6, {sa_family=AF_INET6, sin6_port=htons(443), sin6_addr=inet_pton(AF_INET6, "2606:2800::1")}, 28) = 0`
	act, ok := parseStraceLine(line)
	if !ok {
		t.Fatal("expected parseStraceLine to return true for IPv6 connect")
	}
	if act.Type != NetActivityTCP {
		t.Errorf("expected type %q, got %q", NetActivityTCP, act.Type)
	}
	if !strings.Contains(act.Destination, "2606:2800::1") {
		t.Errorf("expected destination to contain IPv6 address, got %q", act.Destination)
	}
}

func TestParseStraceLine_UDPSendto(t *testing.T) {
	line := `sendto(4, "\x12\x34\x01\x00\x00\x01", 29, MSG_NOSIGNAL, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("1.1.1.1")}, 16) = 29`
	act, ok := parseStraceLine(line)
	if !ok {
		t.Fatal("expected parseStraceLine to return true for UDP sendto")
	}
	if act.Type != NetActivityDNS {
		t.Errorf("expected type %q for port 53 UDP, got %q", NetActivityDNS, act.Type)
	}
	if !strings.Contains(act.Destination, "1.1.1.1") {
		t.Errorf("expected destination to contain IP, got %q", act.Destination)
	}
}

func TestParseStraceLine_UDPSendto_NonDNS(t *testing.T) {
	line := `sendto(4, "data", 4, 0, {sa_family=AF_INET, sin_port=htons(5514), sin_addr=inet_addr("10.0.0.1")}, 16) = 4`
	act, ok := parseStraceLine(line)
	if !ok {
		t.Fatal("expected parseStraceLine to return true for non-DNS UDP sendto")
	}
	if act.Type != NetActivityUDP {
		t.Errorf("expected type %q for non-DNS UDP, got %q", NetActivityUDP, act.Type)
	}
}

func TestParseStraceLine_UnrelatedLine(t *testing.T) {
	tests := []struct {
		name string
		line string
	}{
		{"open syscall", `openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3`},
		{"write syscall", `write(1, "hello\n", 6) = 6`},
		{"empty line", ``},
		{"close syscall", `close(3) = 0`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := parseStraceLine(tt.line)
			if ok {
				t.Errorf("expected parseStraceLine to return false for unrelated line %q", tt.line)
			}
		})
	}
}

func TestParseStraceLine_TimestampSet(t *testing.T) {
	before := time.Now()
	line := `connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("1.2.3.4")}, 16) = 0`
	act, ok := parseStraceLine(line)
	after := time.Now()
	if !ok {
		t.Fatal("expected ok")
	}
	if act.Timestamp.Before(before) || act.Timestamp.After(after) {
		t.Errorf("timestamp %v not between %v and %v", act.Timestamp, before, after)
	}
}

// ---------------------------------------------------------------------------
// buildDummyArgs tests
// ---------------------------------------------------------------------------

func TestBuildDummyArgs_NilSchema(t *testing.T) {
	result := buildDummyArgs(nil)
	if len(result) != 0 {
		t.Errorf("expected empty map for nil schema, got %v", result)
	}
}

func TestBuildDummyArgs_EmptySchema(t *testing.T) {
	result := buildDummyArgs(map[string]any{})
	if len(result) != 0 {
		t.Errorf("expected empty map for schema without properties, got %v", result)
	}
}

func TestBuildDummyArgs_AllScalarTypes(t *testing.T) {
	schema := map[string]any{
		"properties": map[string]any{
			"name":    map[string]any{"type": "string"},
			"count":   map[string]any{"type": "number"},
			"active":  map[string]any{"type": "boolean"},
			"data":    map[string]any{"type": "object"},
			"tags":    map[string]any{"type": "array"},
			"nothing": map[string]any{"type": "null"},
			"qty":     map[string]any{"type": "integer"},
		},
	}

	result := buildDummyArgs(schema)

	if result["name"] != "test" {
		t.Errorf("string: expected %q, got %v", "test", result["name"])
	}
	if result["count"] != 0 {
		t.Errorf("number: expected 0, got %v", result["count"])
	}
	if result["active"] != false {
		t.Errorf("boolean: expected false, got %v", result["active"])
	}
	if _, ok := result["data"].(map[string]any); !ok {
		t.Errorf("object: expected map[string]any, got %T", result["data"])
	}
	if _, ok := result["tags"].([]any); !ok {
		t.Errorf("array: expected []any, got %T", result["tags"])
	}
	if result["nothing"] != nil {
		t.Errorf("null: expected nil, got %v", result["nothing"])
	}
	if result["qty"] != 0 {
		t.Errorf("integer: expected 0, got %v", result["qty"])
	}
}

func TestBuildDummyArgs_UnknownType(t *testing.T) {
	schema := map[string]any{
		"properties": map[string]any{
			"weird": map[string]any{"type": "exotic"},
		},
	}
	result := buildDummyArgs(schema)
	if result["weird"] != nil {
		t.Errorf("unknown type: expected nil, got %v", result["weird"])
	}
}

func TestBuildDummyArgs_AnyOf(t *testing.T) {
	schema := map[string]any{
		"properties": map[string]any{
			"flexible": map[string]any{
				"anyOf": []any{
					map[string]any{"type": "string"},
					map[string]any{"type": "number"},
				},
			},
		},
	}
	result := buildDummyArgs(schema)
	// anyOf should pick the first entry → string → "test"
	if result["flexible"] != "test" {
		t.Errorf("anyOf: expected %q, got %v", "test", result["flexible"])
	}
}

func TestBuildDummyArgs_OneOf(t *testing.T) {
	schema := map[string]any{
		"properties": map[string]any{
			"choice": map[string]any{
				"oneOf": []any{
					map[string]any{"type": "boolean"},
					map[string]any{"type": "string"},
				},
			},
		},
	}
	result := buildDummyArgs(schema)
	// oneOf should pick the first entry → boolean → false
	if result["choice"] != false {
		t.Errorf("oneOf: expected false, got %v", result["choice"])
	}
}

func TestBuildDummyArgs_NoTypeNoAnyOf(t *testing.T) {
	schema := map[string]any{
		"properties": map[string]any{
			"mystery": map[string]any{
				"description": "some parameter",
			},
		},
	}
	result := buildDummyArgs(schema)
	if result["mystery"] != nil {
		t.Errorf("no type: expected nil, got %v", result["mystery"])
	}
}

// ---------------------------------------------------------------------------
// parseProcNetAddr tests
// ---------------------------------------------------------------------------

func TestParseProcNetAddr_IPv4(t *testing.T) {
	tests := []struct {
		name     string
		hexAddr  string
		wantHost string
		wantPort string
	}{
		{
			name:     "127.0.1.1:53 (little-endian 0x0101007F)",
			hexAddr:  "0101007F:0035",
			wantHost: "127.0.1.1",
			wantPort: "53",
		},
		{
			name:     "0.0.0.0:80",
			hexAddr:  "00000000:0050",
			wantHost: "0.0.0.0",
			wantPort: "80",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, ok := parseProcNetAddr(tt.hexAddr)
			if !ok {
				t.Fatalf("expected parseProcNetAddr to return true for %q", tt.hexAddr)
			}
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				t.Fatalf("SplitHostPort(%q): %v", addr, err)
			}
			if host != tt.wantHost {
				t.Errorf("host: want %q, got %q", tt.wantHost, host)
			}
			if port != tt.wantPort {
				t.Errorf("port: want %q, got %q", tt.wantPort, port)
			}
		})
	}
}

func TestParseProcNetAddr_InvalidFormat(t *testing.T) {
	tests := []string{
		"",
		"NOCOLON",
		"GGGGGGGG:0050",
		"0101007F:ZZZZ",
	}
	for _, hex := range tests {
		_, ok := parseProcNetAddr(hex)
		if ok {
			t.Errorf("expected parseProcNetAddr(%q) to return false", hex)
		}
	}
}

// ---------------------------------------------------------------------------
// NetActivityToFindings tests
// ---------------------------------------------------------------------------

func TestNetActivityToFindings_Empty(t *testing.T) {
	findings := NetActivityToFindings(nil)
	if len(findings) != 0 {
		t.Errorf("expected no findings for nil input, got %d", len(findings))
	}
}

func TestNetActivityToFindings_DNSQuery(t *testing.T) {
	acts := []NetActivity{
		{Type: NetActivityDNS, Destination: "8.8.8.8:53", Timestamp: time.Now()},
	}
	findings := NetActivityToFindings(acts)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityWarning {
		t.Errorf("DNS: expected WARNING, got %v", f.Severity)
	}
	if f.Rule != "net-probe-dns-query" {
		t.Errorf("DNS: expected rule %q, got %q", "net-probe-dns-query", f.Rule)
	}
}

func TestNetActivityToFindings_MetadataService(t *testing.T) {
	acts := []NetActivity{
		{Type: NetActivityTCP, Destination: "169.254.169.254:80", Timestamp: time.Now(), ToolName: "evil-tool"},
	}
	findings := NetActivityToFindings(acts)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityCritical {
		t.Errorf("metadata: expected CRITICAL, got %v", f.Severity)
	}
	if f.Rule != "net-probe-metadata-service" {
		t.Errorf("metadata: expected rule %q, got %q", "net-probe-metadata-service", f.Rule)
	}
	if f.Tool != "evil-tool" {
		t.Errorf("metadata: expected tool %q, got %q", "evil-tool", f.Tool)
	}
}

func TestNetActivityToFindings_RFC1918(t *testing.T) {
	tests := []struct {
		name string
		dest string
	}{
		{"10.x.x.x", "10.0.0.1:8080"},
		{"172.16.x.x", "172.16.0.1:443"},
		{"192.168.x.x", "192.168.1.1:22"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acts := []NetActivity{
				{Type: NetActivityTCP, Destination: tt.dest, Timestamp: time.Now()},
			}
			findings := NetActivityToFindings(acts)
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(findings))
			}
			f := findings[0]
			if f.Severity != SeverityHigh {
				t.Errorf("RFC1918 %s: expected HIGH, got %v", tt.dest, f.Severity)
			}
			if f.Rule != "net-probe-private-ip" {
				t.Errorf("RFC1918: expected rule %q, got %q", "net-probe-private-ip", f.Rule)
			}
		})
	}
}

func TestNetActivityToFindings_PublicIP(t *testing.T) {
	acts := []NetActivity{
		{Type: NetActivityTCP, Destination: "93.184.216.34:443", Timestamp: time.Now()},
	}
	findings := NetActivityToFindings(acts)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("public IP: expected HIGH, got %v", f.Severity)
	}
	if f.Rule != "net-probe-outbound-connection" {
		t.Errorf("public IP: expected rule %q, got %q", "net-probe-outbound-connection", f.Rule)
	}
}

func TestNetActivityToFindings_UDPPublicIP(t *testing.T) {
	acts := []NetActivity{
		{Type: NetActivityUDP, Destination: "203.0.113.1:5514", Timestamp: time.Now()},
	}
	findings := NetActivityToFindings(acts)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("UDP public: expected HIGH, got %v", f.Severity)
	}
	// Message should mention UDP
	if !strings.Contains(f.Message, "UDP") {
		t.Errorf("expected message to mention UDP, got %q", f.Message)
	}
}

func TestNetActivityToFindings_UnparsableHost(t *testing.T) {
	// If the destination can't be parsed as host:port (no colon), it should
	// still produce a HIGH finding.
	acts := []NetActivity{
		{Type: NetActivityTCP, Destination: "notanip", Timestamp: time.Now()},
	}
	findings := NetActivityToFindings(acts)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for unparsable host, got %d", len(findings))
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("unparsable host: expected HIGH, got %v", findings[0].Severity)
	}
}

func TestNetActivityToFindings_ToolNamePropagated(t *testing.T) {
	acts := []NetActivity{
		{Type: NetActivityDNS, Destination: "1.1.1.1:53", Timestamp: time.Now(), ToolName: "fetch_data"},
	}
	findings := NetActivityToFindings(acts)
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	if findings[0].Tool != "fetch_data" {
		t.Errorf("expected tool %q, got %q", "fetch_data", findings[0].Tool)
	}
}

// ---------------------------------------------------------------------------
// NetActivity struct tests
// ---------------------------------------------------------------------------

func TestNetActivity_ZeroValue(t *testing.T) {
	var act NetActivity
	if act.Type != "" {
		t.Errorf("expected empty type, got %q", act.Type)
	}
	if act.Destination != "" {
		t.Errorf("expected empty destination, got %q", act.Destination)
	}
	if !act.Timestamp.IsZero() {
		t.Errorf("expected zero timestamp, got %v", act.Timestamp)
	}
	if act.ToolName != "" {
		t.Errorf("expected empty tool name, got %q", act.ToolName)
	}
}

func TestNetActivity_FieldAssignment(t *testing.T) {
	now := time.Now()
	act := NetActivity{
		Type:        NetActivityTCP,
		Destination: "1.2.3.4:443",
		Timestamp:   now,
		ToolName:    "my_tool",
	}
	if act.Type != NetActivityTCP {
		t.Errorf("type: want %q, got %q", NetActivityTCP, act.Type)
	}
	if act.Destination != "1.2.3.4:443" {
		t.Errorf("destination: want %q, got %q", "1.2.3.4:443", act.Destination)
	}
	if !act.Timestamp.Equal(now) {
		t.Errorf("timestamp: want %v, got %v", now, act.Timestamp)
	}
	if act.ToolName != "my_tool" {
		t.Errorf("tool name: want %q, got %q", "my_tool", act.ToolName)
	}
}

// ---------------------------------------------------------------------------
// isRFC1918 / isMetadataService unit tests
// ---------------------------------------------------------------------------

func TestIsRFC1918(t *testing.T) {
	privateIPs := []string{"10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.0.1", "192.168.255.255"}
	for _, ipStr := range privateIPs {
		ip := net.ParseIP(ipStr)
		if !isRFC1918(ip) {
			t.Errorf("expected %q to be RFC1918, but isRFC1918 returned false", ipStr)
		}
	}

	publicIPs := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "169.254.169.254"}
	for _, ipStr := range publicIPs {
		ip := net.ParseIP(ipStr)
		if isRFC1918(ip) {
			t.Errorf("expected %q to NOT be RFC1918, but isRFC1918 returned true", ipStr)
		}
	}
}

func TestIsMetadataService(t *testing.T) {
	ip := net.ParseIP("169.254.169.254")
	if !isMetadataService(ip) {
		t.Error("expected 169.254.169.254 to be metadata service")
	}

	notMeta := []string{"8.8.8.8", "10.0.0.1", "127.0.0.1"}
	for _, ipStr := range notMeta {
		ip := net.ParseIP(ipStr)
		if isMetadataService(ip) {
			t.Errorf("expected %q to NOT be metadata service", ipStr)
		}
	}
}
