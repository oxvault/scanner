package providers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"sync/atomic"
)

type mcpClient struct {
	logger *slog.Logger
	nextID atomic.Int64
}

func NewMCPClient(logger *slog.Logger) MCPClient {
	return &mcpClient{logger: logger}
}

// jsonRPCRequest is a JSON-RPC 2.0 request
type jsonRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// jsonRPCResponse is a JSON-RPC 2.0 response
type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// mcpProcess holds the spawned server process
type mcpProcess struct {
	cmd    *exec.Cmd
	stdin  *json.Encoder
	stdout *bufio.Scanner
}

func (c *mcpClient) Connect(cmd string, args []string) (*MCPSession, error) {
	c.logger.Info("connecting to MCP server", "cmd", cmd, "args", args)

	proc := exec.Command(cmd, args...)
	stdin, err := proc.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := proc.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	if err := proc.Start(); err != nil {
		return nil, fmt.Errorf("start process: %w", err)
	}

	encoder := json.NewEncoder(stdin)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB buffer

	process := &mcpProcess{
		cmd:    proc,
		stdin:  encoder,
		stdout: scanner,
	}

	// Send initialize request
	initID := c.nextID.Add(1)
	initReq := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      initID,
		Method:  "initialize",
		Params: map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    "oxvault",
				"version": "0.1.0",
			},
		},
	}

	if err := encoder.Encode(initReq); err != nil {
		proc.Process.Kill()
		return nil, fmt.Errorf("send initialize: %w", err)
	}

	// Read initialize response
	if !scanner.Scan() {
		proc.Process.Kill()
		return nil, fmt.Errorf("no response from server")
	}

	var initResp jsonRPCResponse
	if err := json.Unmarshal(scanner.Bytes(), &initResp); err != nil {
		proc.Process.Kill()
		return nil, fmt.Errorf("parse initialize response: %w", err)
	}

	if initResp.Error != nil {
		proc.Process.Kill()
		return nil, fmt.Errorf("server error: %s", initResp.Error.Message)
	}

	// Parse server info
	var initResult struct {
		ServerInfo MCPServerInfo `json:"serverInfo"`
	}
	if err := json.Unmarshal(initResp.Result, &initResult); err != nil {
		proc.Process.Kill()
		return nil, fmt.Errorf("parse server info: %w", err)
	}

	// Send initialized notification
	notif := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}
	if err := encoder.Encode(notif); err != nil {
		proc.Process.Kill()
		return nil, fmt.Errorf("send initialized: %w", err)
	}

	c.logger.Info("connected to MCP server",
		"server", initResult.ServerInfo.Name,
		"version", initResult.ServerInfo.Version,
	)

	return &MCPSession{
		ServerInfo: initResult.ServerInfo,
		process:    process,
	}, nil
}

func (c *mcpClient) ListTools(session *MCPSession) ([]MCPTool, error) {
	process := session.process.(*mcpProcess)

	reqID := c.nextID.Add(1)
	req := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      reqID,
		Method:  "tools/list",
		Params:  map[string]any{},
	}

	if err := process.stdin.Encode(req); err != nil {
		return nil, fmt.Errorf("send tools/list: %w", err)
	}

	if !process.stdout.Scan() {
		return nil, fmt.Errorf("no response for tools/list")
	}

	var resp jsonRPCResponse
	if err := json.Unmarshal(process.stdout.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("parse tools/list response: %w", err)
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("tools/list error: %s", resp.Error.Message)
	}

	var result struct {
		Tools []MCPTool `json:"tools"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("parse tools: %w", err)
	}

	c.logger.Info("received tools", "count", len(result.Tools))
	session.Tools = result.Tools

	return result.Tools, nil
}

func (c *mcpClient) Close(session *MCPSession) error {
	if session == nil || session.process == nil {
		return nil
	}

	process := session.process.(*mcpProcess)

	if process.cmd.Process != nil {
		process.cmd.Process.Kill()
		process.cmd.Wait()
	}

	c.logger.Info("disconnected from MCP server")
	return nil
}
