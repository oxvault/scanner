# Oxvault Scanner

## What Is This

Oxvault Scanner is a CLI security tool that scans MCP (Model Context Protocol) servers for vulnerabilities before they are installed or used. MCP is the standard protocol for connecting AI agents (Claude, GPT, Copilot, Cursor) to external tools — and 66% of MCP servers have security vulnerabilities.

The scanner catches: tool description poisoning, command injection, path traversal, credential exposure, SSRF, rug pulls (tool description changes), sensitive function exposure, and network egress violations.

**This is the open-source core of the Oxvault platform.** Other products (gateway, registry, dashboard) live in separate private repos and import this scanner's detection engine.

## Tech Stack

- **Language:** Go 1.24+
- **CLI framework:** Cobra
- **Output formats:** Terminal (default), SARIF, JSON
- **No database, no HTTP server** — pure CLI tool

## Architecture

```
cmd/oxvault/        → Cobra commands (scan, pin, check)
app/                → DI container (App struct, InitProviders, InitEngines, functional options)
engines/            → Orchestrators (scanner, pinner — coordinate providers)
providers/          → Leaf nodes (MCP client, SAST, rule matcher, reporter, pin store, resolver)
rules/              → External rule definitions (semgrep YAML, YARA rules)
examples/           → Intentionally vulnerable MCP servers for testing
config/             → Config loading + MCP config auto-discovery
testutil/           → Mocks + test fixtures
```

### Layer Rules

- `cmd/` → knows about: `app/`
- `app/` → knows about: `config/`, `engines/`, `providers/`
- `engines/` → knows about: `providers/` (interfaces only)
- `providers/` → knows about: nothing (leaf nodes)
- **No circular dependencies.** Each layer only looks down.

### App Container Pattern

Uses the same DI pattern as shuttle-link/server and gamescoregenius/server:

1. **App struct** holds all engines and providers as private fields
2. **AppInterface** defines contract (Initialize, Shutdown, getters)
3. **Functional options** (`WithXXX`) for constructor injection in tests
4. **Ordered initialization:** `InitConfig()` → `InitProviders()` → `InitEngines()`
5. **Lazy init:** each `InitXXX()` checks `if x == nil` before creating
6. **Interfaces everywhere** for mockability

### Data Flow: `oxvault scan ./server`

```
cmd/scan.go           → parse flags, create App, Initialize()
app/app.go            → InitProviders() → InitEngines()
engines/scanner.go    → Scan() orchestrates:
  ├→ providers/resolver     → download/clone the target
  ├→ providers/sast         → analyze source code
  ├→ providers/mcpclient    → connect via JSON-RPC, get tools/list
  ├→ providers/rulematcher  → scan descriptions, classify risk tiers
  └→ providers/reporter     → format output
cmd/scan.go           → print output, exit 1 if critical findings
```

## MCP Protocol Basics

MCP uses JSON-RPC 2.0 over stdin/stdout (local) or HTTP (remote). The key call for this scanner:

```
Client sends:  {"jsonrpc":"2.0","id":1,"method":"initialize","params":{...}}
Server sends:  {"jsonrpc":"2.0","id":1,"result":{"serverInfo":{...},"capabilities":{...}}}

Client sends:  {"jsonrpc":"2.0","method":"notifications/initialized"}

Client sends:  {"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
Server sends:  {"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"...","description":"...","inputSchema":{...}}]}}
```

The scanner connects to a server, gets `tools/list`, and scans every tool's description and input schema for security patterns.

## What The Scanner Detects

### Check 1: Source Code SAST
AST-based taint analysis — detects when a tool parameter flows to a dangerous sink (os.popen, subprocess, child_process.exec).

### Check 2: Tool Description Poisoning
Regex + byte-level scanning for hidden instructions in tool descriptions:
- `<IMPORTANT>` / `<SYSTEM>` tags
- Unicode invisible characters (Tags block U+E0000-E007F, zero-width steganography)
- Secrecy instructions ("do not tell the user")
- Sensitive file path references (~/.ssh, ~/.aws)

### Check 3: Sensitive Function Exposure
Classifies tools into risk tiers based on capabilities:
- Tier 1 (CRITICAL): shell execution, code eval
- Tier 2 (HIGH): filesystem, database, infrastructure access
- Tier 3 (MEDIUM): network requests, messaging
- Tier 4 (LOW): compute-only, data transformation

### Check 4: Network Egress Analysis
Detects tools that make outbound network calls when they shouldn't. A calculator that phones home = flagged.

### Check 5: Credential Hygiene
Regex patterns for hardcoded API keys (AWS, OpenAI, GitHub PATs), private keys, bearer tokens. Also checks HOW credentials are loaded (hardcoded vs env var vs OAuth).

### Check 6: Dependency Audit
Checks package.json/requirements.txt against known MCP CVE database.

### Check 7: Tool Pinning (Rug Pull Detection)
SHA-256 hash of (name, description, inputSchema) per tool. Stored in `.oxvault/pins.json`. On subsequent checks, compares hashes and alerts on changes.

### Check 8: Output Sanitization Patterns
Scans tool response patterns in source code for potential sensitive data leakage (credentials, PII, internal infrastructure details).

## CLI Commands

```bash
oxvault scan ./my-server                          # Scan local project
oxvault scan @company/mcp-server                  # Scan npm package
oxvault scan github:user/repo                     # Scan GitHub repo
oxvault scan --config ~/.claude/claude_desktop_config.json  # Scan all configured servers
oxvault scan ./server --format=sarif --fail-on=high        # CI/CD mode
oxvault pin ./my-server                           # Pin tool description hashes
oxvault check ./my-server                         # Check for rug pulls
```

## Quality Gates

```bash
make build      # go build ./cmd/oxvault
make test       # go test ./...
make lint       # golangci-lint run
```

All three must pass before merging.

## Project Context

- **Organization:** github.com/oxvault
- **This repo:** github.com/oxvault/scanner (private, will go public at launch)
- **Related repos (future):** oxvault/gateway, oxvault/registry, oxvault/dashboard
- **Planning docs:** /root/Code/oxvault/*.md (product plan, architecture, CVE database, market validation)
- **Go module:** github.com/oxvault/scanner
