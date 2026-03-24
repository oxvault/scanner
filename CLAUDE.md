# Oxvault Scanner

## What Is This

Oxvault Scanner is a CLI security tool that scans MCP (Model Context Protocol) servers for vulnerabilities before they are installed or used. MCP is the standard protocol for connecting AI agents (Claude, GPT, Copilot, Cursor) to external tools — and 66% of MCP servers have security vulnerabilities.

**This is the open-source core of the Oxvault platform.** Other products (gateway, registry, dashboard) will live in separate private repos and import this scanner's detection engine.

## Tech Stack

- **Language:** Go 1.24
- **CLI framework:** Cobra
- **Output formats:** Terminal (default), SARIF, JSON
- **No database, no HTTP server** — pure CLI tool
- **CI/CD:** GitHub Actions (go-test.yml) + GoReleaser (release.yml)

## Architecture

```
cmd/main.go         → Cobra CLI entry point (scan, pin, check commands)
app/app.go          → DI container (App struct, functional options, ordered init)
engines/            → Orchestrators (ScannerEngine, PinEngine)
providers/           → Leaf nodes — each does one thing:
  ├── interfaces.go     All provider contracts
  ├── types.go          Finding, MCPTool, RiskTier, Severity, OutputFormat
  ├── mcpclient.go      JSON-RPC client (initialize → tools/list)
  ├── rulematcher.go    Description poisoning + argument injection + response patterns
  ├── sast.go           Source code analysis (Python, JS/TS, Go) + egress detection
  ├── reporter.go       Output formatting (terminal, SARIF, JSON)
  ├── pinstore.go       SHA-256 tool hash storage for rug pull detection
  ├── resolver.go       Target resolution (local path, npm, GitHub)
  └── sanitizer.go      Response sanitization patterns (PII, keys)
config/config.go    → Config struct + defaults
rules/              → External rule definitions (semgrep YAML, YARA — future)
examples/           → Intentionally vulnerable MCP servers for testing + demos
testutil/mocks.go   → Mock implementations of all provider interfaces
```

### Layer Rules

- `cmd/` → knows about: `app/`
- `app/` → knows about: `config/`, `engines/`, `providers/`
- `engines/` → knows about: `providers/` (interfaces only)
- `providers/` → knows about: nothing (leaf nodes)
- **No circular dependencies.** Each layer only looks down.

### App Container Pattern

Same DI pattern as shuttle-link/server and gamescoregenius/server:

1. **App struct** holds all engines and providers as private fields
2. **AppInterface** defines contract (Initialize, Shutdown, getters)
3. **Functional options** (`WithXXX`) for constructor injection in tests
4. **Ordered initialization:** `Initialize()` → `InitProviders()` → `InitEngines()`
5. **Lazy init:** each `InitXXX()` checks `if x == nil` before creating — options set before init are preserved
6. **Interfaces everywhere** for mockability

### Data Flow: `oxvault scan ./server`

```
cmd/main.go (newScanCmd)  → parse flags, create App, Initialize()
app/app.go                → InitProviders() → InitEngines()
engines/scanner.go        → Scan() orchestrates:
  ├→ providers/resolver      → download/clone the target
  ├→ providers/sast          → analyze source code + detect egress
  ├→ providers/mcpclient     → connect via JSON-RPC, get tools/list
  ├→ providers/rulematcher   → scan descriptions, classify risk tiers
  └→ providers/reporter      → format findings
cmd/main.go               → print output, exit 1 if severity >= --fail-on
```

## MCP Protocol

MCP uses JSON-RPC 2.0 over stdin/stdout. The scanner's key interaction:

```
→ {"jsonrpc":"2.0","id":1,"method":"initialize","params":{...}}
← {"jsonrpc":"2.0","id":1,"result":{"serverInfo":{...},"capabilities":{...}}}
→ {"jsonrpc":"2.0","method":"notifications/initialized"}
→ {"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
← {"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"...","description":"...","inputSchema":{...}}]}}
```

## Detection Capabilities

### Source Code SAST (providers/sast.go)
Pattern-based analysis for Python, JavaScript/TypeScript, and Go:
- Command injection: `os.popen`, `subprocess(shell=True)`, `child_process.exec/execSync`, `exec.Command`
- Code eval: `eval()`, `exec()`, `new Function()`, `vm.runInNewContext`
- Unsafe deserialization: `pickle.load`, `yaml.load` without SafeLoader
- Path traversal: concatenated file paths
- Destructive operations: `shutil.rmtree`, `fs.unlinkSync`, `os.RemoveAll`
- Dynamic imports: `__import__()`, `require('child_process')`
- Sandbox escape: `vm.runInNewContext`, `vm.runInThisContext`
- Network egress: `requests.post`, `fetch`, `axios`, `net.Dial`, `http.NewRequest`
- Auto-skips test files and directories (`tests/`, `*_test.go`, `*.test.js`, etc.)

### Tool Description Poisoning (providers/rulematcher.go — ScanDescription)
- Tag injection: `<IMPORTANT>`, `<SYSTEM>`, `<INST>`, `<HIDDEN>`, `<NOTE>`
- Unicode invisible characters: Tags block (U+E0000-E007F), zero-width steganography, BiDi overrides
- HTML comment injection: `<!-- instructions -->`
- Markdown hidden comments: `[//]: #`
- Role markers: `SYSTEM:`, `USER:` in descriptions
- Secrecy instructions: "do not tell the user"
- Prompt overrides: "ignore previous instructions"
- Cross-tool references: "before using this tool, call X"
- Emotional manipulation: "urgent", "critical override", "emergency"
- Sensitive file paths: `~/.ssh`, `~/.aws`, `~/.cursor`, `~/.docker`, `~/.kube`
- Exfiltration instructions: "pass content as parameter"

### Argument Injection (providers/rulematcher.go — ScanArguments)
- Shell metacharacters: `; | & $ ()` backticks
- Path traversal: `../`
- SQL injection: `SELECT...FROM`, `UNION`, `DROP`
- SSRF: `169.254.169.254`, `metadata.google.internal`, RFC 1918 IPs
- LDAP injection: `)(` patterns
- XML injection: `<!ENTITY`, `<![CDATA[`
- Template injection: `{{`, `${`, `#{`
- Log injection: `\n`, `\r` escapes

### Response Sanitization (providers/rulematcher.go — ScanResponse)
- AWS keys, OpenAI keys, GitHub PATs, Stripe keys
- Private keys, Bearer tokens, JWTs
- Database connection strings with credentials
- SSNs, email addresses, passwords
- Internal hostnames (`.internal`, `.local`, `.corp`)
- RFC 1918 IP addresses
- Slack/Discord webhook URLs

### Credential Exposure (providers/sast.go)
- Hardcoded: AWS AKIA keys, OpenAI `sk-` keys, GitHub `ghp_` PATs
- Bearer tokens, private key material
- Slack/Discord webhooks, Stripe `sk_live_` keys, Twilio SIDs
- Environment variable leakage via `process.env`

### Risk Tier Classification (providers/rulematcher.go — ClassifyTool)
- Tier 1 CRITICAL: shell execution, code eval
- Tier 2 HIGH: filesystem, database, infrastructure
- Tier 3 MEDIUM: network requests, messaging
- Tier 4 LOW: compute-only, data transformation

### Rug Pull Detection (providers/pinstore.go)
- SHA-256 hash of (name, description, inputSchema) per tool
- Stored in `.oxvault/pins.json`
- Detects: changed descriptions, new tools, removed tools

## CLI Commands

```bash
oxvault scan ./my-server                          # Scan local project
oxvault scan @company/mcp-server                  # Scan npm package
oxvault scan github:user/repo                     # Scan GitHub repo
oxvault scan ./server --format=sarif --fail-on=high  # CI/CD mode
oxvault scan ./server --skip-sast                 # Skip source analysis
oxvault scan ./server --skip-manifest             # Skip MCP connection
oxvault scan ./server --skip-egress               # Skip egress detection
oxvault pin npx -y @company/server                # Pin tool hashes
oxvault check npx -y @company/server              # Check for rug pulls
```

## Quality Gates

```bash
make build      # go build -o bin/oxvault ./cmd/
make test       # go test ./... -v
make lint       # golangci-lint run
make scan-demo  # Build + scan example vulnerable servers
```

All three (build, test, lint) must pass. CI runs on every push and PR.

## Testing

- **providers/** — comprehensive tests for every detection pattern, all output formats, pin lifecycle
- **engines/** — mock-based tests for scan orchestration, skip options, error handling
- **app/** — DI container wiring, functional options, lazy init, idempotency
- **testutil/mocks.go** — mock implementations of all 6 provider interfaces with call counters

## Project Context

- **Organization:** github.com/oxvault
- **This repo:** github.com/oxvault/scanner (private, will go public at launch)
- **Related repos (future):** oxvault/gateway, oxvault/registry, oxvault/dashboard
- **Planning docs:** /root/Code/oxvault/*.md
- **Go module:** github.com/oxvault/scanner
