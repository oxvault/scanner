# Oxvault Scanner

## What Is This

Oxvault Scanner is a CLI security tool that scans **AI supply chain artifacts** for vulnerabilities before they are loaded or used. Three artifact classes are covered (or scheduled):

1. **MCP servers** (v0.3, shipped) — Model Context Protocol servers that AI agents like Claude, GPT, Copilot, and Cursor connect to. 66% of MCP servers have security vulnerabilities.
2. **ML model artifacts** (v0.4, in progress) — pickle (.pkl/.pt/.pth), ONNX, safetensors, model cards, and signature manifests. Pickle deserialization equals arbitrary code execution; we disassemble opcodes without executing.
3. **RAG corpora** (v0.5, planned) — documents indexed for retrieval-augmented generation. Same prompt-injection patterns as MCP tool descriptions, applied to retrieval-time content.

**This is the open-source core of the Oxvault platform.** Other products (gateway, registry, dashboard) will live in separate private repos and import this scanner's detection engine.

## Tech Stack

- **Language:** Go 1.24
- **CLI framework:** Cobra
- **Output formats:** Terminal (default), SARIF, JSON
- **No database, no HTTP server** — pure CLI tool
- **CI/CD:** GitHub Actions (go-test.yml) + GoReleaser (release.yml)

## Architecture

```
cmd/main.go              → Cobra CLI entry point (scan, pin, check commands)
app/app.go               → DI container (App struct, functional options, ordered init)
engines/                 → Orchestrators (ScannerEngine, PinEngine)
providers/               → Leaf nodes — each does one thing:
  ├── interfaces.go          All provider contracts (MCP + AIBOM)
  ├── types.go               Finding, MCPTool, RiskTier, Severity, ArtifactFormat, PackageKind
  ├── fileutil.go            Shared file helpers + DetectArtifactFormat
  ├── mcpclient.go           JSON-RPC client (initialize → tools/list)
  ├── rulematcher.go         Description poisoning + argument injection + response patterns
  ├── sast.go                Source code analysis (Python, JS/TS, Go) + egress detection
  ├── reporter.go            Output formatting (terminal, SARIF, JSON) + ANSI sanitisation
  ├── pinstore.go            SHA-256 tool hash storage for rug pull detection
  ├── resolver.go            Target resolution (local path, npm, GitHub, hf:org/model stub)
  ├── sanitizer.go           Response sanitization patterns (PII, keys)
  ├── aibom_composer.go      AIBOMComposer — dispatches model artifacts to sub-providers
  ├── pickle.go              Pickle opcode disassembler (no execution, 11 rules)
  ├── pickle_opcodes.go      Pickle protocol 0-5 opcode constants
  ├── safetensors.go         Safetensors header + offset + metadata validation
  ├── onnx.go                ONNX protobuf wire walker + custom-op + external-data checks
  ├── modelcard.go           Model card YAML/markdown checker (delegates to RuleMatcher)
  └── signature.go           OpenSSF Model Signing manifest verifier (hash-only v0.4)
patterns/                → Pure data — detection pattern lists (MCP + AIBOM)
  ├── *.go                   MCP detection pattern lists
  └── aibom.go               Dangerous globals, ONNX domains, model card keys, etc.
internal/version/        → Single source of truth for the CLI version string
  └── version.go
config/config.go         → Config struct + defaults
rules/                   → External rule definitions (semgrep YAML, YARA — future)
examples/                → Intentionally vulnerable MCP servers for testing + demos
testdata/aibom/          → Binary fixtures for pickle, safetensors, onnx, modelcard, signature
testutil/mocks.go        → Mock implementations of all provider interfaces
```

### Layer Rules

- `cmd/` → knows about: `app/`
- `app/` → knows about: `config/`, `engines/`, `providers/`
- `engines/` → knows about: `providers/` (interfaces only)
- `providers/` → knows about: `patterns/`
- `patterns/` → knows about: nothing (pure data, leaf node)
- `internal/version/` → knows about: nothing
- **No circular dependencies.** Each layer only looks down.

### App Container Pattern

Same DI pattern as shuttle-link/server and gamescoregenius/server:

1. **App struct** holds all engines and providers as private fields
2. **AppInterface** defines contract (Initialize, Shutdown, getters)
3. **Functional options** (`WithXXX`) for constructor injection in tests
4. **Ordered initialization:** `Initialize()` → `InitProviders()` → `InitEngines()`
5. **Lazy init:** each `InitXXX()` checks `if x == nil` before creating — options set before init are preserved
6. **Interfaces everywhere** for mockability

### Data Flow

The resolver classifies the target into a `PackageKind`. The engine dispatches based on kind:

#### MCP server scan: `oxvault scan ./server`

```
cmd/main.go (newScanCmd)  → parse flags, create App, Initialize()
app/app.go                → InitProviders() → InitEngines()
engines/scanner.go        → resolver returns Kind=KindMCPServer → MCP flow:
  ├→ providers/resolver      → download/clone the target
  ├→ providers/sast          → analyze source code + detect egress
  ├→ providers/mcpclient     → connect via JSON-RPC, get tools/list
  ├→ providers/rulematcher   → scan descriptions, classify risk tiers
  └→ providers/reporter      → format findings
cmd/main.go               → print output, exit 1 if severity >= --fail-on
```

#### Model artifact scan: `oxvault scan ./model.pkl` (v0.4)

```
cmd/main.go (newScanCmd)  → parse flags, create App, Initialize()
engines/scanner.go        → resolver returns Kind=KindModelArtifact|KindModelDirectory → AIBOM flow:
  └→ providers/aibom_composer → DetectArtifactFormat per file → dispatch:
      ├→ providers/pickle      → opcode disassembly (no execution)
      ├→ providers/safetensors → header + offset + metadata validation
      ├→ providers/onnx        → protobuf wire walk
      ├→ providers/modelcard   → YAML frontmatter + body via RuleMatcher
      └→ providers/signature   → OpenSSF Model Signing manifest verification
cmd/main.go               → print output (same Finding type / Reporter as MCP scan)
```

The composer also aggregates per-directory findings (e.g. `aibom-modelcard-missing` when a model artifact lives in a directory with no card).

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

### Source Code SAST (providers/sast.go + patterns/)
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

## AIBOM Detection Capabilities (v0.4 — model artifacts)

### Pickle disassembly (providers/pickle.go)
Reads `.pkl`, `.pt`, `.pth` files at the opcode level — no `pickle.load`, no execution.
- Protocol 0-5 opcode coverage; tracks GLOBAL/STACK_GLOBAL/REDUCE for callable references
- Dangerous globals (CRITICAL): `os.system`, `subprocess.*`, `eval`, `exec`, `__import__`, `runpy.*`
- Network primitives (HIGH): `socket.*`, `urllib.*`, `requests.*`
- Filesystem destructive (WARNING): `shutil.rmtree`, `os.remove`, `pathlib.write_*`
- ML allowlist suppress-to-INFO: `torch._utils.*`, `numpy.core.multiarray.*`
- PyTorch ZIP wrapper detection (recurses into `data.pkl`, capped at 16 inner entries)
- DoS guards: 2 GiB file cap, 1 M opcodes cap, 200 K stack cap, depth-4 recursion cap, top-level recover

### Safetensors validation (providers/safetensors.go)
- Header overflow / empty / malformed JSON detection
- Tensor offset bounds + overlap detection
- Dtype validation against HF spec (F32, F16, BF16, F64, I*, U*, F8_E4M3, F8_E5M2)
- Pre-decode pickle-magic scan for `` JSON escape smuggling
- Metadata prompt-injection via existing RuleMatcher.ScanDescription

### ONNX protobuf walking (providers/onnx.go)
Hand-rolled wire walker — no codegen, no vendored .proto.
- Malformed protobuf (HIGH) — varint cap, length-delim bounds, group rejection
- Custom-domain operators (WARNING) — outside `ai.onnx`, `ai.onnx.ml`, etc.
- Suspicious operator domains (HIGH) — URLs, `javascript:`, `data:` schemes
- External data path traversal (WARNING) — `../`, absolute paths, NTFS ADS, URLs
- Oversized initializer (WARNING) — dim product overflow / above 256 M elements
- Missing producer name (INFO)

### Model card validation (providers/modelcard.go)
README.md / MODEL_CARD.md / model_card.yaml inspection. yaml.v3 dependency.
- Suspicious instructions (HIGH) — delegates to RuleMatcher.ScanDescription (same engine as MCP poisoning)
- Missing license / source / eval (WARNING / INFO) — frontmatter keys + body section headers
- Uncited claims (INFO) — accuracy/F1/AUC numbers without eval section or citation
- Malformed YAML / too-large / empty — distinct rule IDs (CWE-20)

### Signature verification (providers/signature.go) — v0.4 hash-only
- OpenSSF Model Signing manifest (`model_signing.json`) parsing
- SHA-256 hash mismatch detection (CRITICAL)
- Untrusted issuer detection (HIGH) against configurable trusted-issuer list
- Sigstore bundle (`.sigstore`) presence check (full Rekor/Fulcio verification deferred to v0.4.1)
- Missing signature (WARNING)

## CLI Commands

```bash
# MCP server scans (v0.3)
oxvault scan ./my-server                          # Local project
oxvault scan @company/mcp-server                  # npm package
oxvault scan github:user/repo                     # GitHub repo
oxvault scan ./server --format=sarif --fail-on=high  # CI/CD mode
oxvault scan ./server --skip-sast                 # Skip source analysis
oxvault scan ./server --skip-manifest             # Skip MCP connection
oxvault scan ./server --skip-egress               # Skip egress detection

# Model artifact scans (v0.4)
oxvault scan ./model.pkl                          # Single pickle file
oxvault scan ./model.safetensors                  # Single safetensors file
oxvault scan ./model.onnx                         # Single ONNX file
oxvault scan ./hf-cache/                          # Directory of artifacts (mixed formats)
# oxvault scan hf:org/model                       # Hugging Face — Day 8

# Rug-pull pinning (v0.3)
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
