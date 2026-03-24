<div align="center">

<img src="https://avatars.githubusercontent.com/u/270633514?v=4" width="100" alt="Oxvault logo" />

# Oxvault Scanner

**Detect vulnerabilities in MCP servers before they run.**

[![Go](https://img.shields.io/badge/Go-1.24-00ADD8?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue)](LICENSE)
[![CI](https://github.com/oxvault/scanner/actions/workflows/go-test.yml/badge.svg)](https://github.com/oxvault/scanner/actions/workflows/go-test.yml)

</div>

---

MCP (Model Context Protocol) is the standard for connecting AI agents to external tools. **66% of MCP servers have security vulnerabilities.** Oxvault Scanner catches them before installation.

## What It Detects

| Check | What It Catches |
|---|---|
| **Tool poisoning** | Hidden `<IMPORTANT>` tags, Unicode steganography, secrecy instructions |
| **Command injection** | `os.popen`, `subprocess(shell=True)`, `child_process.exec`, `eval` |
| **Credential exposure** | Hardcoded AWS keys, API tokens, GitHub PATs, Stripe keys, private keys |
| **Path traversal** | Concatenated file paths, `../` patterns |
| **SSRF** | Metadata service IPs, RFC 1918 ranges, localhost references |
| **Sensitive exposure** | Risk tier classification (shell access, filesystem, network, compute-only) |
| **Network egress** | Tools that phone home when they shouldn't |
| **Rug pulls** | Tool description changes detected via SHA-256 hash pinning |
| **Unsafe deserialization** | `pickle.load`, `yaml.load` without SafeLoader |
| **Destructive operations** | `shutil.rmtree`, `os.remove`, `fs.unlinkSync` |

## Quick Start

```bash
# Install
go install github.com/oxvault/scanner/cmd@latest

# Scan a local MCP server project
oxvault scan ./my-mcp-server

# Scan an npm package
oxvault scan @company/mcp-server

# Scan a GitHub repo
oxvault scan github:user/mcp-server

# CI/CD mode — exit non-zero on critical findings, output SARIF
oxvault scan ./server --format=sarif --fail-on=high
```

## Example Output

```
$ oxvault scan github:harishsg993010/damn-vulnerable-MCP-server --skip-manifest

  ── Source Code Analysis ──────────────────────────────────

  CRITICAL  mcp-cmd-injection
  challenges/easy/challenge2/server_sse.py:31
  Subprocess with shell=True: result = subprocess.check_output(command, shell=True, text=True)

  CRITICAL  mcp-code-eval
  challenges/hard/challenge8/server_sse.py:26
  Dynamic code evaluation: result = eval(expression)

  ── Credential Analysis ───────────────────────────────────

  CRITICAL  mcp-hardcoded-api-key
  challenges/easy/challenge1/server.py:15
  Hardcoded API key (OpenAI format): API Key: sk-a1b2c3d4e5f6g7h8i9j0

  CRITICAL  mcp-hardcoded-aws-key
  challenges/hard/challenge10/server.py:36
  Hardcoded AWS access key: AccessKeyID = AKIAIOSFODNN7EXAMPLE

  ── Summary ───────────────────────────────────────────────

  19 CRITICAL · 0 HIGH · 0 WARNING · 0 INFO

  This server is NOT SAFE to install.
```

## Rug Pull Detection

Pin tool descriptions and detect changes between sessions:

```bash
# Pin current tool hashes
oxvault pin npx -y @company/mcp-server
# Pinned 5 tools. Hashes saved to .oxvault/pins.json

# Later — check for changes
oxvault check npx -y @company/mcp-server
# ✓ get_weather: hash unchanged
# ✗ send_email: Tool description or schema changed — possible rug pull
```

## Output Formats

| Format | Flag | Use Case |
|---|---|---|
| Terminal | `--format=terminal` (default) | Human-readable, colored output |
| SARIF | `--format=sarif` | GitHub Advanced Security, GitLab CI |
| JSON | `--format=json` | Programmatic consumption, pipelines |

## CI/CD Integration

### GitHub Actions

```yaml
- name: Scan MCP servers
  run: |
    go install github.com/oxvault/scanner/cmd@latest
    oxvault scan ./my-mcp-server --format=sarif --fail-on=high > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Architecture

```
cmd/main.go           CLI entry point (cobra)
app/app.go            DI container (functional options, ordered init)
engines/              Orchestrators (scanner, pinner)
providers/            Leaf nodes (MCP client, SAST, rules, reporter, pin store)
rules/                External rule definitions (semgrep, YARA)
examples/             Intentionally vulnerable servers for testing
```

## Development

```bash
make build       # Build binary to bin/oxvault
make test        # Run all tests
make lint        # Run golangci-lint
make scan-demo   # Build + scan example vulnerable servers
```

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

<div align="center">

Part of the [Oxvault](https://github.com/oxvault) security platform.

</div>
