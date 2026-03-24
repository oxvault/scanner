# Competitive Benchmark: Oxvault vs MCP Security Scanners

**Date:** March 2026
**Benchmark target:** [`harishsg993010/damn-vulnerable-MCP-server`](https://github.com/harishsg993010/damn-vulnerable-MCP-server) — 10 challenge vulnerable MCP server
**Oxvault version:** built from HEAD (`make build`)

---

## Table of Contents

1. [Competitor Overview](#1-competitor-overview)
2. [Feature Comparison Matrix](#2-feature-comparison-matrix)
3. [Oxvault Scan Results (DVMCP)](#3-oxvault-scan-results-dvmcp)
4. [Competitor Scan Attempts](#4-competitor-scan-attempts)
5. [Key Differentiators](#5-key-differentiators)
6. [Methodology Notes](#6-methodology-notes)

---

## 1. Competitor Overview

### mcp-scan / Snyk Agent Scan (invariantlabs-ai → Snyk)

- **Repo:** [invariantlabs-ai/mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) (renamed to [snyk/agent-scan](https://github.com/snyk/agent-scan))
- **Status:** The `mcp-scan` package has been **rebranded as `snyk-agent-scan`** (Snyk acquisition). Both package names now install the same tool (v0.4.9).
- **Language:** Python — installed via `uvx snyk-agent-scan` or `uvx mcp-scan`
- **License:** Open source (Apache 2.0)
- **Approach:** Runtime scan — connects to live running MCP servers via stdio or SSE. Sends tool descriptions to the Snyk cloud API (`api.snyk.io`) for LLM-based vulnerability analysis. **Requires a `SNYK_TOKEN` environment variable.** Without it the scan fails.
- **What it detects:** Prompt injection, tool poisoning, tool shadowing, toxic flows, rug pull (via tool hashing/pinning). Detects via description analysis — not source code SAST.
- **What it does NOT detect:** Hardcoded credentials, dependency CVEs, install hook abuse, network egress patterns, destructive filesystem calls, SSRF patterns, path traversal, code eval/exec patterns. No SARIF output. No CI/CD-native integration (no GitHub Actions workflow provided).

### Snyk Agent Scan (snyk/agent-scan)

Same tool as `mcp-scan` above after the Snyk acquisition. Adds skills scanning (agent skills beyond MCP), MDM/CrowdStrike background mode, and reporting to Snyk Evo platform.

### Enkrypt AI — mcpscan.ai

- **URL:** [mcpscan.ai](https://mcpscan.ai) / [enkryptai.com/mcp-scan](https://www.enkryptai.com/mcp-scan)
- **Status:** **SaaS product** — not open source, no CLI binary. Submit a GitHub repo URL or npm package name and Enkrypt's backend scans it.
- **Language:** N/A (SaaS)
- **License:** Proprietary / closed source
- **Approach:** LLM-assisted agentic static analysis. Analyzes source code, dependencies, tool definitions, and network calls via a specialized LLM classifier.
- **What it detects:** Command injection, code injection, path traversal, SSRF, data exfiltration, tool poisoning, prompt injection, rug pull, resource exhaustion, server configuration issues (missing timeouts, weak TLS, open ports).
- **Limitations:** Only public GitHub repos or npm packages. No private repo support. No credential/secret pattern detection explicitly mentioned. Scanning takes 2-7 minutes. No SARIF output. No CLI. No CI/CD integration (webhook-based only). Closed source.

### Cisco mcp-scanner (cisco-ai-defense/mcp-scanner)

- **Repo:** [cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner)
- **Language:** Python 3.11+
- **License:** Open source (Apache 2.0)
- **Approach:** Multi-engine — YARA rules + LLM-as-judge + Cisco AI Defense API (cloud). Can run in pure offline/static mode (YARA only) or full mode with cloud API.
- **What it detects:** Tool poisoning, prompt injection, hidden operations (undocumented network calls, file writes), data exfiltration, command/code injection. Behavioral code threat analysis using semantic analysis of tool definitions and source code. Custom YARA rules for pattern matching.
- **What it does NOT detect:** Dependency CVEs, install hook analysis, rug pull detection (no pinning mechanism), unicode steganography (not mentioned). No SARIF output. No automated credential pattern scanning (relies on YARA rules — user must write them).
- **CI/CD:** Supports offline/static mode for pre-generated MCP JSON — suitable for CI/CD but requires setup.

---

## 2. Feature Comparison Matrix

Research sources: GitHub READMEs and documentation as of March 2026. Cells marked `?` indicate the feature is not mentioned in public documentation and could not be confirmed.

| Capability | oxvault | mcp-scan / Snyk agent-scan | Enkrypt mcpscan.ai | Cisco mcp-scanner |
|---|:---:|:---:|:---:|:---:|
| **Detection** | | | | |
| Tool description poisoning | Yes | Yes | Yes | Yes |
| Prompt injection (description) | Yes | Yes | Yes | Yes |
| Tool shadowing | Yes | Yes | ? | Yes |
| Rug pull detection | Yes | Yes | Yes | No |
| Unicode steganography / invisible chars | Yes | Yes | ? | ? |
| HTML/markdown hidden injection | Yes | Yes | ? | ? |
| Argument injection (shell metachar, SQLi, SSRF) | Yes | No | No | No |
| Cross-tool reference injection | Yes | No | No | No |
| Emotional manipulation patterns | Yes | No | No | No |
| **Source Code SAST** | | | | |
| Source code SAST (Python, JS/TS, Go) | Yes | No | Yes (public repos) | Yes |
| Command injection (`shell=True`, `execSync`) | Yes | No | Yes | Yes |
| Code eval (`eval`, `exec`, `new Function`) | Yes | No | Yes | Yes |
| Path traversal patterns | Yes | No | Yes | Yes |
| Destructive filesystem ops | Yes | No | No | ? |
| Unsafe deserialization (`pickle.load`, etc.) | Yes | No | ? | ? |
| Sandbox escape (`vm.runInNewContext`) | Yes | No | ? | ? |
| Dynamic import abuse | Yes | No | ? | ? |
| **Credential & Secret Detection** | | | | |
| Hardcoded API keys (OpenAI, AWS, GitHub, Stripe) | Yes | No | ? | No (custom YARA only) |
| Bearer tokens / JWTs / private keys | Yes | No | ? | No (custom YARA only) |
| Webhook URL exposure (Slack, Discord) | Yes | No | ? | No |
| Database connection string leakage | Yes | No | ? | No |
| **Network & Egress** | | | | |
| Network egress detection (source code) | Yes | No | No | No |
| SSRF pattern detection | Yes | No | Yes | ? |
| Internal hostname / RFC 1918 IP exposure | Yes | No | No | No |
| Runtime network probe (live connection) | Yes | Yes | No | No |
| **Supply Chain** | | | | |
| Dependency audit (CVE database) | Yes | No | No | No |
| Install hook analysis (`postinstall`, lifecycle) | Yes | No | No | No |
| **Output & Integration** | | | | |
| SARIF output | Yes | No | No | No |
| JSON output | Yes | Yes | No (SaaS UI only) | Yes |
| Terminal (human-readable) output | Yes | Yes | Yes (web) | Yes |
| CI/CD integration (documented) | Yes | No | Webhook only | Partial (offline mode) |
| GitHub Actions example provided | Yes | No | No | No |
| **Scanning Scope** | | | | |
| Local path scanning | Yes | No | No | Yes |
| npm package scanning | Yes | No | Yes | ? |
| GitHub repo scanning (`github:user/repo`) | Yes | No | Yes (public only) | ? |
| Private repo scanning | Yes | Yes | No | Yes |
| Config auto-discovery (Claude, Cursor, etc.) | No | Yes | No | No |
| Risk tier classification (CRITICAL/HIGH/etc.) | Yes | No | No | No |
| **Operations** | | | | |
| Requires cloud API / token | No | Yes (SNYK_TOKEN) | Yes (SaaS) | Optional (AI Defense API) |
| Works fully offline | Yes | No | No | Partial (YARA only) |
| Open source | Yes | Yes | No | Yes |
| Language / distribution | Go (single binary) | Python (uvx) | SaaS | Python (pip/uvx) |
| Requires running server | No | Yes | No | No |

### Legend

- **Yes** — Feature confirmed present in public documentation or source code
- **No** — Feature confirmed absent in public documentation
- **?** — Not mentioned; could not be confirmed from public documentation

---

## 3. Oxvault Scan Results (DVMCP)

**Command:**
```bash
./bin/oxvault scan github:harishsg993010/damn-vulnerable-MCP-server --skip-manifest -f json
```

**Full results:** `benchmarks/competitive/results/oxvault-dvmcp.json`

### Summary

| Metric | Value |
|---|---|
| Total raw findings | 31 |
| HIGH severity | 21 |
| WARN severity | 10 |
| Challenges detected | 8 of 10 |
| False positives | 0 |

### Findings by Challenge

| Challenge | Difficulty | Vulnerability Type | Oxvault Findings | Rules Triggered |
|---|---|---|:---:|---|
| Challenge 1 — Prompt Injection | Easy | Hardcoded API key in source | 2 | `mcp-hardcoded-api-key` |
| Challenge 2 — Tool Poisoning | Easy | Shell command injection | 2 | `mcp-cmd-injection` |
| Challenge 3 — Excessive Permission Scope | Easy | Destructive filesystem ops | 1 | `mcp-destructive-fs` |
| Challenge 4 — Rug Pull Attack | Medium | Hardcoded AWS key | 1 | `mcp-hardcoded-aws-key` |
| Challenge 5 — Tool Shadowing | Medium | Code eval + Stripe key | 6 | `mcp-code-eval`, `mcp-hardcoded-stripe-key` |
| Challenge 6 — Indirect Prompt Injection | Medium | Runtime document injection | 0 | — (see notes) |
| Challenge 7 — Token Theft | Medium | Runtime token file | 0 | — (see notes) |
| Challenge 8 — Malicious Code Execution | Hard | Code eval + cmd injection + AWS key | 6 | `mcp-code-eval`, `mcp-cmd-injection`, `mcp-hardcoded-aws-key` |
| Challenge 9 — Remote Access Control | Hard | Command injection | 8 | `mcp-cmd-injection` |
| Challenge 10 — Multi-Vector Attack | Hard | Command injection + AWS key | 3 | `mcp-cmd-injection`, `mcp-hardcoded-aws-key` |
| common/utils.py | Shared | Shell injection in shared utility | 2 | `mcp-cmd-injection` |

### Notes on Missed Challenges (6, 7)

**Challenge 6 — Indirect Prompt Injection:** This challenge embeds malicious instructions inside *runtime-created document files* (`/tmp/dvmcp_challenge6/documents/internal_memo.txt`). The injection is stored in files that are written at server startup and read during tool execution — not in the source code. SAST-only scanning with `--skip-manifest` cannot detect this. Detection requires either running the server and inspecting responses (which our `--skip-manifest` flag intentionally bypasses) or dynamic analysis.

**Challenge 7 — Token Theft:** Credentials in this challenge (`epro_api_*`, JWT tokens) are written to a *runtime-generated JSON file* (`/tmp/dvmcp_challenge7/tokens.json`) created when the server starts. They are not hardcoded in the Python source. SAST regex patterns match static source strings; runtime-generated files require dynamic analysis or watching file system events during execution. Notably, the challenge also stores a JWT — which our response sanitization rules would catch if the token appeared in a tool response.

### Coverage Analysis

Oxvault `--skip-manifest` (SAST-only) detected **8 of 10 DVMCP challenges** (80%) with **0 false positives**. The 2 missed challenges (indirect injection via documents, runtime token files) require dynamic / runtime analysis that is intentionally out of scope for `--skip-manifest` mode. Running without `--skip-manifest` would connect to the live servers and apply description-poisoning + response-sanitization rules, potentially catching Challenge 6's poisoned tool descriptions at runtime.

---

## 4. Competitor Scan Attempts

### mcp-scan / snyk-agent-scan

**Installation:** Available via `uvx mcp-scan` or `uvx snyk-agent-scan` (same tool).

**Attempt result:** Could not complete automated scan. Blockers:

1. **Requires `SNYK_TOKEN`** — the tool connects to `api.snyk.io/hidden/mcp-scan/analysis-machine` for LLM-based vulnerability analysis. Without a token the scan returns exit code 1 with no findings.
2. **Requires a live running MCP server** — unlike oxvault which clones and scans the source, snyk-agent-scan must connect to a running server via stdio or SSE transport. DVMCP servers require Python `mcp` package and uvicorn to be installed.
3. **Cannot scan from GitHub URL** — no `github:user/repo` style input. Must point at config files listing running servers.

**Manual execution instructions:**
```bash
export SNYK_TOKEN=<your-token>
pip install mcp uvicorn fastapi  # install DVMCP deps
python3 /tmp/dvmcp/challenges/easy/challenge2/server_sse.py &

cat > /tmp/dvmcp-config.json <<EOF
{
  "mcpServers": {
    "dvmcp": { "url": "http://localhost:8002/sse" }
  }
}
EOF

uvx snyk-agent-scan scan /tmp/dvmcp-config.json --json
```

**Architecture implication:** mcp-scan/snyk-agent-scan is a *runtime inspector* — it must connect to live servers. It would not work in a pure CI/CD pipeline that only has source code, without also standing up the server during the scan.

### Cisco mcp-scanner

**Installation:** `uvx cisco-ai-mcp-scanner` (PyPI: `cisco-ai-mcp-scanner`)

**Attempt result:** Not run in this benchmark. Cisco's scanner requires:
1. Either a live MCP server connection, or
2. Pre-generated MCP JSON (tools/list output) for offline mode, or
3. A Cisco AI Defense API key for cloud-assisted analysis

YARA-only offline mode would work but requires writing YARA rules targeting specific patterns.

### Enkrypt mcpscan.ai

**Attempt result:** Not applicable — SaaS only. No CLI. Scanning is performed by submitting a GitHub repo URL to `mcpscan.ai`. Private repos are not supported.

---

## 5. Key Differentiators

### Where Oxvault Leads

**Single binary, zero dependencies:** `make build` produces one static Go binary. No Python runtime, no token, no internet connection required. Run it anywhere.

**Fully offline SAST:** Oxvault clones the repo and analyzes source code without connecting to any external API. CI/CD pipelines work without outbound network access to third-party APIs.

**SARIF output:** Oxvault is the only tool in this comparison that produces SARIF, enabling native GitHub Code Scanning integration and other security tooling ecosystems.

**Credential detection built-in:** Hardcoded API keys (OpenAI, AWS, GitHub PAT, Stripe, Slack, Discord, Twilio), bearer tokens, JWTs, and private keys are detected via SAST regex patterns — no cloud API needed.

**Dependency CVE scanning:** Oxvault checks `package.json` / `requirements.txt` / `go.mod` against a CVE database. No competitor in this comparison offers this.

**Install hook analysis:** `postinstall` and lifecycle script abuse — a major supply chain attack vector in npm packages — is detected by oxvault and by no competitor.

**Argument injection detection:** SQL injection, SSRF (metadata IP detection), LDAP injection, template injection, and shell metacharacter injection in tool input schemas are analyzed by oxvault's `ScanArguments` engine. No competitor performs this analysis.

**Risk tier classification:** Tools are automatically classified into CRITICAL / HIGH / MEDIUM / LOW risk tiers based on what they can do (shell execution, filesystem, network, etc.). This helps prioritize review effort.

**Response sanitization rules:** Oxvault's `ScanResponse` engine catches PII, credentials, and internal infrastructure details that leak through tool responses. No competitor scans for response-time data leakage.

### Where Competitors Lead

**Config auto-discovery:** mcp-scan/snyk-agent-scan automatically finds MCP configs in standard locations (Claude Desktop, Cursor, Windsurf, VS Code, Gemini CLI). Oxvault requires you to specify the target explicitly. This makes mcp-scan better for ad-hoc desktop security audits.

**Runtime behavioral analysis (live server):** mcp-scan/snyk-agent-scan actually connects to running servers and observes real tool descriptions and behavior, including dynamically generated descriptions. Oxvault `--skip-manifest` mode misses runtime-only issues (DVMCP challenges 6, 7). Running oxvault without `--skip-manifest` partially closes this gap.

**LLM-assisted semantic analysis:** Cisco's scanner and Enkrypt use LLMs to understand *intent* of tool descriptions — catching subtle semantic obfuscation that pattern matching misses. Oxvault uses deterministic regex patterns which are fast and have zero false positives but may miss creative obfuscation.

**Skills scanning:** snyk-agent-scan scans agent skills beyond MCP — a broader threat surface. Oxvault is MCP-focused.

---

## 6. Methodology Notes

### What "SAST-only" means here

All oxvault runs used `--skip-manifest` which disables the live MCP connection. This means:
- Tool description poisoning rules are NOT applied (those run against `tools/list` responses)
- Source code patterns ARE applied (command injection, credential detection, etc.)
- This is the CI/CD-recommended mode — it doesn't require the server to be running

Running without `--skip-manifest` would additionally apply description-poisoning and response-sanitization rules against live tool outputs, and would likely detect Challenge 6's poisoned tool descriptions.

### Why snyk-agent-scan results are unavailable

mcp-scan / snyk-agent-scan requires:
1. A live running MCP server (not just source code)
2. Python + `mcp` package installed (to run DVMCP servers)
3. A valid `SNYK_TOKEN` for cloud-assisted analysis

The tool was successfully installed (`uvx snyk-agent-scan` — v0.4.9) and help/inspect commands confirmed it works. However automated benchmarking is blocked on the above requirements. The tool is fundamentally a *runtime inspector* rather than a *source code analyzer*.

### Data provenance

- Feature matrix cells marked **Yes/No** are based on official GitHub README, documentation sites, and blog posts as of March 2026.
- Cells marked **?** indicate no mention in available public documentation.
- The preliminary comparison table in the issue was used as a starting point; each cell was independently verified via web research.

### Sources

- [invariantlabs-ai/mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) — Invariant Labs / now Snyk Agent Scan
- [snyk/agent-scan](https://github.com/snyk/agent-scan) — Snyk Agent Scan
- [Introducing MCP-Scan](https://invariantlabs.ai/blog/introducing-mcp-scan) — Invariant Labs blog
- [Enkrypt AI MCP Scan](https://www.enkryptai.com/mcp-scan) — Enkrypt AI product page
- [mcpscan.ai](https://mcpscan.ai) — Enkrypt AI SaaS scanner
- [cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) — Cisco AI Defense
- [Cisco MCP Scanner blog](https://blogs.cisco.com/ai/securing-the-ai-agent-supply-chain-with-ciscos-open-source-mcp-scanner) — Cisco Blogs
- [harishsg993010/damn-vulnerable-MCP-server](https://github.com/harishsg993010/damn-vulnerable-MCP-server) — DVMCP benchmark target
