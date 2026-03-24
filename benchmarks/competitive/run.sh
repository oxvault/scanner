#!/usr/bin/env bash
# Competitive benchmark: oxvault vs mcp-scan (Snyk agent-scan) vs DVMCP
#
# Target: harishsg993010/damn-vulnerable-MCP-server (10-challenge vulnerable server)
# Results written to: benchmarks/competitive/results/
#
# Usage:
#   cd <repo-root>
#   bash benchmarks/competitive/run.sh
#
# Requirements:
#   - Go binary at ./bin/oxvault (run `make build` first)
#   - Optional: uvx in PATH for snyk-agent-scan (mcp-scan)
#   - git, jq

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"
DVMCP_REPO="https://github.com/harishsg993010/damn-vulnerable-MCP-server"
DVMCP_LOCAL="/tmp/dvmcp-benchmark"

mkdir -p "${RESULTS_DIR}"

echo "================================================================"
echo " Oxvault Competitive Benchmark"
echo " Target: damn-vulnerable-MCP-server (10 challenges)"
echo " Results: ${RESULTS_DIR}"
echo "================================================================"
echo ""

# ---------------------------------------------------------------------------
# 1. Clone / update DVMCP
# ---------------------------------------------------------------------------
echo "[1/4] Cloning damn-vulnerable-MCP-server..."
if [[ -d "${DVMCP_LOCAL}/.git" ]]; then
    echo "  Already cloned. Pulling latest..."
    git -C "${DVMCP_LOCAL}" pull --quiet
else
    git clone --quiet "${DVMCP_REPO}" "${DVMCP_LOCAL}"
fi
echo "  Done: ${DVMCP_LOCAL}"
echo ""

# ---------------------------------------------------------------------------
# 2. Run oxvault
# ---------------------------------------------------------------------------
echo "[2/4] Running oxvault scan..."
OXVAULT_BIN="${REPO_ROOT}/bin/oxvault"
if [[ ! -x "${OXVAULT_BIN}" ]]; then
    echo "  ERROR: Binary not found at ${OXVAULT_BIN}. Run 'make build' first."
    exit 1
fi

OXVAULT_OUT="${RESULTS_DIR}/oxvault-dvmcp.json"
"${OXVAULT_BIN}" scan github:harishsg993010/damn-vulnerable-MCP-server \
    --skip-manifest \
    -f json \
    2>/dev/null > "${OXVAULT_OUT}" || true

OXVAULT_COUNT=0
if [[ -s "${OXVAULT_OUT}" ]]; then
    OXVAULT_COUNT=$(python3 -c "import json; d=json.load(open('${OXVAULT_OUT}')); print(len(d))" 2>/dev/null || echo 0)
fi
echo "  Findings: ${OXVAULT_COUNT}"
echo "  Output:   ${OXVAULT_OUT}"
echo ""

# ---------------------------------------------------------------------------
# 3. Attempt mcp-scan / snyk-agent-scan
# ---------------------------------------------------------------------------
echo "[3/4] Attempting snyk-agent-scan (formerly mcp-scan)..."
SNYK_OUT="${RESULTS_DIR}/snyk-agent-scan-dvmcp.txt"
SNYK_COUNT="N/A"

if command -v uvx &>/dev/null; then
    echo "  uvx found. Checking snyk-agent-scan..."

    # snyk-agent-scan works by connecting to running MCP servers via stdio or SSE.
    # DVMCP servers use SSE/HTTP transport (uvicorn) and require the 'mcp' Python
    # package. They also need a live Snyk cloud API token (SNYK_TOKEN) to perform
    # vulnerability analysis — the tool offloads analysis to api.snyk.io.
    #
    # Limitations in this environment:
    #   - No SNYK_TOKEN available
    #   - DVMCP servers require Python 'mcp' package (pip install mcp)
    #   - Servers use SSE transport; snyk-agent-scan prefers stdio
    #
    # To run manually:
    #   export SNYK_TOKEN=<your-token>
    #   pip install mcp  # install DVMCP dependencies
    #   python3 /tmp/dvmcp/challenges/easy/challenge2/server_sse.py &
    #   # Create config:
    #   cat > /tmp/dvmcp-config.json << EOF
    #   { "mcpServers": { "dvmcp": { "url": "http://localhost:8002/sse" } } }
    #   EOF
    #   uvx snyk-agent-scan scan /tmp/dvmcp-config.json --json > snyk-results.json

    echo "  NOTE: snyk-agent-scan requires SNYK_TOKEN + running MCP server." \
        > "${SNYK_OUT}"
    echo "  See comments in this script for manual execution instructions." \
        >> "${SNYK_OUT}"
    echo "  Skipping automated run — see ${SNYK_OUT} for instructions."
else
    echo "  uvx not found. Install via: curl -LsSf https://astral.sh/uv/install.sh | sh"
    echo "uvx not found" > "${SNYK_OUT}"
fi
echo ""

# ---------------------------------------------------------------------------
# 4. Summary
# ---------------------------------------------------------------------------
echo "[4/4] Summary"
echo "----------------------------------------------------------------"
printf "  %-30s %s\n" "Tool" "Findings (DVMCP)"
echo "  ------------------------------  ----------------"
printf "  %-30s %s\n" "oxvault (SAST, --skip-manifest)" "${OXVAULT_COUNT}"
printf "  %-30s %s\n" "snyk-agent-scan" "${SNYK_COUNT} (requires token)"
printf "  %-30s %s\n" "mcp-scan (legacy name)" "same as snyk-agent-scan"
printf "  %-30s %s\n" "Cisco mcp-scanner" "N/A (requires AI Defense API)"
printf "  %-30s %s\n" "Enkrypt mcpscan.ai" "N/A (SaaS, public repos only)"
echo "----------------------------------------------------------------"
echo ""
echo "  Full oxvault findings: ${OXVAULT_OUT}"
echo "  Feature comparison:    ${SCRIPT_DIR}/RESULTS.md"
echo ""
echo "Benchmark complete."
