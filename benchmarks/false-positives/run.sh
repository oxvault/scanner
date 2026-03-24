#!/bin/bash
# False Positive Benchmark — scans official + popular MCP servers
# Usage: ./benchmarks/false-positives/run.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
BINARY="./bin/oxvault"

echo "Building oxvault..."
go build -o "$BINARY" ./cmd/

rm -rf "$RESULTS_DIR"
mkdir -p "$RESULTS_DIR"

TOTAL_FINDINGS=0
TOTAL_SERVERS=0

# ── Part 1: Official MCP servers (monorepo) ──────────────────

MONO_DIR=$(mktemp -d)
echo ""
echo "Cloning modelcontextprotocol/servers..."
git clone --depth 1 https://github.com/modelcontextprotocol/servers.git "$MONO_DIR" 2>/dev/null

MONO_SERVERS=("filesystem" "fetch" "git" "memory" "everything" "sequentialthinking" "time")

for name in "${MONO_SERVERS[@]}"; do
  SCAN_PATH="$MONO_DIR/src/$name"
  if [ ! -d "$SCAN_PATH" ]; then
    echo "  SKIP $name — not found"
    continue
  fi

  echo "Scanning: official/$name..."
  RESULT_FILE="$RESULTS_DIR/official-${name}.json"
  "$BINARY" scan "$SCAN_PATH" --skip-manifest --no-color -f json > "$RESULT_FILE" 2>/dev/null || true

  COUNT=$(python3 -c "import json; d=json.load(open('$RESULT_FILE')); print(len(d) if isinstance(d,list) else 0)" 2>/dev/null || echo "0")
  echo "  → $COUNT findings"
  TOTAL_FINDINGS=$((TOTAL_FINDINGS + COUNT))
  TOTAL_SERVERS=$((TOTAL_SERVERS + 1))
done

rm -rf "$MONO_DIR"

# ── Part 2: Popular third-party MCP servers ──────────────────

THIRD_PARTY=(
  "anthropics/anthropic-quickstarts:computer-use-demo|anthropic-computer-use"
  "firebase/genkit:js/plugins/mcp|firebase-genkit-mcp"
  "tumf/mcp-text-editor:.|mcp-text-editor"
  "punkpeye/mcp-server-fetch:.|punkpeye-fetch"
)

for entry in "${THIRD_PARTY[@]}"; do
  IFS='|' read -r repo_path name <<< "$entry"
  IFS=':' read -r repo subdir <<< "$repo_path"

  CLONE_DIR=$(mktemp -d)
  echo "Scanning: third-party/$name..."
  git clone --depth 1 "https://github.com/$repo.git" "$CLONE_DIR" 2>/dev/null || { echo "  SKIP $name — clone failed"; continue; }

  SCAN_PATH="$CLONE_DIR/$subdir"
  if [ ! -d "$SCAN_PATH" ]; then
    SCAN_PATH="$CLONE_DIR"
  fi

  RESULT_FILE="$RESULTS_DIR/thirdparty-${name}.json"
  "$BINARY" scan "$SCAN_PATH" --skip-manifest --no-color -f json > "$RESULT_FILE" 2>/dev/null || true

  COUNT=$(python3 -c "import json; d=json.load(open('$RESULT_FILE')); print(len(d) if isinstance(d,list) else 0)" 2>/dev/null || echo "0")
  echo "  → $COUNT findings"
  TOTAL_FINDINGS=$((TOTAL_FINDINGS + COUNT))
  TOTAL_SERVERS=$((TOTAL_SERVERS + 1))

  rm -rf "$CLONE_DIR"
done

# ── Summary ──────────────────────────────────────────────────

echo ""
echo "=========================================="
echo "Servers scanned: $TOTAL_SERVERS"
echo "Total findings:  $TOTAL_FINDINGS"
echo "Results:         $RESULTS_DIR/"
echo "=========================================="
