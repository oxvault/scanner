#!/usr/bin/env bash
# sweep-v040.sh — Full sweep against v0.4.0 baseline.
#
# Scans all MCP targets in validation-targets.json + a curated list of
# HuggingFace models (clean + malicious test vectors). Writes per-target
# JSON + consolidated summary.
#
# Usage:
#   ./scripts/sweep-v040.sh [--dry-run N] [--skip-build] [--skip-hf]

set -euo pipefail

SCANNER_DIR="/root/Code/oxvault/scanner"
SCANNER_BIN="${SCANNER_DIR}/bin/oxvault"
TARGETS_FILE="/root/Code/oxvault/validation-targets.json"
RESULTS_DIR="/root/Code/oxvault/sweep-results/v040"
MCP_DIR="${RESULTS_DIR}/mcp"
HF_DIR="${RESULTS_DIR}/hf"

DRY_RUN=0
SKIP_BUILD=0
SKIP_HF=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN="$2"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --skip-hf) SKIP_HF=1; shift ;;
    *) echo "unknown flag: $1" >&2; exit 1 ;;
  esac
done

# Curated HF model list — small + diverse
HF_TARGETS=(
  # Known-malicious test vectors
  "hf:mcpotato/42-eicar-street"
  # Clean small models (regression check — should be 0 critical)
  "hf:hf-internal-testing/tiny-random-bert"
  "hf:hf-internal-testing/tiny-random-gpt2"
  "hf:hf-internal-testing/tiny-random-t5"
  "hf:hf-internal-testing/tiny-random-roberta"
  "hf:hf-internal-testing/tiny-random-distilbert"
  # Real-world small public models
  "hf:google/electra-small-discriminator"
  "hf:distilbert-base-uncased"
  "hf:sentence-transformers/all-MiniLM-L6-v2"
)

# ── build ─────────────────────────────────────────────────────────────────
if [[ "${SKIP_BUILD}" -eq 0 ]]; then
  echo "==> Building scanner..."
  cd "${SCANNER_DIR}" && make build
fi

[[ -x "${SCANNER_BIN}" ]] || { echo "scanner binary not found: ${SCANNER_BIN}" >&2; exit 1; }

mkdir -p "${MCP_DIR}" "${HF_DIR}"

# ── MCP sweep ─────────────────────────────────────────────────────────────
echo ""
echo "==> MCP sweep (validation-targets.json)"

MCP_TARGETS=$(jq -r '.targets[] | (.package // .repo // .name)' "${TARGETS_FILE}")
TOTAL_MCP=$(echo "${MCP_TARGETS}" | wc -l)
LIMIT="${TOTAL_MCP}"
if [[ "${DRY_RUN}" -gt 0 ]]; then
  LIMIT="${DRY_RUN}"
  MCP_TARGETS=$(echo "${MCP_TARGETS}" | head -"${DRY_RUN}")
fi

i=0
while IFS= read -r target; do
  [[ -z "${target}" ]] && continue
  i=$((i + 1))
  SAFE_NAME=$(echo "${target}" | tr '/@:' '___')
  OUT_FILE="${MCP_DIR}/${SAFE_NAME}.json"
  echo "  [${i}/${LIMIT}] ${target}"
  timeout 120 "${SCANNER_BIN}" scan "${target}" --format=json --skip-manifest > "${OUT_FILE}" 2>/dev/null || echo "    (timeout or error)"
done <<< "${MCP_TARGETS}"

# ── HF sweep ──────────────────────────────────────────────────────────────
if [[ "${SKIP_HF}" -eq 0 ]]; then
  echo ""
  echo "==> HF sweep (curated list)"
  i=0
  TOTAL_HF=${#HF_TARGETS[@]}
  for target in "${HF_TARGETS[@]}"; do
    i=$((i + 1))
    SAFE_NAME=$(echo "${target}" | tr '/@:' '___')
    OUT_FILE="${HF_DIR}/${SAFE_NAME}.json"
    echo "  [${i}/${TOTAL_HF}] ${target}"
    timeout 300 "${SCANNER_BIN}" scan "${target}" --format=json > "${OUT_FILE}" 2>/dev/null || echo "    (timeout or error)"
  done
fi

# ── Summary ───────────────────────────────────────────────────────────────
echo ""
echo "==> Generating summary"

SUMMARY="${RESULTS_DIR}/summary.json"
cat > "${SUMMARY}" <<EOF
{
  "version": "v0.4.0",
  "swept_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "mcp": {
    "total_scanned": $(ls "${MCP_DIR}"/*.json 2>/dev/null | wc -l),
    "with_findings": $(grep -l "\"severity\":" "${MCP_DIR}"/*.json 2>/dev/null | wc -l),
    "with_critical": $(grep -l "\"severity\":\"critical\"" "${MCP_DIR}"/*.json 2>/dev/null | wc -l)
  },
  "hf": {
    "total_scanned": $(ls "${HF_DIR}"/*.json 2>/dev/null | wc -l),
    "with_findings": $(grep -l "\"severity\":" "${HF_DIR}"/*.json 2>/dev/null | wc -l),
    "with_critical": $(grep -l "\"severity\":\"critical\"" "${HF_DIR}"/*.json 2>/dev/null | wc -l)
  }
}
EOF

cat "${SUMMARY}"
echo ""
echo "==> Done. Results: ${RESULTS_DIR}/"
