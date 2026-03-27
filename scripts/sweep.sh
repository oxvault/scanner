#!/usr/bin/env bash
# sweep.sh — Runs the oxvault scanner against all targets in validation-targets.json
# and produces per-server JSON results plus a consolidated summary.
#
# Usage:
#   ./sweep.sh [--dry-run N] [--skip-build]
#
# Flags:
#   --dry-run N    Only scan the first N servers (for testing)
#   --skip-build   Skip the `make build` step

set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCANNER_DIR="/root/Code/oxvault/scanner"
SCANNER_BIN="${SCANNER_DIR}/bin/oxvault"
TARGETS_FILE="/root/Code/oxvault/validation-targets.json"
RESULTS_DIR="/root/Code/oxvault/sweep-results"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
DRY_RUN=0
SKIP_BUILD=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      if [[ -z "${2:-}" || ! "${2}" =~ ^[0-9]+$ ]]; then
        echo "ERROR: --dry-run requires a positive integer argument" >&2
        exit 1
      fi
      DRY_RUN="$2"
      shift 2
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    *)
      echo "ERROR: Unknown argument: $1" >&2
      echo "Usage: $0 [--dry-run N] [--skip-build]" >&2
      exit 1
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# sanitize_name replaces characters that are unsafe in filenames.
# @ and / and spaces are replaced with -; leading/trailing dashes removed.
sanitize_name() {
  local name="$1"
  # Replace @, /, spaces, and parentheses with hyphens
  name="${name//[@\/ ()()]/-}"
  # Collapse consecutive hyphens
  name="$(echo "$name" | sed 's/-\{2,\}/-/g')"
  # Strip leading/trailing hyphens
  name="${name#-}"
  name="${name%-}"
  echo "$name"
}

# extract_github_target converts a GitHub HTTPS URL to the github:owner/repo format.
# Input:  https://github.com/owner/repo
# Output: github:owner/repo
extract_github_target() {
  local url="$1"
  # Strip protocol and domain, leaving /owner/repo
  local path
  path="$(echo "$url" | sed 's|https://github.com/||')"
  # Keep only the first two path segments (owner/repo), drop deeper paths
  path="$(echo "$path" | cut -d'/' -f1-2)"
  echo "github:${path}"
}

# ---------------------------------------------------------------------------
# Step 1: Build the scanner binary
# ---------------------------------------------------------------------------
if [[ "$SKIP_BUILD" -eq 0 ]]; then
  echo "==> Building scanner..."
  if ! make -C "${SCANNER_DIR}" build; then
    echo "ERROR: make build failed" >&2
    exit 1
  fi
  echo "==> Build complete: ${SCANNER_BIN}"
else
  echo "==> Skipping build (--skip-build)"
  if [[ ! -x "${SCANNER_BIN}" ]]; then
    echo "ERROR: Scanner binary not found or not executable: ${SCANNER_BIN}" >&2
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# Step 2: Validate inputs
# ---------------------------------------------------------------------------
if [[ ! -f "${TARGETS_FILE}" ]]; then
  echo "ERROR: Targets file not found: ${TARGETS_FILE}" >&2
  exit 1
fi

if ! command -v jq &>/dev/null; then
  echo "ERROR: jq is required but not installed" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 3: Prepare output directory
# ---------------------------------------------------------------------------
mkdir -p "${RESULTS_DIR}"

# ---------------------------------------------------------------------------
# Step 4: Load targets
# ---------------------------------------------------------------------------
TOTAL="$(jq '.targets | length' "${TARGETS_FILE}")"

if [[ "$DRY_RUN" -gt 0 && "$DRY_RUN" -lt "$TOTAL" ]]; then
  LIMIT="$DRY_RUN"
  echo "==> Dry-run mode: scanning first ${LIMIT} of ${TOTAL} targets"
else
  LIMIT="$TOTAL"
fi

# ---------------------------------------------------------------------------
# Step 5: Scan loop
# ---------------------------------------------------------------------------
SUCCESS=0
FAIL=0
TIMEOUT_COUNT=0
FINDINGS_TOTAL=0

# Severity integer constants (matches providers/types.go iota order):
#   0 = INFO, 1 = WARNING, 2 = HIGH, 3 = CRITICAL
COUNT_CRITICAL=0
COUNT_HIGH=0
COUNT_WARNING=0
COUNT_INFO=0

declare -A CWE_COUNTS   # associative array: CWE_COUNTS["CWE-78"]=5
SERVERS_WITH_FINDINGS=0
SERVERS_CLEAN=0

# Failures accumulate as a JSON array string we build incrementally.
FAILURES_JSON="[]"

echo ""
echo "==> Starting sweep of ${LIMIT} targets → results in ${RESULTS_DIR}"
echo ""

for i in $(seq 0 $((LIMIT - 1))); do
  IDX=$((i + 1))

  # Extract fields from JSON
  NAME="$(jq -r ".targets[$i].name" "${TARGETS_FILE}")"
  PACKAGE="$(jq -r ".targets[$i].package // empty" "${TARGETS_FILE}")"
  REPO="$(jq -r ".targets[$i].repo" "${TARGETS_FILE}")"
  INSTALL="$(jq -r ".targets[$i].install" "${TARGETS_FILE}")"

  # Determine scan target string
  SCAN_TARGET=""
  if [[ "$INSTALL" == "npm" && -n "$PACKAGE" ]]; then
    SCAN_TARGET="$PACKAGE"
  else
    # pip, binary, docker, source — all use github:owner/repo
    SCAN_TARGET="$(extract_github_target "$REPO")"
  fi

  # Output filename
  SAFE_NAME="$(sanitize_name "$NAME")"
  OUT_FILE="${RESULTS_DIR}/${SAFE_NAME}.json"

  printf "[%d/%d] Scanning %-50s " "$IDX" "$LIMIT" "${NAME}..."

  # Run scanner with a 120s timeout; suppress stderr so noisy resolver logs
  # don't pollute sweep output.
  SCAN_OUTPUT=""
  SCAN_EXIT=0
  TIMED_OUT=0

  set +e
  SCAN_OUTPUT="$(timeout 120 "${SCANNER_BIN}" scan "${SCAN_TARGET}" \
    --format json \
    --no-color \
    --skip-manifest \
    2>/dev/null)"
  SCAN_EXIT=$?
  set -e

  # timeout exits 124 when the subprocess is killed
  if [[ "$SCAN_EXIT" -eq 124 ]]; then
    TIMED_OUT=1
  fi

  if [[ "$TIMED_OUT" -eq 1 ]]; then
    echo "TIMEOUT"
    FAIL=$((FAIL + 1))
    TIMEOUT_COUNT=$((TIMEOUT_COUNT + 1))
    # Write a sentinel file so we have a record
    echo '[]' > "${OUT_FILE}"
    FAILURES_JSON="$(echo "$FAILURES_JSON" | jq \
      --arg n "$NAME" \
      --arg t "$SCAN_TARGET" \
      '. + [{"name": $n, "target": $t, "error": "timeout (120s)"}]')"
    continue
  fi

  # Non-zero exit other than timeout means error or findings above threshold.
  # The scanner exits non-zero when findings exist at the --fail-on level.
  # We treat scanner errors (no output at all) separately from findings output.

  # Normalise empty output to an empty JSON array so jq never chokes.
  if [[ -z "$SCAN_OUTPUT" ]]; then
    SCAN_OUTPUT="[]"
  fi

  # Validate that output is parseable JSON
  if ! echo "$SCAN_OUTPUT" | jq empty 2>/dev/null; then
    echo "FAIL (invalid JSON output)"
    FAIL=$((FAIL + 1))
    echo '[]' > "${OUT_FILE}"
    FAILURES_JSON="$(echo "$FAILURES_JSON" | jq \
      --arg n "$NAME" \
      --arg t "$SCAN_TARGET" \
      '. + [{"name": $n, "target": $t, "error": "invalid JSON output from scanner"}]')"
    continue
  fi

  # Normalize null → [] for consistent jq processing
  SCAN_OUTPUT="$(echo "$SCAN_OUTPUT" | jq 'if . == null then [] else . end')"

  # Save output
  echo "$SCAN_OUTPUT" > "${OUT_FILE}"

  # Count findings in this result
  SERVER_FINDINGS="$(echo "$SCAN_OUTPUT" | jq 'length')"

  # Accumulate severity counts
  # Severity integers: 0=INFO 1=WARNING 2=HIGH 3=CRITICAL
  S_CRITICAL="$(echo "$SCAN_OUTPUT" | jq '[.[] | select(.severity == 3)] | length')"
  S_HIGH="$(echo "$SCAN_OUTPUT" | jq '[.[] | select(.severity == 2)] | length')"
  S_WARNING="$(echo "$SCAN_OUTPUT" | jq '[.[] | select(.severity == 1)] | length')"
  S_INFO="$(echo "$SCAN_OUTPUT" | jq '[.[] | select(.severity == 0)] | length')"

  FINDINGS_TOTAL=$((FINDINGS_TOTAL + SERVER_FINDINGS))
  COUNT_CRITICAL=$((COUNT_CRITICAL + S_CRITICAL))
  COUNT_HIGH=$((COUNT_HIGH + S_HIGH))
  COUNT_WARNING=$((COUNT_WARNING + S_WARNING))
  COUNT_INFO=$((COUNT_INFO + S_INFO))

  if [[ "$SERVER_FINDINGS" -gt 0 ]]; then
    SERVERS_WITH_FINDINGS=$((SERVERS_WITH_FINDINGS + 1))
  else
    SERVERS_CLEAN=$((SERVERS_CLEAN + 1))
  fi

  # Accumulate CWE counts
  # For each unique CWE in this result, add to our associative array
  while IFS= read -r cwe; do
    [[ -z "$cwe" || "$cwe" == "null" ]] && continue
    CWE_COUNTS["$cwe"]=$(( ${CWE_COUNTS["$cwe"]:-0} + 1 ))
  done < <(echo "$SCAN_OUTPUT" | jq -r '.[] | select(.cwe != null and .cwe != "") | .cwe')

  # Determine status label for terminal output
  if [[ "$SCAN_EXIT" -eq 0 ]]; then
    if [[ "$SERVER_FINDINGS" -gt 0 ]]; then
      printf "OK (%d findings)\n" "$SERVER_FINDINGS"
    else
      echo "OK (clean)"
    fi
  else
    # Non-zero but valid JSON — scanner found issues above fail-on threshold
    printf "FINDINGS (%d findings)\n" "$SERVER_FINDINGS"
  fi

  SUCCESS=$((SUCCESS + 1))
done

# ---------------------------------------------------------------------------
# Step 6: Build CWE JSON object
# ---------------------------------------------------------------------------
CWE_JSON="{}"
for cwe in "${!CWE_COUNTS[@]}"; do
  count="${CWE_COUNTS[$cwe]}"
  CWE_JSON="$(echo "$CWE_JSON" | jq --arg k "$cwe" --argjson v "$count" '. + {($k): $v}')"
done

# ---------------------------------------------------------------------------
# Step 7: Write summary.json
# ---------------------------------------------------------------------------
SUMMARY_FILE="${RESULTS_DIR}/summary.json"

SCANNED=$((SUCCESS))
FAILED=$FAIL

jq -n \
  --argjson total       "$TOTAL" \
  --argjson limit       "$LIMIT" \
  --argjson scanned     "$SCANNED" \
  --argjson failed      "$FAILED" \
  --argjson timeouts    "$TIMEOUT_COUNT" \
  --argjson findings    "$FINDINGS_TOTAL" \
  --argjson critical    "$COUNT_CRITICAL" \
  --argjson high        "$COUNT_HIGH" \
  --argjson warning     "$COUNT_WARNING" \
  --argjson info        "$COUNT_INFO" \
  --argjson with_findings "$SERVERS_WITH_FINDINGS" \
  --argjson clean       "$SERVERS_CLEAN" \
  --argjson cwe         "$CWE_JSON" \
  --argjson failures    "$FAILURES_JSON" \
  '{
    total:               $total,
    limit:               $limit,
    scanned:             $scanned,
    failed:              $failed,
    timeouts:            $timeouts,
    findings_total:      $findings,
    by_severity: {
      critical: $critical,
      high:     $high,
      warning:  $warning,
      info:     $info
    },
    by_cwe:              $cwe,
    servers_with_findings: $with_findings,
    servers_clean:       $clean,
    failures:            $failures
  }' > "${SUMMARY_FILE}"

# ---------------------------------------------------------------------------
# Step 8: Print summary table
# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
echo " Oxvault Validation Sweep — Results"
echo "============================================================"
printf "  %-24s %s\n" "Total targets:"        "$TOTAL"
printf "  %-24s %s\n" "Scanned (this run):"   "$LIMIT"
printf "  %-24s %s\n" "Succeeded:"            "$SUCCESS"
printf "  %-24s %s\n" "Failed / timed out:"   "$FAILED  (timeouts: $TIMEOUT_COUNT)"
echo ""
echo "  Findings breakdown"
printf "  %-24s %s\n" "Total findings:"       "$FINDINGS_TOTAL"
printf "  %-24s %s\n" "  CRITICAL:"           "$COUNT_CRITICAL"
printf "  %-24s %s\n" "  HIGH:"               "$COUNT_HIGH"
printf "  %-24s %s\n" "  WARNING:"            "$COUNT_WARNING"
printf "  %-24s %s\n" "  INFO:"               "$COUNT_INFO"
echo ""
printf "  %-24s %s\n" "Servers with findings:" "$SERVERS_WITH_FINDINGS"
printf "  %-24s %s\n" "Servers clean:"        "$SERVERS_CLEAN"
echo ""

if [[ "${#CWE_COUNTS[@]}" -gt 0 ]]; then
  echo "  Top CWEs:"
  # Sort by count descending, print top 10
  for cwe in "${!CWE_COUNTS[@]}"; do
    echo "    ${CWE_COUNTS[$cwe]} ${cwe}"
  done | sort -rn | head -10
  echo ""
fi

if [[ "$FAILED" -gt 0 ]]; then
  echo "  Failed targets:"
  echo "$FAILURES_JSON" | jq -r '.[] | "    \(.name): \(.error)"'
  echo ""
fi

echo "  Summary written to: ${SUMMARY_FILE}"
echo "  Per-server results:  ${RESULTS_DIR}/"
echo "============================================================"
echo ""
