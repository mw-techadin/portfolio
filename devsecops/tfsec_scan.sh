#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# tfsec_scan.sh
# Wrapper around tfsec for scanning Terraform configurations.
# Outputs a human-readable report and exits non-zero on HIGH/CRITICAL findings.
#
# Prerequisites:
#   tfsec must be installed: https://github.com/aquasecurity/tfsec
#   or: brew install tfsec / go install github.com/aquasecurity/tfsec/cmd/tfsec@latest
#
# Usage:
#   ./tfsec_scan.sh                             # scan ./
#   ./tfsec_scan.sh --dir infrastructure/
#   ./tfsec_scan.sh --dir infra/ --severity HIGH --format json
#   ./tfsec_scan.sh --dir infra/ --output report.json
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
TF_DIR="."
MIN_SEVERITY="HIGH"        # LOW | MEDIUM | HIGH | CRITICAL
FORMAT="default"           # default | json | sarif | csv
OUTPUT_FILE=""
FAIL_ON_VIOLATIONS=true

# ── Parse args ─────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)        TF_DIR="$2";         shift 2 ;;
    --severity)   MIN_SEVERITY="$2";   shift 2 ;;
    --format)     FORMAT="$2";         shift 2 ;;
    --output)     OUTPUT_FILE="$2";    shift 2 ;;
    --no-fail)    FAIL_ON_VIOLATIONS=false; shift ;;
    *) echo "[WARN] Unknown argument: $1"; shift ;;
  esac
done

# ── Validate prerequisites ─────────────────────────────────────────────────────
if ! command -v tfsec &>/dev/null; then
  echo "[ERROR] tfsec not found. Install it first:"
  echo "  brew install tfsec"
  echo "  OR: go install github.com/aquasecurity/tfsec/cmd/tfsec@latest"
  exit 1
fi

if [[ ! -d "$TF_DIR" ]]; then
  echo "[ERROR] Directory not found: $TF_DIR"
  exit 1
fi

TFSEC_VERSION="$(tfsec --version 2>/dev/null | head -1 || echo 'unknown')"

echo "════════════════════════════════════════════════════════════"
echo "  tfsec Terraform Security Scanner"
echo "  Version    : $TFSEC_VERSION"
echo "  Target     : $TF_DIR"
echo "  Min severity: $MIN_SEVERITY"
echo "  Format     : $FORMAT"
echo "════════════════════════════════════════════════════════════"
echo ""

# ── Build tfsec command ────────────────────────────────────────────────────────
CMD=(
  tfsec
  "$TF_DIR"
  "--minimum-severity" "$MIN_SEVERITY"
  "--format"           "$FORMAT"
  "--no-color"
)

if [[ -n "$OUTPUT_FILE" ]]; then
  CMD+=("--out" "$OUTPUT_FILE")
fi

# Include any .tfsec config file if present
if [[ -f ".tfsec/config.yml" ]]; then
  CMD+=("--config-file" ".tfsec/config.yml")
fi

# ── Run the scan ───────────────────────────────────────────────────────────────
set +e
"${CMD[@]}"
EXIT_CODE=$?
set -e

echo ""
echo "════════════════════════════════════════════════════════════"

if [[ "$EXIT_CODE" -eq 0 ]]; then
  echo "  [OK] No $MIN_SEVERITY or higher findings detected."
else
  echo "  [!] Findings detected at $MIN_SEVERITY severity or above."
  if [[ -n "$OUTPUT_FILE" ]]; then
    echo "  Report written to: $OUTPUT_FILE"
  fi
fi

echo "════════════════════════════════════════════════════════════"

if [[ "$FAIL_ON_VIOLATIONS" == "true" ]]; then
  exit "$EXIT_CODE"
else
  exit 0
fi
