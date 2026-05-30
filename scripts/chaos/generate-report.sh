#!/usr/bin/env bash
# Build CHAOS_REPORT.md from soak artifacts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPORT_DIR="${1:-$ROOT/out/readiness/chaos-soak-20260531}"
MATRIX="$REPORT_DIR/chaos-matrix.tsv"
SUMMARY="$REPORT_DIR/soak-summary.txt"
LOG="$REPORT_DIR/chaos-soak.log"
UNSAFE="$REPORT_DIR/unsafe-events.log"
OUT="$REPORT_DIR/CHAOS_REPORT.md"

mkdir -p "$REPORT_DIR"

unsafe_n=0
if [[ -f "$UNSAFE" ]]; then
  unsafe_n=$(grep -c . "$UNSAFE" 2>/dev/null || echo 0)
fi

matrix_rows=0
if [[ -f "$MATRIX" ]]; then
  matrix_rows=$(( $(wc -l <"$MATRIX") - 1 ))
fi

mtbus="NEVER (target)"
if [[ "$unsafe_n" -gt 0 ]]; then
  mtbus="**VIOLATED** — $unsafe_n unsafe event(s); MTBUS = 0"
fi

{
  echo "# MNEME Chaos Soak Report"
  echo ""
  echo "**Branch:** \`cursor/readiness-adversarial-audit-not-ready\`"
  echo "**Date (UTC):** $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "**Target dir:** \`out/agent-targets/chaos-soak\`"
  echo ""
  echo "## Executive summary"
  echo ""
  if [[ -f "$SUMMARY" ]]; then
    echo '```'
    cat "$SUMMARY"
    echo '```'
  fi
  echo ""
  echo "| Metric | Value |"
  echo "|--------|-------|"
  echo "| Fault rows recorded | $matrix_rows |"
  echo "| Unsafe states | $unsafe_n |"
  echo "| **MTBUS** | $mtbus |"
  echo ""
  echo "### Unsafe state definition"
  echo ""
  echo "- \`verify_store\` returns Ok on a store known to be corrupted by the fault"
  echo "- Silent data loss (golden payload missing when recovery expected)"
  echo "- Panic in verifier TCB (\`verify_store\` / open / \`recall_verified\`)"
  echo "- \`recall_verified\` returns wrong plaintext"
  echo ""
  echo "## Fault-injection matrix (aggregated)"
  echo ""
  if [[ -f "$MATRIX" ]]; then
    echo "| Fault | Injection point | Expected | Actual (sample) | verify_store | Unsafe count |"
    echo "|-------|-----------------|----------|-----------------|--------------|--------------|"
    tail -n +2 "$MATRIX" | awk -F'\t' '
      { key=$3 SUBSEP $4 SUBSEP $5; n[key]++; if(!a[key]) a[key]=$6; if(!v[key]) v[key]=$7; if($10=="true") u[key]++ }
      END {
        for (k in n) {
          split(k,p,SUBSEP);
          ucnt = (k in u) ? u[k] : 0;
          printf "| %s | %s | %s | %s | %s | %d / %d |\n", p[1], p[2], p[3], a[k], v[k], ucnt, n[k]
        }
      }' | sort
  else
    echo "_No matrix TSV found — run \`scripts/chaos/soak.sh\` first._"
  fi
  echo ""
  echo "## Per-fault family notes"
  echo ""
  echo "| Fault | Harness behavior |"
  echo "|-------|------------------|"
  echo "| disk_full_mid_txn | Read-only tree during \`remember\` (ENOSPC simulation on macOS) |"
  echo "| corrupt_random_blob | Random flip on HEAD / key_index / object CBOR |"
  echo "| clock_skew_merge | Two-peer \`merge_from_path\`; **limitation:** no \`ClockRegression\` hook in store |"
  echo "| stale_signed_root | A-REPLAY rollback of HEAD + key_index after forget |"
  echo "| forged_root | Signature byte corruption on HEAD |"
  echo "| kill_random_boundary | Pause hook at random remember boundary (SIGKILL equiv.) |"
  echo "| kill_merge_boundary | Pause during merge object write |"
  echo "| kill_forget_boundary | Pause during forget |"
  echo ""
  echo "## Log paths"
  echo ""
  echo "- Soak log: \`$LOG\`"
  echo "- Matrix TSV: \`$MATRIX\`"
  echo "- Unsafe events: \`$UNSAFE\`"
  echo "- Harness: \`tests/chaos/mod.rs\`, \`scripts/chaos/soak.sh\`"
  echo ""
  if [[ "$unsafe_n" -gt 0 ]]; then
    echo "## Blockers (UNSAFE)"
    echo ""
    cat "$UNSAFE"
  fi
} >"$OUT"

echo "Wrote $OUT"
