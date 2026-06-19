#!/usr/bin/env bash
# Prune regenerable build/CI artifacts that accumulate under the repo.
#
# The validation ladder gives every lane its own CARGO_TARGET_DIR under
# out/agent-targets/ci-<lane> (see lib.sh) so parallel agents never clobber each
# other. Nothing reclaims those dirs, so they grow without bound (tens of GiB).
# This script prunes the regenerable caches while preserving evidence (run logs,
# SUMMARY.txt) and the accumulated fuzz corpus.
#
# Usage:
#   scripts/ci/clean-artifacts.sh           # dry-run: show what would be freed
#   scripts/ci/clean-artifacts.sh --yes     # actually delete
#   scripts/ci/clean-artifacts.sh --all     # also remove ./target and fuzz/target
#                                            # (slower next build; dev caches too)
#
# Always preserved: out/overnight/**/*.log, **/SUMMARY.txt, out/**/*.json results,
# fuzz/corpus (coverage-increasing inputs).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

APPLY=0
ALL=0
for arg in "$@"; do
  case "$arg" in
    -y|--yes) APPLY=1 ;;
    --all) ALL=1 ;;
    -h|--help)
      sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "clean-artifacts: unknown arg '$arg'" >&2; exit 2 ;;
  esac
done

# Build the prune list (regenerable caches only).
targets=()
[[ -d out/agent-targets ]] && targets+=(out/agent-targets)
# Overnight runs: drop only the build dirs, keep the logs/SUMMARY beside them.
while IFS= read -r d; do targets+=("$d"); done < <(
  find out/overnight -mindepth 2 -maxdepth 2 -type d -name 'target*' 2>/dev/null || true
)
if [[ "$ALL" -eq 1 ]]; then
  [[ -d target ]] && targets+=(target)
  [[ -d fuzz/target ]] && targets+=(fuzz/target)
fi

if [[ "${#targets[@]}" -eq 0 ]]; then
  echo "clean-artifacts: nothing to prune."
  exit 0
fi

echo "Prunable build/CI caches (all regenerable):"
total_k=0
for t in "${targets[@]}"; do
  k=$(du -sk "$t" 2>/dev/null | cut -f1)
  total_k=$((total_k + ${k:-0}))
  printf '  %8s  %s\n' "$(du -sh "$t" 2>/dev/null | cut -f1)" "$t"
done
printf 'Total reclaimable: %d MiB\n' "$((total_k / 1024))"

if [[ "$APPLY" -ne 1 ]]; then
  echo
  echo "(dry-run) re-run with --yes to delete. Preserved: run logs, SUMMARY.txt, fuzz/corpus."
  exit 0
fi

for t in "${targets[@]}"; do
  rm -rf "$t"
done
echo "Done. Freed ~$((total_k / 1024)) MiB. Build caches repopulate on next cargo/CI run."
