#!/usr/bin/env bash
# VCP C2 — Jewel C accumulator scaffold smoke (mneme-accum, feature-gated).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

echo "vcp-c2-smoke: mneme-accum jewel_c scaffold"
cargo test -p mneme-accum --features jewel_c -- --nocapture
echo "vcp-c2-smoke: OK"
