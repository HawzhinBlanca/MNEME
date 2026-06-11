#!/usr/bin/env bash
# Verifiable Cognition Program — integration track smoke (certs, beacon, complete-kNN, crossref).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

echo "vcp-integration-smoke: beacon spot-check + complete-kNN cert vectors"
cargo test -p mneme-index --test beacon_spot_check -- --nocapture
cargo test -p mneme-index --test complete_knn_cert_v1 -- --nocapture

echo "vcp-integration-smoke: crossref Appendix B cognition + beacon extension"
cargo test -p mneme-crossref --test appendix_b_crossref crossref_ -- --nocapture

echo "vcp-integration-smoke: CLI verify-cert audit + complete-topk paths"
cargo test -p mneme-cli verify_cert -- --nocapture

echo "vcp-integration-smoke: OK"
