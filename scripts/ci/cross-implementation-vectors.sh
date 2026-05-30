#!/usr/bin/env bash
# Appendix B cross-implementation gate (B5): reference crate reproduces committed bytes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
mneme_ci_init "$ROOT" "${MNEME_CI_LANE:-cross-impl}"

bash scripts/ci/check-test-vectors.sh

echo "cross-implementation-vectors: running mneme-crossref Appendix B harness..."
cargo test -p mneme-crossref --test appendix_b_crossref -- --nocapture

echo "cross-implementation-vectors: running primary Appendix B tests..."
cargo test -p mneme-core --test appendix_b_vectors appendix_b_ -- --nocapture
cargo test -p mneme-smt --test smt_invariants appendix_b_ -- --nocapture
cargo test -p mneme-root --test appendix_b_roots -- --nocapture
cargo test -p mneme-cap --test appendix_b_capabilities -- --nocapture
cargo test -p mneme-verify --test appendix_b_receipts -- --nocapture
cargo test -p mneme-crdt appendix_b_mst_convergence_vector_matches_fixture -- --nocapture

echo "cross-implementation-vectors: OK (primary + mneme-crossref reference)"
