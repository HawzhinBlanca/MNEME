#!/usr/bin/env bash
# Idempotent Trick #4 installer — field 8 wire, verifier, CLI, crossref, docs.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec python3 scripts/apply_trick4_bundle.py
