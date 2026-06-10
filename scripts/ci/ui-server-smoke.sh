#!/usr/bin/env bash
# Fast no-browser smoke for the local MNEME web UI server.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

node --check scripts/serve-ui.js
node --check ui/index.js
node scripts/ci/ui-server-smoke.mjs

echo "ui-server-smoke: OK"
