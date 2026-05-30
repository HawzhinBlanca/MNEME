# Golden root / receipt digests (blueprint §18)

Pinned digests checked on nightly reliability runs. Populated by the integration owner when foundation-gate and recall receipts stabilize (**§20.5**).

| File | Source |
|---|---|
| `foundation-gate.v1.json` | `mneme determinism foundation-gate` fixture (1970-01-01T00:00:00Z) |

Do not refresh golden files from feature branches without running `validation-lane determinism` twice on clean trees.

Two-machine procedure: see [docs/MNEME_SECOND_HOST.md](../../docs/MNEME_SECOND_HOST.md). Local same-host check: `bash scripts/ci/determinism-local-second-host.sh`.
