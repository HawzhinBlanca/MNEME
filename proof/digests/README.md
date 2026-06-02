# Golden root / receipt digests (blueprint §18)

Pinned digests checked on nightly reliability runs. Populated by the integration owner when foundation-gate and recall receipts stabilize (**§20.5**).

| File | Source |
|---|---|
| `foundation-gate.v1.json` | `mneme determinism foundation-gate` fixture (1970-01-01T00:00:00Z) |

Do not refresh golden files from feature branches without running `validation-lane determinism` twice on clean trees.

## Determinism checks (what each gate proves)

| Check | Command | CI? | Cross-host / independent VM? |
|---|---|---|---|
| Pinned golden match | `check-foundation-digests.sh <report>` | Yes | N/A |
| **Cross-runner (B4)** | `determinism-cross-runner.sh` + `determinism-cross-runner.yml` | **Yes** | **Yes** — ubuntu-latest vs macos-latest |
| Dual-workspace isolation | `determinism-two-machine.sh` (default) | Schedule / determinism lane | No — same runner, two rsync trees |
| Local two-run smoke | `determinism-local-second-host.sh` | Optional | No |
| SSH peer | `MNEME_SECOND_HOST=… determinism-two-machine.sh` | Optional (secrets) | Yes — dedicated peer host |

**Audit B4:** Closed by automated cross-runner workflow when SSH secrets are unset. Ops SSH proof remains available via `MNEME_SECOND_HOST`.

Procedure: [docs/MNEME_SECOND_HOST.md](../../docs/MNEME_SECOND_HOST.md).
