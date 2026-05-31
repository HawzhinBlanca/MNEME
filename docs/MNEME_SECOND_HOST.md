# Two-machine determinism (blueprint §17.7, audit B4)

Foundation-gate digests must match across two real hosts at the same source revision with fixture timestamp `1970-01-01T00:00:00Z` and `mneme_crypto` fixture mode (no production `OsRng` in the gate path).

## B4 closure status (2026-05-31)

| Proof | Mechanism | Automated? | Closes B4? |
|---|---|---|---|
| **Cross-runner CI** | `.github/workflows/determinism-cross-runner.yml` — `ubuntu-latest` vs `macos-latest`, `determinism-cross-runner.sh compare` | **Yes** (weekly + PR/push to main) | **Yes** — distinct GitHub VMs, same commit |
| **Dual-workspace** | `determinism-two-machine.sh` (no env) | Yes (`reliability.yml` on schedule) | **No** — same physical runner |
| **SSH peer** | `MNEME_SECOND_HOST` + `determinism-two-machine.sh` | Optional (`determinism-ssh-peer` job when secrets set) | **Yes** — dedicated second host |
| **Localhost SSH** | `user@localhost` | Local only | **No** — same machine |

**Ops-only gap:** A customer-specific bare-metal second host is still proven only when repository secrets `MNEME_SECOND_HOST` and `MNEME_DETERMINISM_SSH_KEY` are configured. Without those secrets, B4 is closed by **cross-runner CI**, not by SSH.

## Scope (honest)

| Mode | Script | What it proves | CI default? | Closes §17.7 / 12-month? |
|---|---|---|---|---|
| **Cross-runner** | `determinism-cross-runner.sh` + workflow | Distinct `runs-on` images (Linux + macOS) | **Yes** (B4 gate) | **Yes** (independent VMs) |
| **Dual-workspace** | `determinism-two-machine.sh` (no env) | Two isolated rsync trees on one host, independent `CARGO_TARGET_DIR`, byte-identical digests vs pinned golden | Schedule / determinism lane | **No** — same physical host/OS |
| **Local two-run** | `determinism-local-second-host.sh` | Same checkout, two `out/` dirs, digest stability | Smoke only | **No** |
| **SSH remote peer** | `determinism-two-machine.sh` + `MNEME_SECOND_HOST` | Driver vs remote host via passwordless SSH | Optional ops job | **Yes** (when peer is a distinct host) |

Localhost SSH (`MNEME_SECOND_HOST=$USER@localhost`) is **LOCAL-ONLY** even if `sshd` is running — set `MNEME_STRICT_CROSS_HOST=1` to fail closed. It does not satisfy §17.7 cross-host independence.

## CI default — dual-workspace (same runner)

Runs without secrets or SSH:

```bash
bash scripts/ci/determinism-two-machine.sh
```

When `MNEME_SECOND_HOST` is unset, the script rsyncs two temp workspaces, runs `foundation-gate` in each with isolated targets, compares `run_a` digests, and checks `proof/digests/foundation-gate.v1.json`.

## Cross-runner CI (B4 automated proof)

Workflow: `.github/workflows/determinism-cross-runner.yml`

1. Matrix job runs `bash scripts/ci/determinism-cross-runner.sh gate --label gh-ubuntu|gh-macos` on **ubuntu-latest** and **macos-latest**.
2. `compare-digests` downloads artifacts and runs:

```bash
bash scripts/ci/determinism-cross-runner.sh compare \
  <ubuntu-report> <macos-report> gh-ubuntu gh-macos
```

3. `b4-gate` requires cross-runner compare success; SSH peer job is skipped when secrets are unset.

Local rehearsal (compare logic only — **not** cross-host):

```bash
export CARGO_TARGET_DIR="$PWD/out/agent-targets/b4-ssh"
bash scripts/ci/determinism-cross-runner.sh gate --label local-a --out /tmp/mneme-a
bash scripts/ci/determinism-cross-runner.sh gate --label local-b --out /tmp/mneme-b
bash scripts/ci/determinism-cross-runner.sh compare \
  /tmp/mneme-a/foundation.report.json /tmp/mneme-b/foundation.report.json
```

## Docker simulation (no second host, no secrets)

When no SSH peer is available, the Docker mode approximates cross-host independence on a single machine. It builds **one** pinned image and runs **two fully isolated containers**, then compares their `run_a` digests and checks the pinned golden.

```bash
bash scripts/ci/determinism-two-machine.sh --docker
# equivalent: MNEME_DOCKER_SIM=1 bash scripts/ci/determinism-two-machine.sh
```

Isolation properties (why it approximates a second host):

- **No shared filesystem** — containers run with no `-v`/`--mount`; each writes `/work/out` inside its own private writable layer.
- **Independent entropy / identity** — distinct `--hostname` (`mneme-alpha` / `mneme-bravo`), separate PID namespaces, and per-container `/dev/urandom`.
- **`--network none`** at runtime — no network can leak shared state into the gate.
- **Pinned build** — `scripts/ci/determinism.Dockerfile` uses `rust:1.86.0-bookworm` and `cargo build -p mneme-cli --locked`; the build context is a clean rsync of the working tree (`target/`, `out/`, `.git/`, `fuzz/corpus/` excluded).

Honesty boundary: containers **share the host kernel and CPU architecture**, so this is a same-kernel *simulation* — a strong proxy for §17.7 cross-host independence, **not** a two-physical-machine proof. The authoritative cross-host proofs remain cross-runner CI (Linux + macOS) and the optional `MNEME_SECOND_HOST` SSH peer.

Outputs (under `out/ci-two-machine-docker/`):

- `container-alpha.report.json`, `container-bravo.report.json` — the two `foundation.report.json` files (byte-identical on success).
- `docker-sim-manifest.json` — provenance: image tag, source revision, fixture timestamp, container hostnames, and the recorded digests.

Useful env overrides: `MNEME_DOCKER_IMAGE` (image tag), `MNEME_DOCKER_OUT` (output dir), `MNEME_DETERMINISM_TS` (fixture timestamp).

CI: the `determinism-docker-sim` job in `.github/workflows/determinism-cross-runner.yml` runs this on every push/PR (no secrets) and is required by `b4-gate`.

## Local smoke — same checkout, two outputs

```bash
bash scripts/ci/determinism-local-second-host.sh
```

Proves only that the local fixture gate is stable across two local output directories. Weaker than dual-workspace (shared target cache path semantics); use dual-workspace for same-host CI.

## SSH second host (operational follow-up)

1. Check out the **same commit** on both machines.
2. Install the Rust toolchain from `rust-toolchain.toml` on both machines.
3. Ensure the repository path on the remote matches the driver's workspace path, or set `MNEME_REMOTE_ROOT` on the driver to the remote checkout path.
4. Confirm passwordless SSH from the driver:

```bash
ssh -o BatchMode=yes user@peer.example true
```

5. On the **driver** machine:

```bash
export MNEME_SECOND_HOST='user@peer.example'
export MNEME_DETERMINISM_TS='1970-01-01T00:00:00Z'
export MNEME_STRICT_CROSS_HOST=1
# optional when remote path differs from driver $PWD:
# export MNEME_REMOTE_ROOT='/path/on/remote/MNEME'
bash scripts/ci/determinism-two-machine.sh
```

Requirements for `MNEME_SECOND_HOST`:

- Passwordless SSH (`ssh -o BatchMode=yes user@peer.example true` succeeds).
- Same source revision (`git rev-parse HEAD` on remote when `.git` exists).
- Same repository path on the remote as driver `ROOT`, unless `MNEME_REMOTE_ROOT` is set.
- `cargo` and `python3` available on both hosts.

Preflight checks (connection, remote root, toolchain, git HEAD) exit non-zero with explicit errors — **no silent fallback** to dual-workspace when `MNEME_SECOND_HOST` is set.

Evidence logging (local ops runs):

```bash
export MNEME_B4_EVIDENCE_DIR=out/readiness/b4-close-20260531
bash scripts/ci/determinism-two-machine.sh  # or SSH mode with MNEME_SECOND_HOST set
```

## GitHub Actions — SSH peer (optional)

Configured in `.github/workflows/determinism-cross-runner.yml` as job `determinism-ssh-peer` when secrets exist:

| Secret | Required | Purpose |
|---|---|---|
| `MNEME_SECOND_HOST` | Yes (for SSH job) | `user@host` SSH target |
| `MNEME_DETERMINISM_SSH_KEY` | Yes | Private key authorized on the peer |
| `MNEME_REMOTE_ROOT` | No | Remote checkout path when it differs from the runner workspace |

The `determinism-dual-workspace` job in `reliability.yml` runs `determinism-two-machine.sh` **without** `MNEME_SECOND_HOST` (same-runner isolation only).

## Pinned digests

Nightly / full lane compares against `proof/digests/foundation-gate.v1.json` via:

```bash
bash scripts/ci/check-foundation-digests.sh out/ci-foundation-gate/foundation.report.json
```

## INV-10: identity digests

Foundation digests hash only receipt fields, SMT paths, root preimages, and canonical object bytes. They must **not** incorporate wall-clock time, process ID, or absolute filesystem paths. The crossref crate test `crossref_identity_digests_exclude_nondeterministic_inputs` guards obvious regressions; code review remains required for new hash inputs.
