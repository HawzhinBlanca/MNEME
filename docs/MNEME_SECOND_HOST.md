# Two-machine determinism (blueprint §17.7, audit B4)

Foundation-gate digests must match across two real hosts at the same source revision with fixture timestamp `1970-01-01T00:00:00Z` and `mneme_crypto` fixture mode (no production `OsRng` in the gate path).

## Scope (honest)

| Mode | Script | What it proves | CI default? | Closes §17.7 / 12-month? |
|---|---|---|---|---|
| **Dual-workspace** | `determinism-two-machine.sh` (no env) | Two isolated rsync trees on one host, independent `CARGO_TARGET_DIR`, byte-identical digests vs pinned golden | **Yes** | **No** — same physical host/OS/toolchain |
| **Local two-run** | `determinism-local-second-host.sh` | Same checkout, two `out/` dirs, digest stability | Smoke only | **No** |
| **SSH remote peer** | `determinism-two-machine.sh` + `MNEME_SECOND_HOST` | Driver vs remote host via passwordless SSH | Optional ops job | **Yes** (when peer is a distinct host) |

**Audit B4 (two-machine):** dual-workspace **passes CI** and proves digest reproducibility across clean trees; it does **not** replace SSH cross-host proof. Real SSH evidence remains an operational follow-up before declaring the 12-month two-machine milestone closed.

Localhost SSH (`MNEME_SECOND_HOST=$USER@localhost`) is **LOCAL-ONLY** even if `sshd` is running — it does not satisfy §17.7 cross-host independence.

## CI default — dual-workspace

Runs without secrets or SSH:

```bash
bash scripts/ci/determinism-two-machine.sh
```

When `MNEME_SECOND_HOST` is unset, the script rsyncs two temp workspaces, runs `foundation-gate` in each with isolated targets, compares `run_a` digests, and checks `proof/digests/foundation-gate.v1.json`.

## Local smoke — same checkout, two outputs

```bash
bash scripts/ci/determinism-local-second-host.sh
```

Proves only that the local fixture gate is stable across two local output directories. Weaker than dual-workspace (shared target cache path semantics); use dual-workspace for CI.

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
# optional when remote path differs from driver $PWD:
# export MNEME_REMOTE_ROOT='/path/on/remote/MNEME'
bash scripts/ci/determinism-two-machine.sh
```

Requirements for `MNEME_SECOND_HOST`:

- Passwordless SSH (`ssh -o BatchMode=yes user@peer.example true` succeeds).
- Same source revision and clean generated fixtures on both hosts.
- Same repository path on the remote as driver `ROOT`, unless `MNEME_REMOTE_ROOT` is set.
- `cargo` and `python3` available on both hosts.

Preflight failures (connection refused, auth denied) exit non-zero with an explicit SSH error — no silent fallback to dual-workspace when `MNEME_SECOND_HOST` is set.

## GitHub Actions job template (optional SSH peer)

Add to `.github/workflows/reliability.yml` (or a dedicated workflow) when a repository secret `MNEME_SECOND_HOST` is configured (e.g. `runner-user@determinism-peer.internal`):

```yaml
  determinism-ssh-peer:
    name: determinism (SSH peer — §17.7)
    runs-on: ubuntu-latest
    if: ${{ secrets.MNEME_SECOND_HOST != '' }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          toolchain-file: rust-toolchain.toml
      - name: Load SSH key for determinism peer
        uses: webfactory/ssh-agent@v0.9.0
        with:
          ssh-private-key: ${{ secrets.MNEME_DETERMINISM_SSH_KEY }}
      - name: Trust peer host key
        run: |
          mkdir -p ~/.ssh
          ssh-keyscan -H "${{ secrets.MNEME_SECOND_HOST }}" >> ~/.ssh/known_hosts
      - name: Two-machine foundation gate (SSH)
        env:
          MNEME_SECOND_HOST: ${{ secrets.MNEME_SECOND_HOST }}
          MNEME_DETERMINISM_TS: '1970-01-01T00:00:00Z'
          MNEME_REMOTE_ROOT: ${{ secrets.MNEME_REMOTE_ROOT }}
        run: bash scripts/ci/determinism-two-machine.sh
```

Secrets:

| Secret | Required | Purpose |
|---|---|---|
| `MNEME_SECOND_HOST` | Yes (for this job) | `user@host` SSH target |
| `MNEME_DETERMINISM_SSH_KEY` | Yes | Private key authorized on the peer |
| `MNEME_REMOTE_ROOT` | No | Remote checkout path when it differs from the runner workspace |

The existing `determinism` matrix job in `reliability.yml` should keep running `determinism-two-machine.sh` **without** `MNEME_SECOND_HOST` (dual-workspace CI gate).

## Pinned digests

Nightly / full lane compares against `proof/digests/foundation-gate.v1.json` via:

```bash
bash scripts/ci/check-foundation-digests.sh out/ci-foundation-gate/foundation.report.json
```

## INV-10: identity digests

Foundation digests hash only receipt fields, SMT paths, root preimages, and canonical object bytes. They must **not** incorporate wall-clock time, process ID, or absolute filesystem paths. The crossref crate test `crossref_identity_digests_exclude_nondeterministic_inputs` guards obvious regressions; code review remains required for new hash inputs.
