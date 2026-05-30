# Two-machine determinism (blueprint §17.7, B6)

Foundation-gate digests must match across two real hosts at the same source revision with fixture timestamp `1970-01-01T00:00:00Z` and `mneme_crypto` fixture mode (no production `OsRng` in the gate path).

`scripts/ci/determinism-two-machine.sh` is fail-closed: if `MNEME_SECOND_HOST` is unset, it exits non-zero. Same-host checks are useful smoke tests, but they are LOCAL-ONLY and must not be reported as cross-machine evidence.

## LOCAL-ONLY Same-Host Check

Runs two foundation gates in the driver checkout:

```bash
bash scripts/ci/determinism-local-second-host.sh
```

This proves only that the local fixture gate is stable across two local output directories. It does not prove host/OS/CPU/toolchain independence and does not close §17.7.

## SSH Second Host

1. Check out the **same commit** on both machines.
2. Install the Rust toolchain from `rust-toolchain.toml` on both machines.
3. Ensure the repository path on the remote matches the driver's workspace path, or update the script before running.
4. Confirm passwordless SSH from the driver:

```bash
ssh user@peer.example true
```

5. On the **driver** machine:

```bash
export MNEME_SECOND_HOST='user@peer.example'
export MNEME_DETERMINISM_TS='1970-01-01T00:00:00Z'
bash scripts/ci/determinism-two-machine.sh
```

Requirements for `MNEME_SECOND_HOST`:

- Passwordless SSH (`ssh user@peer.example true` succeeds).
- Same source revision and clean generated fixtures on both hosts.
- Same repository path on the remote as `ROOT` in the script (default: driver's `$PWD`).
- `cargo` and `python3` available on both hosts.

If `MNEME_SECOND_HOST` is unset, `determinism-two-machine.sh` fails closed. Set it only for a real SSH peer; do not point it back to localhost unless the run is explicitly labeled LOCAL-ONLY and excluded from the §17.7 claim.

## Pinned digests

Nightly / full lane compares against `proof/digests/foundation-gate.v1.json` via:

```bash
bash scripts/ci/check-foundation-digests.sh out/ci-foundation-gate/foundation.report.json
```

## INV-10: identity digests

Foundation digests hash only receipt fields, SMT paths, root preimages, and canonical object bytes. They must **not** incorporate wall-clock time, process ID, or absolute filesystem paths. The crossref crate test `crossref_identity_digests_exclude_nondeterministic_inputs` guards obvious regressions; code review remains required for new hash inputs.
