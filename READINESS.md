# MNEME Readiness Report - Bounded Status

This file is a bounded operator status note, not an authoritative proof of
production readiness. The canonical invariants and validation commands live in
[`CLAUDE.md`](CLAUDE.md); concrete readiness claims must be backed by current
logs from those commands, preferably from a clean checkout.

## Current Verdict

MNEME has a strong fail-closed single-host kernel and a growing operator audit
surface, but it must not be described as universally complete, fully secure, or
"100%" ready. A release claim is defensible only for the exact scope covered by
fresh validation evidence.

## Proven Scope To Recheck Before Release

- `mneme verify` rejects invalid signed roots and now accepts an external
  `--pin-peak-state` witness for append-only root-history extension.
- Disk-detectable replay is rejected through the checkpoint log. A full
  self-consistent snapshot rollback still requires an out-of-band trusted root pin or an external peak-state pin.
- Peak-state pins must live outside the store and existing pins must be regular single-link files, not symlinks or hard links; same-host pin files can still be rolled back if the store and pin are snapshotted together.
- Default product builds hide operator-only `audit`, `init`, and
  `determinism`; operator tools remain behind the `operator_tools` feature.
- Recall receipts prove integrity, provenance, authorization, and declared
  procedure-faithfulness. They do not prove semantic truth, exact nearest-neighbor optimality, or default SNARK/Plonky2 verification.

## Required Evidence

Before using this repository as a release candidate, regenerate and retain:

- `cargo fmt --all -- --check`
- `scripts/ci/validation-lane.sh quick`
- `scripts/ci/validation-lane.sh tamper`
- `scripts/ci/validation-lane.sh determinism`
- `scripts/ci/validation-lane.sh full` from a clean checkout when making a
  broad readiness claim
- A real cross-host or CI cross-runner determinism proof when making a
  two-physical-host claim

## Open External Proofs

- Live KMS/HSM custody proof against real infrastructure.
- Continuous cross-host determinism re-verification on distinct machines.
- Sustained fuzz and soak evidence beyond the local smoke gates.
- TEE/remote-attestation integration for model consumption claims.
- Machine-checked proofs for the higher-level cognition-certificate roadmap.

## Forbidden Readiness Claims

Do not claim that MNEME is fully secure, 100% hardened, semantically truthful,
exact-nearest-neighbor complete, or SNARK-backed by default. If a feature sounds
stronger than the verifier can check offline, downgrade the claim or add a real
verification path first.
