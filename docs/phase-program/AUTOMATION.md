# Phase Program Automation

This checklist hard-blocks merges on the Phase program gates. Follow it for every PR and push to `master`. Run from repo root.

## Tools
- `scripts/ci/phase-program-gate.sh` — orchestrates checklists, validation lanes, and Phase I targeted tests.
- `docs/phase-program/manifest.yaml` — living evidence tracker (update after each run).

## Runbook (PR / push to master)
1. `git checkout master && git pull --rebase`
2. `PHASE_GATE_LEVEL=quick bash scripts/ci/phase-program-gate.sh`
3. Update `docs/phase-program/manifest.yaml` with new evidence paths and statuses.
4. If any gate fails, stop and fix before merging (fail-closed, no TODO stubs).

## Full gate
- Nightly or manual: `PHASE_GATE_LEVEL=full bash scripts/ci/phase-program-gate.sh`
- Tamper-only run: `PHASE_GATE_LEVEL=tamper bash scripts/ci/phase-program-gate.sh`

## What the gate runs
- Phase checklists from `docs/PHASE_*_TASK_SPEC.md` + manifest summary.
- Validation lanes (`quick`, `tamper`, or `full`).
- Phase I targeted tests: zkANN (pedersen_schnorr_zk), cognition certificate, `recall_verified_at`, `provenance_scoped`, CLI certify/verify-cert, crossref cognition-cert vectors.

## Policy
- Fail-closed verifiers only; TCB ≤ 500 lines (`mneme-verify`).
- Honesty strings preserved; no fabricated attestations or proofs.
- Run `ccc index` after meaningful edits to keep the code index fresh.
