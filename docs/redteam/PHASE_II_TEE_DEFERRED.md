# Phase II — TEE / enclave verify deferred (document-only)

**Date:** 2026-06-04 • **Branch:** `cursor/phase-ii-max` • **Status:** deferred (no fake TEE)

## Scope honesty

Phase II ROADMAP steps 1–2 require hardware that is **not present** in this repository:

| Item | ROADMAP step | Status |
|---|---|---|
| P2-1 TEE / GPU confidential compute | Enclave verify inside TEE | **Deferred** — no NVIDIA CC, no sealed enclave |
| P2-2 Enclave verify + remote attestation | Receipt + zkANN re-check in enclave | **Deferred** — document-only |

## What shipped instead (software slice)

- Deterministic assembly (`mneme-context`, P2-3)
- CCA wire + digest verifier stub (`mneme-core` / `mneme-gate`, P2-4/P2-5)
- `context_gate` feature **off by default** (P2-6)
- Certificate v2 **draft** wire behind `context_gate` (not a production cert)
- Output-binding types + domain-separated `hash_model_output` (P2-7)
- Enclave-report **placeholder** wire that **always fails closed** on verify (P2-8)

## Fail-closed rules

1. `PHASE_II_GATE_OPEN` remains `false`.
2. `verify_enclave_report_placeholder` rejects every report, including honest placeholders.
3. No status string may claim verified TEE, remote attestation, or attested model execution.
4. `mneme-verify` TCB is unchanged; enclave logic stays out of the 500-line budget.

## When P2-1 / P2-2 can move to partial

Only after: real enclave integration, remote attestation quote verification, red-team forgery suite, and updated honesty strings — not before.
