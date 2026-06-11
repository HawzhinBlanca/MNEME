# P3 Local Scaffolds (research substitutes — not shipped external proof)

Last updated: 2026-06-11

These are **in-repo substitutes** for human-gated Phase III proofs documented in
[`HUMAN_TASKS.md`](HUMAN_TASKS.md). They exist so operators and agents can run
cheap local gates without secrets, hardware, or organizational decisions.

**Honesty boundary:** passing `scripts/ci/validation-lane.sh p3-local` proves the
scaffold scripts and their local checks — **not** live KMS/HSM continuous proof,
TEE enclave execution, SSH cross-host convergence on distinct physical hardware,
or machine-checked Lean verification.

## Aggregate gate

```bash
scripts/ci/validation-lane.sh p3-local
```

Runs, in order:

| Script | Local check | Skipped without (fail-closed skip, exit 0) |
|---|---|---|
| `scripts/ci/convergence-two-host.sh --local-smoke` | CRDT merge + two-peer sync tests | N/A (`--local-smoke` always runs) |
| `scripts/kms/conformance-local.sh` | `EnvelopeKeyVault` round-trip parity | Live AWS bridge when `AWS_KMS_KEY_ID` unset |
| `scripts/ci/attestation-policy-local.sh` | `mneme-attest` PEM/DER parser tests | Operator blob path when `MNEME_TEE_ATTESTATION_EVIDENCE` unset |
| `scripts/ci/formal-obligations-local.sh` | TCB guard + budget + obligation inventory | Lean artifacts when `proof/formal/` absent |

## Convergence (`convergence-two-host.sh`)

- **`--local-smoke`:** same-host `mneme-crdt` merge convergence and `mnemed`
  two-peer WebSocket sync convergence. Does **not** prove distinct-host CRDT
  anti-entropy over the public internet.
- **`MNEME_SECOND_HOST`:** optional operator SSH gate running merge tests on a
  peer checkout. Still not a substitute for production convergence monitoring.

## KMS/HSM (`kms/conformance-local.sh`)

- Always runs `EnvelopeKeyVault` contract tests (`mneme-crypto`).
- When `AWS_KMS_KEY_ID` and `aws` CLI are present, also runs
  `scripts/kms/dek-from-aws.sh` as an operator bridge smoke.
- Live GCP/PKCS#11 two-tier KEK rotation remains external-endpoint work; see
  [`HSM_KMS_ADAPTER.md`](HSM_KMS_ADAPTER.md).

## TEE attestation (`attestation-policy-local.sh`)

`mneme-attest` validates PEM/DER **shape** only. It is **not** a production TEE
attestor.

### `AcceptedReportPolicy` (placeholder — not enforced)

Future operator policy (frozen sketch, not wired):

| Field | Intent |
|---|---|
| `pinned_root` | Accept only attestation chains rooted at operator-chosen CA |
| `measurement_allowlist` | MRENCLAVE / PCR / SNP measurement set |
| `nonce_freshness` | Reject stale/nonces-replayed quotes |

When `MNEME_TEE_ATTESTATION_EVIDENCE` points at a file, the scaffold only checks
that the file exists and is non-empty. Vendor quote verification and enclave
execution proof remain **human-gated**.

## Formal methods (`formal-obligations-local.sh`)

- Runs `verify-tcb-guard.sh` and `tcb_budget` tests.
- Scans `mneme-verify` for `INVARIANT`, `PROOF-OBLIGATION`, and `HONESTY`
  comment markers.
- A real Lean/F*/Kani proof requires artifacts under `proof/formal/` and formal-
  methods owner review — not claimed by this lane.

## What remains human-gated

See [`HUMAN_TASKS.md`](HUMAN_TASKS.md): SSH peer re-verification, cloud KMS/HSM
continuous proof, TEE hardware attestation, Lean verifier proof, trust-ops pilot,
and Phase IV prover/interop commitments.
