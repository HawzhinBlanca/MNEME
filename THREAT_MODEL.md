# MNEME Threat Model

This document describes adversaries, assets, and mitigations for the MNEME verifiable
memory substrate. It is an engineering threat model — not a formal security proof.

## Scope

| Component | In scope |
|---|---|
| Store + key-index (SMT, content-addressed objects) | Yes |
| Verifier TCB (`mneme-verify`, ≤500 lines) | Yes |
| Daemon (`mnemed`) + §11 sync wire | Yes |
| Key vault (file, envelope/KMS adapters) | Yes |
| Semantic index (HNSW) + receipt verification | Yes (procedure-faithfulness, not truth) |

Out of scope for this document: TEE/enclave attestation (Phase II, deferred), Lean proofs
(Phase III, human-gated), and global exact-NN PIOP provers (Phase IV, research).

## Assets

| Asset | Goal | Impact if lost |
|---|---|---|
| Memory integrity | Detect tamper and forgery | Agent acts on false memories |
| Recall provenance | Bind reads to authorized writers and keys | Poisoned or cross-tenant context |
| Cryptographic keys | Protect operator seed and payload keys | Forged roots, plaintext leak |
| Forgotten state | Tombstones and shred are irreversible | GDPR / resurrection attacks |

## Adversary model

### Untrusted operator (host / disk)

Can read and rewrite filesystem state, reorder writes, roll back checkpoints, and corrupt
blobs. Goal: serve stale or tampered state that still appears plausible to an agent.

### Malicious sync peer

Can send regressed checkpoints, tampered objects, or unauthorized capability scopes over
WebSocket/Unix sync. Goal: poison replica state or desynchronize roots.

### Compromised client (leaked capability)

Holds scoped write/promote/forget tokens. Goal: exceed scope (wrong namespace, tier promotion,
historical overwrite).

## Threats and mitigations

### A-REPLAY (checkpoint rollback)

**Threat:** Restore an older signed root to resurrect forgotten entries or undo writes.

**Mitigation:** INV-6 cold-open rejects when any on-disk signed checkpoint sequence exceeds
`HEAD`. HLC high-water marks reject sequence advance with timestamp regression (`RootReplayed`).

### Retrieval / key-index poisoning

**Threat:** Return an entry for a logical key that was never authorized at the signed root.

**Mitigation:** Receipt↔root binding, SMT membership recompute, object re-hash, provenance and
capability checks in `verify_recall`. Any failure fails closed — no partial context.

### Mid-write corruption

**Threat:** Crash during transaction leaves inconsistent metadata or orphan blobs.

**Mitigation:** `.incomplete` sentinel + parent-dir `fsync` on Unix; `Store::repair` and
fail-closed open when incomplete state is detected.

### Key material in memory

**Threat:** DEK or master key extracted from RAM or core dumps.

**Mitigation:** `zeroize` on vault/key drop; sealed operator seed under `MNEME_KMS_MASTER_KEY_HEX`
(WO-18). Live KMS/HSM continuous proof remains operator-gated.

### Verifier fail-open

**Threat:** Malformed wire input or logic bug returns `Ok` when verification should reject.

**Mitigation:** Budgeted orchestration TCB, `#![forbid(unsafe_code)]`, `verify-tcb-guard.sh`
lints, generative tamper suites (`validation-lane.sh tamper`).

## Honesty boundary (not threats — documented limits)

These are **not** mitigated by the v0 verifier and must not be marketed as guarantees:

1. **Authenticated ≠ true.** Valid signatures do not prove factual correctness of content.
2. **Procedure-faithfulness, not exact nearest neighbors.** Verifiable retrieval proves procedure-faithfulness over committed data: membership/completeness plus top-k over prover-asserted distances. True top-k ranking is not proven; returned items are not top-k by true query-to-embedding distance until verifiers recompute candidate distances from carried embeddings.

Semantic VO distance-recompute (v-next interface change) is tracked in
`docs/research/SEMANTIC_VO_DISTANCE_RECOMPUTE_VNEXT.md` — not silently shipped.

## References

- `docs/TCB_MANIFEST.md` — trusted surface enumeration
- `docs/redteam/` — adversarial scenarios and red-team findings
- `scripts/ci/validation-lane.sh tamper` — generative tamper gate
