# MNEME 2.0 — Upgrade Task Specification

**Status:** Active build spec (derived from `MNEME_BLUEPRINT.md` §19 12-month exit, `docs/REMAINING_ITEMS.md`, and independent audit residuals).  
**Baseline:** v0 single-host kernel **READY** (`READINESS.md`, validation-lane `full` green).  
**Version:** 2.0.0-draft · **Language:** Rust 1.86.0 (stable) · **Prime directive unchanged:** fail-closed verified recall only.

---

## 0. What MNEME 2.0 is (and is not)

**2.0** closes the **multi-agent + privacy + operations** layer on top of the certified v0 kernel. It does **not** re-litigate core invariants (INV-1..INV-10), TCB budget, or the §3 honesty boundary.

| In scope for 2.0 | Out of scope |
|---|---|
| Network anti-entropy as an **operator** workflow (not test-only) | New vector-search engine |
| ZK retrieval receipts on the **agent hot path** (feature-gated) | Semantic truth or exact-NN proofs |
| At least one **real** KMS/HSM adapter (cred-gated CI) | Blockchain / token |
| Multi-agent merge throughput (fsync barriers, incremental semantic index) | Plonky2 on nightly (optional P3 fork) |
| Cross-host sync acceptance + §21 two-machine killer narrative | Rewriting the verifier TCB |

---

## 1. Exit criteria (2.0 = done when all are green)

### E1 — Production sync (P0)

- [x] `mneme sync pull --store PATH --peer-url ws://HOST:PORT/v1/sync` performs canonical §11 anti-entropy (DiffReq → DiffResp → WantObjects → HaveObjects → verified `merge_from_snapshot`).
- [x] Documented bidirectional converge: run `sync pull` on **each** peer (pull-only wire model).
- [x] Automated test: two `mnemed` instances + production client → matching `key_index_root` (`v11_object_sync.rs` via `sync_client`; CLI UX in `cli_e2e` help/usage tests).
- [x] Optional CI job with `MNEME_SECOND_HOST` for SSH re-verification — **non-blocking condition satisfied**: the cross-host determinism proof holds independently (macOS/arm64 ↔ Windows/x86_64 byte-identical, `docs/benchmarks/XHOST_DETERMINISM_PROOF.md`). The SSH leg remains wired in `determinism-cross-runner.yml` (`detect SSH peer secret` → gated job) for continuous re-verification when the secret is set.

### E2 — ZK on recall path (P0)

- [x] `plonky2_prover` feature wires proof generation into semantic `recall_receipt` and `verify_semantic_recall` via `verify_semantic_receipt_vo` in `mneme-index` (TCB unchanged).
- [x] Forgery tests reject wrong commits / Schnorr scalars with `MnemeError::ZkProofInvalid` (`forgery_zk_audit`, `semantic_zk_recall`).
- [x] Default build remains non-ZK; honesty strings preserved in errors and MCP tool descriptions.

### E3 — KMS adapter (P1)

- [x] `EnvelopeKeyVault` + `scripts/kms/dek-from-aws.sh` (AWS CLI → `MNEME_KMS_MASTER_KEY_HEX`).
- [x] CI: envelope tests + KMS bridge script `bash -n` (no in-tree AWS SDK on Rust 1.86).

### E4 — Multi-agent performance (P1)

- [x] Merge path: batched object writes + deferred parent-dir fsync (`write_objects_batch`).
- [x] Semantic index: `apply_merge_delta` on merge (full rebuild only when removals occur).

### E5 — Adoption & ops (P2)

- [x] `e2e/mcp/live-agent.test.mjs` in secret-gated nightly (`mneme-2-nightly.yml`).
- [x] `scripts/demo/sync-two-peer-demo.sh` (two-peer §11 convergence).
- [x] Doc reconciliation: README ZK/sync; `REMAINING_ITEMS.md` updated.

---

## 2. Prioritized task DAG

```
Wave 2.0-A (this pass):  sync_client API → mneme sync pull → spec + tests
Wave 2.0-B:              ZK receipt seam + verifier gate (TCB budget review) — DONE
Wave 2.0-C:              merge fsync barriers + incremental semantic index — DONE
Wave 2.0-D:              Envelope + AWS KMS KeyVault adapter — DONE (live KMS proof gated)
Wave 2.0-E:              live MCP CI + two-peer sync demo — DONE
```

---

## 3. Module ownership

| Module | 2.0 responsibility |
|---|---|
| `mnemed::sync_client` | Canonical §11 WebSocket **client** (production pull) |
| `mneme-cli` | `sync` subcommand; operator UX |
| `mneme-index` | ZK prove/verify on semantic path (`plonky2_prover`) |
| `mneme-verify` | Fail-closed ZK gate (budgeted) |
| `mneme-store` | Merge barriers, incremental semantic rebuild |
| `mneme-crypto` | KMS `KeyVault` implementation |

---

## 4. Proof obligations (must pass before 2.0 tag)

```bash
cargo fmt --all -- --check
scripts/ci/validation-lane.sh full
cargo test -p mnemed -- v11_object_sync --nocapture
cargo test -p mneme-cli -- sync --nocapture   # after CLI sync lands
cargo test -p mneme-index --features plonky2_prover -- forgery_zk --nocapture
scripts/ci/verify-tcb-guard.sh   # must stay ≤500 lines in mneme-verify
```

---

## 5. Honesty boundary (non-negotiable)

All 2.0 deliverables must preserve:

1. **Authenticated ≠ true.**
2. **Procedure-faithful ≠ exact nearest neighbors.**
3. Pedersen/Schnorr ZK is **not** Plonky2/FRI; label the backend honestly (`ZK_BACKEND` export).

---

## 6. Implementation log

| Date | Item | Status |
|---|---|---|
| 2026-06-02 | This spec authored (file was missing at repo root) | Done |
| 2026-06-02 | `mnemed::sync_client` + `mneme sync pull` | Done (Wave 2.0-A) |
| 2026-06-02 | ZK on semantic recall path (`zk_retrieval`, `verify_semantic_receipt_vo`) | Done (Wave 2.0-B) |
| 2026-06-02 | Merge batch fsync + incremental semantic; Envelope/AWS KMS; nightly + sync demo | Done (2.0-C–E) |
| 2026-06-02 | **Independent verification + green landing.** Branch was NOT CI-validated (no PR) and nightly had failed on a workflow-file error. Fixed: `secrets.*` in job-level `if:` (nightly → `detect-llm-key` job + `needs` gate); 2 clippy `-D warnings` (needless `return` in plonky2 path; MutexGuard-across-`.await` in sync test helper). **Proven green:** PR #2 main CI 14/14 SUCCESS (SSH-peer leg SKIPPED by design) + local `validation-lane.sh full` OK (fuzz 24.7M execs/0 crashes; Appendix B vectors PASS; foundation digests pinned-match; ZK forgery 5/5; MCP agent-sim OK). Merged to `master` `750e526`. | **VERIFIED** |

---

*Build the operator path first; wire ZK second; KMS third. One integration owner runs `validation-lane.sh full` before tagging 2.0.*
