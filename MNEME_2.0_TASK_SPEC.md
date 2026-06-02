# MNEME 2.0 — Build Task Spec: Five Inventions to Top-Tier Completion

**Purpose.** Take MNEME from a proven verifiable-memory substrate to a field-defining one by adding five inventions, each at highest grade, each proven by the toughest available evidence. This is an execution spec for a multi-agent team of senior experts. Source of truth for the existing system is `MNEME_BLUEPRINT.md`; the inventions are derived from the June-2026 frontier research.

**Hand to your agents as-is.** Every task below names its owner role, exact deliverable, dependency, performance target, and a completion proof gate that must be reproduced from a clean checkout. No task is "done" on a green checkmark — only on reproduced evidence and zero anti-fake findings.

---

## 0. Prime directives (carried from the existing build — non-negotiable)

- **Fail-closed.** Any new verifier path rejects on failure; never degrades, never returns best-effort.
- **TCB discipline.** Anything that can return `Ok` on trusted data lives in or behind `mneme-verify`: `#![forbid(unsafe_code)]`, no `unwrap`/`expect`/`panic`/`anyhow`/`as`-casts on reachable paths, typed closed-enum errors, pinned reviewed line budget. Every invention that adds a verifier raises the budget only with a written justification.
- **Determinism.** Every new artifact that enters a root or a receipt is byte-deterministic across machines (no float associativity, no map-iteration order, no wall-clock/PID in identity).
- **Honesty boundary (must appear in README, API docs, and the verifier's own error text).** Authenticated ≠ true. Retrieval proofs prove *faithfulness of the declared procedure over a committed snapshot*, not truth and not exact-nearest-neighbor. Parametric unlearning is *statistical attestation*, weaker than a cryptographic guarantee. Influence-based attribution is *estimated*, not proven-causal. No task may ship a claim its proof does not support.

---

## 1. The team (senior multi-agent roster)

Assign one accountable owner per role; they may sub-delegate. One **Integration Owner** re-runs the full gate on the merged tree before any milestone is declared.

- **Crypto Lead** — ZK circuits, commitments, sparse-Merkle proofs, signatures.
- **Verifier/TCB Lead** — owns `mneme-verify`; every new proof must verify here, fail-closed, within budget.
- **Memory-Systems Lead** — provenance DAG, dependency closure, CRDT merge, store kernel.
- **Inference-Systems Lead** — deterministic kernels, TEE attestation, replay.
- **ML-Attribution Lead** — influence functions, unlearning attestation.
- **Protocols Lead** — A2A/MCP integration, capability tokens, merge-boundary verification.
- **Adversary/Red-Team Lead** — constructs forgeries, runs the anti-fake audits, owns the proof gates. Reports independently of the build leads.
- **Integration Owner** — final gate, golden-digest custody, cross-machine determinism.
- **Performance Lead** — benchmarks every target on M4 Max + a second machine; owns the load/soak rigs.

**Working rule:** invention epics run in dependency order (Epic A unblocks B and D); within an epic, tasks parallelize across owners against frozen interface contracts. Every finished slice reports per the handoff protocol (§6).

---

## 2. Global proof discipline (applies to EVERY task)

A task is complete only when the Adversary Lead can reproduce ALL of the following from a clean checkout, cold cache:

1. **Forgery rejection.** For any verifier the task adds or touches: construct a targeted forgery and prove it is rejected with the *exact* correct typed variant — never `Ok`, never a panic, never a generic error.
2. **No fakes.** No `todo!`/`unimplemented!`/stub returning hardcoded `Ok`; no test that asserts only "an error occurred," `assert!(true)`, no-assertion, `#[ignore]`, or passes only because a feature is stubbed. Every new exit criterion has a real test that exercises real crypto/IO, not a mock.
3. **Tamper coverage.** New persisted structures are added to the tamper suite (byte-mutation → correct typed rejection). Suite count goes up, never down.
4. **Determinism across two machines.** Any new root/receipt/proof artifact is byte-identical on M4 Max and a second, architecturally-different machine.
5. **Performance target met** (stated per task), measured with fsync on, under load, p50 and p99 reported.
6. **Honesty audit.** The task's public claims do not exceed its proofs; limits are stated in docs and error text.

If any item is unproven, the task is NOT done — list it in "What's left," do not soften it.

---

## 3. Epic A — Proof-Carrying Recall (PCR) — FLAGSHIP

*Goal: upgrade the recall receipt from authenticated-retrieval to verifiable-retrieval — prove the returned entries are the faithful top-k under the declared ANN semantics over the signed snapshot, AND that any forgotten entry is provably absent. Closes MNEME's biggest stated limitation. Build first.*

**A1 — Procedure circuitization.** *Owner: Crypto Lead.* Standardize MNEME's exact retrieval procedure `P` into a fixed-shape arithmetic circuit (V3DB-style for IVF/HNSW), with the signed root as the snapshot commitment. *Perf target:* audit-on-demand proving < 10 s per challenged query at 100K objects on commodity hardware; verification < 5 ms. *Proof gate:* a proof for an honest query verifies; a proof for a query whose returned set was altered by one element FAILS to verify; the verifier never accepts a proof bound to a different root.

**A2 — Proof-of-absence for tombstones.** *Owner: Crypto Lead + Verifier Lead.* Layer a sparse-Merkle non-membership proof so a forgotten/tombstoned key is provably absent from the candidate set. *Proof gate:* forget a datum → root stays valid → the verifier produces a proof the datum is absent from every future candidate set; an attempt to serve the tombstoned item is rejected with `Forgotten`.

**A3 — Verifier integration (fail-closed, in TCB).** *Owner: Verifier/TCB Lead.* `verify_recall` accepts the PCR proof, binds it to the current root, and fails closed on any mismatch. Stays under the (raised, justified) line budget. *Proof gate:* the §2 forgery battery, plus a fuzz target for the proof parser (never panic, never accept malformed).

**A4 — Audit-on-demand API + scaling.** *Owner: Memory-Systems Lead.* Expose `recall` → optional `prove` → `verify`; default path stays fast (no per-query proving). *Perf target:* `recall_verified` p50 unchanged from baseline (~116 µs @ 1M); proving is opt-in and amortized. *Proof gate:* benchmark at 100K and 1M objects, fsync on, p50/p99 reported on two machines.

**A5 — Killer demo (the "previously impossible").** *Owner: Adversary Lead.* End-to-end: an auditor verifies in ms — without seeing the corpus — that a recall is the faithful top-k over the exact signed snapshot; then a datum is forgotten and the *same* verifier proves it is now absent. *Done means:* no existing system (V3DB, PunkGo, SBU, TierMem, Mem0, Zep, Letta) can reproduce both halves; the demo runs offline, reproducibly, on M4 Max.

**Epic A done means:** PCR proof + proof-of-absence verify in the TCB, fail-closed; perf targets met on two machines; tamper suite extended; killer demo reproduced by the Adversary Lead; docs state "faithful retrieval, not truth, not exact-NN."

---

## 4. Epic B — Closed-Loop Cryptographic Forgetting

*Goal: one erasure receipt provably removes a datum from the store AND all derived artifacts AND (as attested) the model's parametric residue — defeating information backflow. The strongest regulatory wedge. Depends on A2.*

**B1 — Dependency-closure forgetting.** *Owner: Memory-Systems Lead.* Extend the provenance DAG to dependency-closure semantics (reference-counted): shredding a leaf forces re-derivation or tombstoning of every dependent summary/embedding/KG-node. *Proof gate:* forget a source datum → prove (via PCR proof-of-absence) that no dependent artifact still encodes it; an attempt to reach the datum through any derived path is rejected.

**B2 — Erasure receipt.** *Owner: Crypto Lead.* A single signed receipt binds: crypto-shred of the object key, tombstone insertion, dependency-closure completion, and the new valid root. *Proof gate:* the receipt verifies in the TCB; a forged receipt claiming completion without closure is rejected; the root stays valid after erasure.

**B3 — Model-side unlearning attestation (v1, honestly statistical).** *Owner: ML-Attribution Lead.* Bind the erasure receipt to an unlearning job whose completion is attested via an influence-function check (LoRIF-style): forget-set influence dropped below threshold τ. *Honesty gate:* the receipt and docs state explicitly that this is *statistical attestation that an unlearning procedure ran and influence fell below τ*, NOT a cryptographic deletion guarantee. *Proof gate:* a job that did not actually reduce influence below τ cannot produce a valid attestation.

**B4 — Regulatory mapping.** *Owner: Protocols Lead.* Map the erasure receipt + proof-of-absence to GDPR Art. 17 and EU AI Act Art. 12 language, robust to either the Aug-2026 or Aug-2027 enforcement schedule. *Done means:* a written mapping a compliance officer can audit, with the statistical-vs-cryptographic boundary clearly drawn.

**Epic B done means:** erasure receipt + dependency closure verify in the same kernel as PCR; backflow defeated for memory + derived artifacts; model-side is honestly labeled statistical; regulatory mapping written; tamper + forgery gates green.

---

## 5. Epic C — Deterministic Verifiable Replay

*Goal: cheap proof-of-correct-execution without zkML — anchor each agent step to (input, signed memory root, model hash, sampler seed) and prove bit-identical re-execution under attested deterministic kernels. Depends on the existing signed-root infra.*

**C1 — Step anchoring.** *Owner: Memory-Systems Lead.* Record per step a signed tuple (input digest, memory root, model hash, seed, kernel+hardware attestation). *Proof gate:* tampering with any field is detectable; the tuple is deterministic.

**C2 — Deterministic execution stack.** *Owner: Inference-Systems Lead.* Pin an attested batch-invariant kernel stack (Thinking-Machines/SGLang-style) + composite TEE attestation (NVIDIA + Intel TDX). *Perf target:* < ~2% overhead vs non-deterministic baseline. *Proof gate:* bit-identical output across two independent attested nodes for the same anchored step.

**C3 — Replay verifier.** *Owner: Verifier/TCB Lead.* Re-run an anchored step; any token divergence is cryptographic evidence of tampering or environment drift, surfaced as a typed error. *Proof gate:* an injected one-token change in a "replayed" output is caught; a stale model hash is rejected.

**C4 — Incident-reconstruction demo.** *Owner: Adversary Lead.* Reconstruct an agent decision exactly from its anchored state for an EU AI Act Art. 12 / 72-hour incident scenario. *Done means:* reproducible bit-identical reconstruction on two machines; honest note that determinism is only as strong as the pinned attested stack.

**Epic C done means:** bit-identical replay across two attested nodes; divergence detected and typed; overhead target met; demo reproduced; the hardware/kernel-pinning limit documented.

---

## 6. Epic D — Attribution-Grade Provenance Receipts

*Goal: extend the provenance receipt past the memory write to training examples via influence functions — "action → belief → memory write → source/training datum," cryptographically chained. Partly genuine invention (the signed chain), partly assembly (the influence computation). Depends on Epic A.*

**D1 — Chain-to-source structure.** *Owner: Memory-Systems Lead.* Extend the provenance receipt schema to carry signed, tamper-evident edges from a belief back through its memory write to influence-estimated source/training data. *Proof gate:* tampering any edge breaks the chain; the chain verifies in the TCB.

**D2 — Influence annotation.** *Owner: ML-Attribution Lead.* Attach LoRIF-style influence estimates to source edges. *Honesty gate:* every such edge is labeled `influence-estimated`, never `proven-cause`; docs state influence functions are approximate and contested as ground-truth.

**D3 — Query surface + demo.** *Owner: Protocols Lead.* `why(action)` returns the verifiable chain with honest confidence labels. *Done means:* a "why did the agent believe this" query returns a cryptographically-verifiable chain to the memory boundary and influence-labeled edges beyond it.

**Epic D done means:** signed chain-to-source verifies fail-closed; influence labeled as estimated; query surface demoed; no claim of proven causality.

---

## 7. Epic E — A2A-Federated Verifiable Memory

*Goal: trustless cross-org shared memory — deterministic CRDT merge + attenuable capabilities + A2A Signed Agent Cards, with content-verification and quarantine at the inter-org merge boundary. Depends on existing CRDT + capability infra.*

**E1 — Signed-Agent-Card binding.** *Owner: Protocols Lead.* Bind A2A Signed Agent Card identity to MNEME capability tokens at the merge boundary. *Proof gate:* an object from an unverified or out-of-scope agent is rejected before merge; identity ≠ authorization is enforced.

**E2 — Merge-boundary verification + quarantine.** *Owner: Memory-Systems Lead + Verifier Lead.* Every received cross-org object is content-verified, provenance-stamped, and lands in quarantine until promoted by a capability the sending channel lacks. *Proof gate:* a poisoned cross-org object is stored, attributed, and structurally non-actionable; a forged provenance stamp is rejected.

**E3 — Deterministic federated convergence.** *Owner: Performance Lead.* Two orgs' agents merge divergent memory to the same root regardless of order. *Honesty gate:* deterministic merge handles *structural* convergence, not *truth reconciliation* — state this. *Proof gate:* N-org random-order convergence to an identical root, proven across two machines.

**Epic E done means:** cross-org objects verified + quarantined at merge; deterministic convergence proven; identity/authorization/truth boundaries documented; forgery + tamper gates green.

---

## 8. Sequencing (dependency-ordered; parallelize within stages)

- **Stage 0 (0–4 wks):** Epic A (PCR) prototype + circuitization threshold check (proceed only if proving < ~10 s @ 100K, else pivot to challenge-sampling).
- **Stage 1 (1–3 mo):** Epic A to completion + Epic B v0 (memory + derived-artifact closure; model side as attestation hook).
- **Stage 2 (3–6 mo):** Epic C.
- **Stage 3 (6–12 mo):** Epic D **or** E based on customer pull (forensics/compliance → D; multi-agent/platform → E). Build the second only if the first is fully proven.

Run Epics within a stage in parallel across owners against frozen interface contracts. The Integration Owner re-runs the full gate on the merged tree at each stage boundary.

---

## 9. The final readiness gate (run after each stage, hard before any "done")

The Adversary Lead + Integration Owner reproduce, from a clean checkout, on two machines:
- Full forgery battery across every verifier (PCR, proof-of-absence, erasure, replay, chain, merge) — all rejected with correct typed variants.
- Anti-fake audit: zero stubs, zero hollow tests; every new exit criterion has a real test.
- Tamper suite extended and fully green; fuzz targets clean to a meaningful corpus.
- Determinism: byte-identical roots/receipts/proofs across both machines.
- Performance: every per-epic target met, fsync on, under load, p50/p99 reported.
- Soak/chaos: faults injected (disk-full mid-write, corrupted blobs, clock skew, malicious peer, random kill) — always recoverable-or-detectably-incomplete, verifier always fails closed.
- Honesty audit: no claim exceeds its proof; all limits in docs + error text.

Deliverable: a single `READINESS_2.0.md` with every command + log path, golden digests from both machines, the full forgery/tamper/fuzz/determinism/perf/soak results, verifier line count vs budget, and a brutal exhaustive **What's left** section. Top-line status is READY only if every item passed with reproducible evidence and zero anti-fake findings; otherwise NOT READY with the file:line list of what's missing. "Mostly done" is banned.

---

## 10. Kill criteria (abandon or re-scope, honestly)

- If ZK proving cost cannot be brought under the Stage-0 threshold even with challenge-sampling, PCR's "every recall provable" claim is downgraded to "audited recall provable" — say so.
- If a hyperscaler/standard ships verifiable retrieval receipts in MCP/A2A core, deprioritize C and accelerate B (forgetting is hardest to commoditize).
- If deterministic inference cannot be pinned stably across the target hardware, Epic C ships only as a single-attested-stack feature, not a portable guarantee.
- If model-side unlearning attestation cannot be made meaningful (influence check unreliable at scale), B3 ships as memory+derived-artifact closure only, with the model-side limit stated plainly.

---

## 11. The real finish line

All gates green is necessary, not sufficient. The genuine proof that MNEME 2.0 is field-defining is **one live task, with a real agent, where PCR proves a real recall and a real forgotten datum is provably absent in the wild** — and, for Epic B, where a real erasure propagates and is independently verified. The audits prove it can't be fooled in the lab; the live run proves it holds. Only then is "top tier" earned rather than asserted.
